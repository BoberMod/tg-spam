// Package events provide event handlers for telegram bot and all the high-level event handlers.
// It parses messages, sends them to the spam detector and handles the results. It can also ban users
// and send messages to the admin.
//
// In addition to that, it provides support for admin chat handling allowing to unban users via the web service and
// update the list of spam samples.
package events

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	tbapi "github.com/OvyFlash/telegram-bot-api"
	"github.com/hashicorp/go-multierror"

	"github.com/umputun/tg-spam/app/bot"
	"github.com/umputun/tg-spam/lib/spamcheck"
)

//go:generate moq --out mocks/spam_logger.go --pkg mocks --with-resets --skip-ensure . SpamLogger

// SpamLogger is an interface for spam logger
type SpamLogger interface {
	Save(msg *bot.Message, response *bot.Response)
}

// SpamLoggerFunc is a function that implements SpamLogger interface
type SpamLoggerFunc func(msg *bot.Message, response *bot.Response)

// Save is a function that implements SpamLogger interface
func (f SpamLoggerFunc) Save(msg *bot.Message, response *bot.Response) {
	f(msg, response)
}

// TelegramListener listens to tg update, forward to bots and send back responses
// Not thread safe
type TelegramListener struct {
	TbAPI                   TbAPI         // telegram bot API
	SpamLogger              SpamLogger    // logger to save spam to files and db
	Bot                     Bot           // bot to handle messages
	BotUsername             string        // telegram bot username (without "@" prefix)
	Groups                  []string      // protected chats, each can be int64 or a public username
	Group                   string        // legacy single-chat input used by older embedders and tests
	AdminGroup              string        // can be int64 or public group username (without "@" prefix)
	IdleDuration            time.Duration // idle timeout to send "idle" message to bots
	SuperUsers              SuperUsers    // list of superusers, can ban and report spam, can't be banned
	TestingIDs              []int64       // list of chat IDs to test the bot
	StartupMsg              string        // message to send on startup to the primary chat
	WarnMsg                 string        // message to send on warning
	NoSpamReply             bool          // do not reply on spam messages in the primary chat
	SuppressJoinMessage     bool          // delete join message when kick out user
	DeleteJoinMessages      bool          // delete join messages immediately
	DeleteLeaveMessages     bool          // delete leave messages immediately
	TrainingMode            bool          // do not ban users, just report and train spam detector
	SoftBanMode             bool          // do not ban users, but restrict their actions
	Locator                 Locator       // message locator to get info about messages
	ReportConfig            ReportConfig  // user spam reporting configuration
	DisableAdminSpamForward bool          // disable forwarding spam reports to admin chat support
	Dry                     bool          // dry run, do not ban or send messages
	AggressiveCleanup       bool          // delete all messages from user when banned via /spam command
	AggressiveCleanupLimit  int           // max messages to delete in aggressive cleanup mode
	WarnThreshold           int           // auto-ban after N warns within window (0=disabled)
	WarnWindow              time.Duration // sliding window for counting warns
	Warnings                Warnings      // storage for admin /warn records
	AdmitDocuments          bool          // admit text-less documents for detector checks and locator-backed counters

	adminHandler    *admin
	reportsHandler  *userReports
	adminHandlers   map[int64]*admin
	reportsHandlers map[int64]*userReports
	dmUsers         dmUsers // recent DM senders, stored in memory for admin UI
	chatID          int64
	linkedChannelID int64
	adminChatID     int64
	globalSupers    SuperUsers
	chats           map[int64]managedChat
	chatOrder       []int64

	msgs struct {
		once sync.Once
		ch   chan bot.Response
	}

	// serializes extra-message deletion goroutines so concurrent spam bursts still respect
	// the per-request rate limiting inside deleteExtraMessages
	extraDeletesMu sync.Mutex
}

type managedChat struct {
	ID              int64
	Name            string
	LinkedChannelID int64
	SuperUsers      SuperUsers
}

// GetDMUsers returns the list of recent DM senders
func (l *TelegramListener) GetDMUsers() []DMUser {
	return l.dmUsers.List()
}

// Do process all events, blocked call
func (l *TelegramListener) Do(ctx context.Context) error {
	groups := l.Groups
	explicitGroups := len(groups) > 0
	if len(groups) == 0 && strings.TrimSpace(l.Group) != "" {
		groups = []string{l.Group}
	}
	log.Printf("[INFO] start telegram listener for %q", groups)

	if l.TrainingMode {
		log.Printf("[WARN] training mode, no bans")
	}

	if l.SoftBanMode {
		log.Printf("[INFO] soft ban mode, no bans but restrictions")
	}

	if len(groups) == 0 && l.chatID == 0 {
		return fmt.Errorf("at least one telegram group is required")
	}
	l.chats = make(map[int64]managedChat, max(len(groups), 1))
	l.chatOrder = l.chatOrder[:0]
	configuredSupers := append(SuperUsers(nil), l.SuperUsers...)
	l.globalSupers = configuredSupers
	if len(groups) == 0 {
		l.chats[l.chatID] = managedChat{
			ID: l.chatID, Name: strconv.FormatInt(l.chatID, 10), LinkedChannelID: l.linkedChannelID,
			SuperUsers: append(SuperUsers(nil), l.SuperUsers...),
		}
		l.chatOrder = append(l.chatOrder, l.chatID)
	}
	for _, configuredGroup := range groups {
		group := strings.TrimSpace(configuredGroup)
		if group == "" {
			continue
		}
		chat, err := l.resolveManagedChat(group, explicitGroups, configuredSupers)
		if err != nil {
			return err
		}
		if _, duplicate := l.chats[chat.ID]; duplicate {
			continue
		}
		l.chats[chat.ID] = chat
		l.chatOrder = append(l.chatOrder, chat.ID)
		if l.chatID == 0 {
			l.chatID = chat.ID
			l.linkedChannelID = chat.LinkedChannelID
		}
		log.Printf("[INFO] protected chat %s (%d), linked channel: %d", chat.Name, chat.ID, chat.LinkedChannelID)
	}
	if len(l.chats) == 0 {
		return fmt.Errorf("at least one telegram group is required")
	}
	l.SuperUsers = append(SuperUsers(nil), l.chats[l.chatID].SuperUsers...)

	if l.AdminGroup != "" {
		// get chat ID for the admin group
		var getChatErr error
		if l.adminChatID, getChatErr = l.getChatID(l.AdminGroup); getChatErr != nil {
			return fmt.Errorf("failed to get chat ID for admin group %q: %w", l.AdminGroup, getChatErr)
		}
		log.Printf("[INFO] admin chat ID: %d", l.adminChatID)
		if _, protected := l.chats[l.adminChatID]; protected && explicitGroups {
			return fmt.Errorf("admin chat %d cannot also be a protected chat", l.adminChatID)
		}
	}

	l.msgs.once.Do(func() {
		l.msgs.ch = make(chan bot.Response, 100)
		if l.IdleDuration == 0 {
			l.IdleDuration = 30 * time.Second
		}
	})

	// send startup message to every protected chat
	if l.StartupMsg != "" && !l.TrainingMode && !l.Dry {
		for _, chatID := range l.chatOrder {
			if err := l.sendBotResponse(bot.Response{Send: true, Text: l.StartupMsg}, chatID, NotificationSilent); err != nil {
				log.Printf("[WARN] failed to send startup message to %d, %v", chatID, err)
			}
		}
	}

	l.adminHandlers = make(map[int64]*admin, len(l.chats))
	l.reportsHandlers = make(map[int64]*userReports, len(l.chats))
	for _, chatID := range l.chatOrder {
		chat := l.chats[chatID]
		l.adminHandlers[chatID] = &admin{
			tbAPI: l.TbAPI, bot: l.Bot, locator: l.Locator, superUsers: chat.SuperUsers,
			primChatID: chatID, adminChatID: l.adminChatID, chatName: chat.Name,
			trainingMode: l.TrainingMode, softBan: l.SoftBanMode, dry: l.Dry, warnMsg: l.WarnMsg,
			aggressiveCleanup: l.AggressiveCleanup, aggressiveCleanupLimit: l.AggressiveCleanupLimit,
			warnings: l.Warnings, warnThreshold: l.WarnThreshold, warnWindow: l.WarnWindow,
			ambiguousForward: len(l.chats) > 1,
		}
		l.reportsHandlers[chatID] = &userReports{
			ReportConfig: l.ReportConfig,
			tbAPI:        l.TbAPI, bot: l.Bot, locator: l.Locator, superUsers: chat.SuperUsers,
			primChatID: chatID, adminChatID: l.adminChatID, chatName: chat.Name,
			trainingMode: l.TrainingMode, softBanMode: l.SoftBanMode, dry: l.Dry,
		}
	}
	l.adminHandler = l.adminHandlers[l.chatID]
	l.reportsHandler = l.reportsHandlers[l.chatID]

	adminForwardStatus := "enabled"
	if l.DisableAdminSpamForward {
		adminForwardStatus = "disabled"
	}
	log.Printf("[DEBUG] admin handler created, spam forwarding %s, %+v", adminForwardStatus, l.adminHandler)

	if l.AggressiveCleanup {
		log.Printf("[INFO] aggressive cleanup enabled, messages from user will be deleted on ban, limit %d",
			l.AggressiveCleanupLimit)
	}

	u := tbapi.NewUpdate(0)
	u.Timeout = 60
	u.AllowedUpdates = []string{"message", "edited_message", "callback_query", "message_reaction"}

	updates := l.TbAPI.GetUpdatesChan(u)
	log.Printf("[DEBUG] start listening for updates")
	// single reusable idle timer, re-armed each iteration: time.After in a loop leaks one
	// live timer per update until it fires
	idleTimer := time.NewTimer(l.IdleDuration)
	defer idleTimer.Stop()
	for {
		idleTimer.Reset(l.IdleDuration)
		select {
		case <-ctx.Done():
			return fmt.Errorf("listener context canceled: %w", ctx.Err())

		case update, ok := <-updates:
			if !ok {
				return fmt.Errorf("telegram update chan closed")
			}

			// handle admin chat messages. can be just messages (MsgHandler will ignore those)
			// or forwards of undetected spam by admins to admin's chat (in this case MsgHandler will process them and ban/train)
			if update.Message != nil && update.Message.From != nil &&
				l.isAdminChat(update.Message.Chat.ID, update.Message.From.UserName, update.Message.From.ID) {
				if l.DisableAdminSpamForward {
					continue
				}
				handler := l.adminHandlerForMessage(update.Message)
				if err := handler.MsgHandler(update); err != nil {
					log.Printf("[WARN] failed to process admin chat message: %v", err)
					errResp := l.sendBotResponse(bot.Response{Send: true, Text: "error: " + err.Error()}, l.adminChatID, NotificationDefault)
					if errResp != nil {
						log.Printf("[WARN] failed to respond on error, %v", errResp)
					}
				}
				continue
			}

			// handle admin chat inline buttons - route based on callback prefix
			if update.CallbackQuery != nil {
				callbackData := update.CallbackQuery.Data
				target, targetErr := parseCallbackTarget(callbackData, l.chatID)
				if targetErr != nil {
					log.Printf("[WARN] failed to parse callback target: %v", targetErr)
					continue
				}
				adminHandler, adminFound := l.adminHandlers[target.ChatID]
				reportsHandler, reportsFound := l.reportsHandlers[target.ChatID]

				// delegate report callbacks (prefixes R+, R-, R?, R!, RX) to reportsHandler
				if len(callbackData) >= 3 && callbackData[:1] == "R" {
					if !reportsFound {
						continue
					}
					if err := reportsHandler.HandleReportCallback(ctx, update.CallbackQuery); err != nil {
						log.Printf("[WARN] failed to process report callback: %v", err)
						errResp := l.sendBotResponse(bot.Response{Send: true, Text: "error: " + err.Error()}, l.adminChatID, NotificationDefault)
						if errResp != nil {
							log.Printf("[WARN] failed to respond on error, %v", errResp)
						}
					}
				} else {
					if !adminFound {
						continue
					}
					// all other callbacks (?, +, !, or no prefix) go to admin handler
					if err := adminHandler.InlineCallbackHandler(update.CallbackQuery); err != nil {
						log.Printf("[WARN] failed to process callback: %v", err)
						errResp := l.sendBotResponse(bot.Response{Send: true, Text: "error: " + err.Error()}, l.adminChatID, NotificationDefault)
						if errResp != nil {
							log.Printf("[WARN] failed to respond on error, %v", errResp)
						}
					}
				}
				continue
			}

			// handle edited messages
			if update.EditedMessage != nil {
				log.Printf("[INFO] processing edited message, id: %d", update.EditedMessage.MessageID)
				// we need to process an edited message as a new message, so we create a new update object
				// and copy the edited message to the message field.
				editedUpdate := tbapi.Update{
					Message: update.EditedMessage,
				}
				if err := l.procEvents(editedUpdate); err != nil {
					log.Printf("[WARN] failed to process edited message update: %v", err)
				}
				continue
			}

			if update.MessageReaction != nil {
				if err := l.procReaction(ctx, update.MessageReaction); err != nil {
					log.Printf("[WARN] failed to process reaction: %v", err)
				}
				continue
			}

			if update.Message == nil {
				continue
			}
			if update.Message.Chat.Type != "private" && !l.isChatAllowed(update.Message.Chat.ID) {
				continue
			}

			if update.Message.NewChatMembers != nil {
				// handle join messages with mutually exclusive logic to prevent double-deletion:
				// - if DeleteJoinMessages=true: delete immediately, don't store in locator
				// - if DeleteJoinMessages=false: store in locator for potential later deletion via SuppressJoinMessage
				// this prevents "message not found" errors when both flags are enabled
				if l.DeleteJoinMessages {
					l.deleteSystemMessage(update.Message.MessageID, update.Message.Chat.ID, "join")
				} else {
					err := l.procNewChatMemberMessage(update)
					if err != nil {
						log.Printf("[WARN] failed to process new chat member: %v", err)
					}
				}
				continue
			}

			// handle left member messages, i.e. "blah blah removed from the chat"
			if update.Message.LeftChatMember != nil {
				if l.SuppressJoinMessage {
					// delete the stored join message when user leaves
					err := l.procLeftChatMemberMessage(update)
					if err != nil {
						log.Printf("[WARN] failed to process left chat member: %v", err)
					}
				}
				// immediately delete leave message if requested
				if l.DeleteLeaveMessages {
					l.deleteSystemMessage(update.Message.MessageID, update.Message.Chat.ID, "leave")
				}
				continue
			}

			// messages without a sender can't be matched against superusers or report commands,
			// send them straight to the regular processing which handles nil From safely
			if update.Message.From == nil {
				if err := l.procEvents(update); err != nil {
					log.Printf("[WARN] failed to process update: %v", err)
				}
				continue
			}

			// handle spam reports from superusers and linked channel
			fromSuper := l.isSuperForChat(update.Message.Chat.ID, update.Message.From.UserName, update.Message.From.ID) ||
				l.isLinkedChannel(update.Message)
			if update.Message.ReplyToMessage != nil && fromSuper {
				if l.procSuperReply(update) {
					// superuser command processed, skip the rest
					continue
				}
			}

			// delete orphaned report commands (sent without replying to a message)
			if !fromSuper && l.isReportCommand(update.Message.Text) && update.Message.ReplyToMessage == nil {
				log.Printf("[DEBUG] deleting orphaned report command %q from %s (%d)",
					update.Message.Text, update.Message.From.UserName, update.Message.From.ID)
				_, err := l.TbAPI.Request(tbapi.DeleteMessageConfig{BaseChatMessage: tbapi.BaseChatMessage{
					MessageID:  update.Message.MessageID,
					ChatConfig: tbapi.ChatConfig{ChatID: update.Message.Chat.ID},
				}})
				if err != nil {
					log.Printf("[WARN] failed to delete orphaned report message %d: %v", update.Message.MessageID, err)
				}
				continue
			}

			// handle spam reports from regular users. senders posting on behalf of a chat
			// (anonymous admin, "post as channel") are excluded: their From is a telegram pseudo-user
			// which can never be an approved reporter, so the report would be dropped after the
			// command message is already deleted
			if update.Message.ReplyToMessage != nil && !fromSuper && update.Message.SenderChat == nil {
				if l.procUserReply(ctx, update) {
					// user command processed, skip the rest
					continue
				}
			}

			// process regular messages, the main part of the bot
			if err := l.procEvents(update); err != nil {
				log.Printf("[WARN] failed to process update: %v", err)
				continue
			}

		case <-idleTimer.C: // hit bots on idle timeout
			resp := l.Bot.OnMessage(bot.Message{Text: "idle"}, false)
			if err := l.sendBotResponse(resp, l.chatID, NotificationSilent); err != nil {
				log.Printf("[WARN] failed to respond on idle, %v", err)
			}
		}
	}
}

func (l *TelegramListener) procEvents(update tbapi.Update) error {
	msgJSON, errJSON := json.Marshal(update.Message)
	if errJSON != nil {
		return fmt.Errorf("failed to marshal update.Message to json: %w", errJSON)
	}

	// intercept private (DM) messages before any other processing.
	// stores the sender info for the admin UI and silently drops the message.
	if update.Message.Chat.Type == "private" {
		if update.Message.From == nil {
			return nil
		}
		from := update.Message.From
		displayName := strings.TrimSpace(from.FirstName + " " + from.LastName)
		l.dmUsers.Add(DMUser{
			UserID:      from.ID,
			UserName:    from.UserName,
			DisplayName: displayName,
			Timestamp:   time.Now(),
		})
		return nil
	}

	fromChat := update.Message.Chat.ID
	// ignore messages from other chats except the one we are monitor and ones from the test list
	if !l.isChatAllowed(fromChat) {
		return nil
	}

	log.Printf("[DEBUG] %s", string(msgJSON))
	msg := transform(update.Message)

	// a text-less document is admitted only when the documents check is on. once admitted it is stored by
	// the locator, inflating the per-user count --max-short-msg-count bans on, and it reaches the checks
	// that need no message text: stop-words (matched against username and user ID too), username-symbols,
	// lua plugins and CAS, which is on by default and bans permanently
	documentAdmitted := msg.WithDocument && l.AdmitDocuments

	// ignore messages with empty text, no media, no video, no video note, no forward, no external reply,
	// no admitted document
	if strings.TrimSpace(msg.Text) == "" && msg.Image == nil && !msg.WithVideoNote && !msg.WithVideo &&
		!msg.WithForward && !msg.WithExternalReply && !documentAdmitted {
		return nil
	}
	ctx := context.TODO()
	log.Printf("[DEBUG] incoming msg: %+v", strings.ReplaceAll(msg.Text, "\n", " "))
	log.Printf("[DEBUG] incoming msg details: %+v", msg)

	// use channel identity for locator when message is sent on behalf of a channel
	locatorUserID := msg.From.ID
	locatorUserName := msg.From.Username
	if msg.SenderChat.ID != 0 {
		locatorUserID = msg.SenderChat.ID
		locatorUserName = msg.SenderChat.UserName
	}
	if err := l.Locator.AddMessage(ctx, msg.Text, fromChat, locatorUserID, locatorUserName, msg.ID); err != nil {
		log.Printf("[WARN] failed to add message to locator: %v", err)
	}

	// skip spam check for anonymous admin posts from this group or from the linked channel.
	// when admins post "as the group", SenderChat.ID equals the group's chat ID;
	// when the linked channel posts, SenderChat.ID equals the linked channel ID.
	if msg.SenderChat.ID != 0 && (msg.SenderChat.ID == fromChat || l.isLinkedChannel(update.Message)) {
		log.Printf("[DEBUG] skipping spam check for anonymous admin post from group itself or linked channel")
		return nil
	}

	resp := l.Bot.OnMessage(*msg, false)

	if !resp.Send { // not spam
		return nil
	}

	// send response to the channel if allowed
	if resp.Send && !l.NoSpamReply && !l.TrainingMode {
		if err := l.sendBotResponse(resp, fromChat, NotificationSilent); err != nil {
			log.Printf("[WARN] failed to respond on update, %v", err)
		}
	}

	errs := new(multierror.Error)

	// ban user if requested by bot
	if resp.Send && resp.BanInterval > 0 {
		log.Printf("[DEBUG] ban initiated for %+v", resp)
		l.SpamLogger.Save(msg, &resp)
		spamUserID := msg.From.ID
		if msg.SenderChat.ID != 0 {
			spamUserID = msg.SenderChat.ID
		}
		if err := addSpamInChat(ctx, l.Locator, fromChat, spamUserID, resp.CheckResults); err != nil {
			log.Printf("[WARN] failed to add spam to locator: %v", err)
		}
		banUserStr := l.getBanUsername(resp, update)

		if l.isSuperForChat(fromChat, msg.From.Username, msg.From.ID) {
			if l.TrainingMode {
				l.adminHandlerForChat(fromChat).ReportBan(banUserStr, msg)
			}
			log.Printf("[DEBUG] superuser %s requested ban, ignored", banUserStr)
			return nil
		}

		banReq := banRequest{duration: resp.BanInterval, userID: resp.User.ID, channelID: resp.ChannelID, userName: banUserStr,
			chatID: fromChat, dry: l.Dry, training: l.TrainingMode, tbAPI: l.TbAPI, restrict: l.SoftBanMode}
		if err := banUserOrChannel(banReq); err != nil {
			errs = multierror.Append(errs, fmt.Errorf("failed to ban %s: %w", banUserStr, err))
		} else if l.adminChatID != 0 && msg.From.ID != 0 {
			l.adminHandlerForChat(fromChat).ReportBan(banUserStr, msg)
		}
	}

	// delete extra messages if spam detected (e.g., duplicates); runs in a goroutine because the
	// rate-limit sleeps between deletions would otherwise stall the single-threaded update loop,
	// same pattern as admin's aggressiveCleanup
	isSuper := l.isSuperForChat(fromChat, msg.From.Username, msg.From.ID)
	go l.deleteExtraMessages(resp.CheckResults, msg.From.ID, msg.From.Username, fromChat, isSuper)

	// delete message if requested by bot
	canDelete := resp.DeleteReplyTo && resp.ReplyTo != 0 && !l.Dry &&
		!l.isSuperForChat(fromChat, msg.From.Username, msg.From.ID) && !l.TrainingMode
	if canDelete {
		if _, err := l.TbAPI.Request(tbapi.DeleteMessageConfig{BaseChatMessage: tbapi.BaseChatMessage{
			MessageID:  resp.ReplyTo,
			ChatConfig: tbapi.ChatConfig{ChatID: fromChat},
		}}); err != nil {
			errs = multierror.Append(errs, fmt.Errorf("failed to delete message %d: %w", resp.ReplyTo, err))
		}
	}

	if err := errs.ErrorOrNil(); err != nil {
		return fmt.Errorf("processing events failed: %w", err)
	}
	return nil
}

// procSuperReply processes superuser commands (reply) /spam, /ban, /warn
func (l *TelegramListener) procSuperReply(update tbapi.Update) (handled bool) {
	handler := l.adminHandlerForChat(update.Message.Chat.ID)
	switch {
	case strings.EqualFold(update.Message.Text, "/spam") || strings.EqualFold(update.Message.Text, "spam"):
		log.Printf("[DEBUG] superuser %s reported spam", update.Message.From.UserName)
		if err := handler.DirectSpamReport(update); err != nil {
			log.Printf("[WARN] failed to process direct spam report: %v", err)
		}
		return true
	case strings.EqualFold(update.Message.Text, "/ban") || strings.EqualFold(update.Message.Text, "ban"):
		log.Printf("[DEBUG] superuser %s requested ban", update.Message.From.UserName)
		if err := handler.DirectBanReport(update); err != nil {
			log.Printf("[WARN] failed to process direct ban request: %v", err)
		}
		return true
	case strings.EqualFold(update.Message.Text, "/warn") || strings.EqualFold(update.Message.Text, "warn"):
		log.Printf("[DEBUG] superuser %s requested warning", update.Message.From.UserName)
		if err := handler.DirectWarnReport(update); err != nil {
			log.Printf("[WARN] failed to process direct warning request: %v", err)
		}
		return true
	}
	return false
}

// isReportCommand checks if message text is a report command variant: report, /report,
// /report@botname, and the spam, /spam aliases. superuser spam, /spam never reaches here, it is
// handled earlier by procSuperReply
func (l *TelegramListener) isReportCommand(text string) bool {
	text = strings.TrimSpace(strings.ToLower(text))

	// exact match for regular report commands, spam and /spam are aliases for non-superusers
	if text == "report" || text == "/report" || text == "spam" || text == "/spam" {
		return true
	}

	// handle "/report@botname" syntax
	if strings.HasPrefix(text, "/report@") {
		// extract everything after "@"
		afterAt := text[8:] // skip "/report@"

		// reject empty username or whitespace-only
		fields := strings.Fields(afterAt)
		if len(fields) == 0 {
			return false
		}

		// extract just the username (up to space or end of string)
		// handles cases like "/report@bot" and "/report@bot some text"
		username := fields[0]

		// if bot username not configured, reject @ commands for security
		if l.BotUsername == "" {
			return false
		}

		// case-insensitive comparison (telegram usernames are case-insensitive)
		return strings.EqualFold(username, l.BotUsername)
	}

	return false
}

// procUserReply processes regular user report commands sent as a reply: report, /report,
// /report@botname and the spam, /spam aliases, all equivalent.
// feature check is intentionally inside this function to keep command detection logic centralized.
func (l *TelegramListener) procUserReply(ctx context.Context, update tbapi.Update) (handled bool) {
	switch {
	case l.isReportCommand(update.Message.Text):
		if !l.ReportConfig.Enabled {
			log.Printf("[DEBUG] user spam reporting disabled, ignoring report command from %s (%d)",
				update.Message.From.UserName, update.Message.From.ID)
			return true // command is suppressed when feature is disabled
		}
		log.Printf("[DEBUG] user %s (%d) reported spam", update.Message.From.UserName, update.Message.From.ID)
		if err := l.reportsHandlerForChat(update.Message.Chat.ID).DirectUserReport(ctx, update); err != nil {
			log.Printf("[WARN] failed to process user spam report: %v", err)
		}
		return true
	}
	return false
}

// procNewChatMemberMessage saves new chat member message to locator. It is used to delete the message if the user kicked out
func (l *TelegramListener) procNewChatMemberMessage(update tbapi.Update) error {
	fromChat := update.Message.Chat.ID
	// ignore messages from other chats except the one we are monitor and ones from the test list
	if !l.isChatAllowed(fromChat) {
		return nil
	}

	if len(update.Message.NewChatMembers) != 1 {
		log.Printf("[DEBUG] we are expecting only one new chat member, got %d", len(update.Message.NewChatMembers))
		return nil
	}

	errs := new(multierror.Error)

	member := update.Message.NewChatMembers[0]
	msg := fmt.Sprintf("new_%d_%d", fromChat, member.ID)
	if err := l.Locator.AddMessage(context.TODO(), msg, fromChat, member.ID, "", update.Message.MessageID); err != nil {
		errs = multierror.Append(errs, fmt.Errorf("failed to add new chat member message to locator: %w", err))
	}

	if err := errs.ErrorOrNil(); err != nil {
		return fmt.Errorf("failed to process new chat member: %w", err)
	}
	return nil
}

// procLeftChatMemberMessage deletes the message about new chat member if the user kicked out
func (l *TelegramListener) procLeftChatMemberMessage(update tbapi.Update) error {
	fromChat := update.Message.Chat.ID
	// ignore messages from other chats except the one we are monitor and ones from the test list
	if !l.isChatAllowed(fromChat) {
		return nil
	}

	if update.Message.From.ID == update.Message.LeftChatMember.ID {
		log.Printf("[DEBUG] left chat member is the same as the message sender, ignored")
		return nil
	}
	msg, found := l.Locator.Message(context.TODO(), fmt.Sprintf("new_%d_%d", fromChat, update.Message.LeftChatMember.ID))
	if !found {
		log.Printf("[DEBUG] no new chat member message found for %d in chat %d", update.Message.LeftChatMember.ID, fromChat)
		return nil
	}
	if _, err := l.TbAPI.Request(tbapi.DeleteMessageConfig{
		BaseChatMessage: tbapi.BaseChatMessage{ChatConfig: tbapi.ChatConfig{ChatID: fromChat}, MessageID: msg.MsgID},
	}); err != nil {
		return fmt.Errorf("failed to delete new chat member message %d: %w", msg.MsgID, err)
	}

	return nil
}

// deleteSystemMessage deletes a system message immediately
func (l *TelegramListener) deleteSystemMessage(msgID int, chatID int64, msgType string) {
	deleteMsg := tbapi.DeleteMessageConfig{
		BaseChatMessage: tbapi.BaseChatMessage{
			MessageID:  msgID,
			ChatConfig: tbapi.ChatConfig{ChatID: chatID},
		},
	}
	if _, err := l.TbAPI.Request(deleteMsg); err != nil {
		log.Printf("[WARN] failed to delete %s message %d: %v", msgType, msgID, err)
	} else {
		log.Printf("[DEBUG] %s message %d deleted", msgType, msgID)
	}
}

// isLinkedChannel checks if the message was sent on behalf of the linked channel
func (l *TelegramListener) isLinkedChannel(msg *tbapi.Message) bool {
	if msg == nil || msg.SenderChat == nil {
		return false
	}
	chat, found := l.chats[msg.Chat.ID]
	if found {
		return chat.LinkedChannelID != 0 && msg.SenderChat.ID == chat.LinkedChannelID
	}
	return l.linkedChannelID != 0 && msg.SenderChat.ID == l.linkedChannelID
}

func (l *TelegramListener) isChatAllowed(fromChat int64) bool {
	if _, found := l.chats[fromChat]; found {
		return true
	}
	if fromChat == l.chatID && l.chatID != 0 {
		return true
	}
	return slices.Contains(l.TestingIDs, fromChat)
}

func (l *TelegramListener) isSuperForChat(chatID int64, userName string, userID int64) bool {
	if chat, found := l.chats[chatID]; found {
		return chat.SuperUsers.IsSuper(userName, userID)
	}
	if l.globalSupers != nil {
		return l.globalSupers.IsSuper(userName, userID)
	}
	return l.SuperUsers.IsSuper(userName, userID)
}

func (l *TelegramListener) adminHandlerForChat(chatID int64) *admin {
	if handler, found := l.adminHandlers[chatID]; found {
		return handler
	}
	return l.adminHandler
}

func (l *TelegramListener) reportsHandlerForChat(chatID int64) *userReports {
	if handler, found := l.reportsHandlers[chatID]; found {
		return handler
	}
	return l.reportsHandler
}

func (l *TelegramListener) adminHandlerForMessage(msg *tbapi.Message) *admin {
	if msg == nil {
		return l.adminHandler
	}
	text := msg.Text
	if text == "" {
		text = transform(msg).Text
	}
	sourceChatID := forwardedSourceChatID(msg)
	if scoped, ok := l.Locator.(chatAwareMessageLocator); ok {
		matches := scoped.Messages(context.TODO(), text)
		if len(matches) == 1 {
			return l.adminHandlerForChat(matches[0].ChatID)
		}
		if _, configured := l.chats[sourceChatID]; configured {
			return l.adminHandlerForChat(sourceChatID)
		}
		return l.adminHandler
	}
	if info, found := l.Locator.Message(context.TODO(), text); found {
		return l.adminHandlerForChat(info.ChatID)
	}
	if _, configured := l.chats[sourceChatID]; configured {
		return l.adminHandlerForChat(sourceChatID)
	}
	return l.adminHandler
}

func (l *TelegramListener) isAdminChat(fromChat int64, from string, fromID int64) bool {
	if fromChat == l.adminChatID {
		log.Printf("[DEBUG] message in admin chat %d, from %s (%d)", fromChat, from, fromID)
		supers := l.globalSupers
		if supers == nil {
			supers = l.SuperUsers
		}
		if !supers.IsSuper(from, fromID) {
			log.Printf("[DEBUG] %s (%d) is not superuser in admin chat, ignored", from, fromID)
			return false
		}
		return true
	}
	return false
}

func (l *TelegramListener) getBanUsername(resp bot.Response, update tbapi.Update) string {
	if resp.ChannelID == 0 {
		return resp.User.String()
	}
	botChat := bot.SenderChat{
		ID: resp.ChannelID,
	}
	if update.Message.SenderChat != nil {
		botChat.UserName = update.Message.SenderChat.UserName
	}
	// if botChat.UserName not set, that means the ban comes from superuser and username should be taken from ReplyToMessage
	if botChat.UserName == "" && update.Message.ReplyToMessage != nil && update.Message.ReplyToMessage.SenderChat != nil {
		if update.Message.ReplyToMessage.ForwardOrigin != nil {
			if update.Message.ReplyToMessage.ForwardOrigin.IsUser() {
				botChat.UserName = update.Message.ReplyToMessage.ForwardOrigin.SenderUser.UserName
			}
			if update.Message.ReplyToMessage.ForwardOrigin.IsHiddenUser() {
				botChat.UserName = update.Message.ReplyToMessage.ForwardOrigin.SenderUserName
			}
		}
	}
	return fmt.Sprintf("%v", botChat)
}

// NotificationType defines how a message is delivered to users
type NotificationType int

const (
	// NotificationDefault sends message with standard notification
	NotificationDefault NotificationType = iota
	// NotificationSilent sends message without sound
	NotificationSilent
)

// sendBotResponse sends bot's answer to tg channel
// actionText is a text for the button to unban user, optional
func (l *TelegramListener) sendBotResponse(resp bot.Response, chatID int64, notifyType NotificationType) error {
	if !resp.Send {
		return nil
	}

	log.Printf("[DEBUG] bot response - %+v, reply-to:%d", strings.ReplaceAll(resp.Text, "\n", "\\n"), resp.ReplyTo)
	tbMsg := tbapi.NewMessage(chatID, resp.Text)
	tbMsg.ParseMode = tbapi.ModeMarkdown
	tbMsg.LinkPreviewOptions = tbapi.LinkPreviewOptions{IsDisabled: true}
	tbMsg.ReplyParameters = tbapi.ReplyParameters{MessageID: resp.ReplyTo}
	tbMsg.DisableNotification = notifyType == NotificationSilent

	if err := send(tbMsg, l.TbAPI); err != nil {
		return fmt.Errorf("can't send message to telegram %q: %w", resp.Text, err)
	}

	return nil
}

func (l *TelegramListener) getChatID(group string) (int64, error) {
	group = strings.TrimSpace(group)
	chatID, err := strconv.ParseInt(group, 10, 64)
	if err == nil {
		return chatID, nil
	}

	group = strings.TrimPrefix(strings.TrimSpace(group), "@")
	chat, err := l.TbAPI.GetChat(tbapi.ChatInfoConfig{ChatConfig: tbapi.ChatConfig{SuperGroupUsername: "@" + group}})
	if err != nil {
		return 0, fmt.Errorf("can't get chat for %s: %w", group, err)
	}

	return chat.ID, nil
}

func (l *TelegramListener) resolveManagedChat(group string, requireInfo bool, configuredSupers SuperUsers) (managedChat, error) {
	chatID, err := l.getChatID(group)
	if err != nil {
		return managedChat{}, fmt.Errorf("failed to get chat ID for group %q: %w", group, err)
	}
	info, err := l.TbAPI.GetChat(tbapi.ChatInfoConfig{ChatConfig: tbapi.ChatConfig{ChatID: chatID}})
	if err != nil {
		if requireInfo {
			return managedChat{}, fmt.Errorf("failed to get chat info for group %q: %w", group, err)
		}
		log.Printf("[WARN] failed to get chat info for group %q: %v", group, err)
	}
	name := info.Title
	if info.UserName != "" {
		name = "@" + info.UserName
	}
	if name == "" {
		name = strings.TrimSpace(group)
	}
	supers := append(SuperUsers(nil), configuredSupers...)
	admins, adminErr := l.TbAPI.GetChatAdministrators(tbapi.ChatAdministratorsConfig{
		ChatConfig: tbapi.ChatConfig{ChatID: chatID},
	})
	if adminErr != nil {
		log.Printf("[WARN] failed to get administrators for chat %d: %v", chatID, adminErr)
	} else {
		for _, member := range admins {
			if member.User.ID != 0 && !supers.IsSuper(member.User.UserName, member.User.ID) {
				supers = append(supers, strconv.FormatInt(member.User.ID, 10))
			}
		}
	}
	return managedChat{ID: chatID, Name: name, LinkedChannelID: info.LinkedChatID, SuperUsers: supers}, nil
}

// updateSupers updates the list of super-users based on the chat administrators fetched from the Telegram API.
// it uses the user ID first, but can match by username if set in the list of super-users.
func (l *TelegramListener) updateSupers() error {
	isSuper := func(username string, id int64) bool {
		for _, super := range l.SuperUsers {
			if super == fmt.Sprintf("%d", id) {
				return true
			}
			if username != "" && super == username {
				return true
			}
		}
		return false
	}

	admins, err := l.TbAPI.GetChatAdministrators(tbapi.ChatAdministratorsConfig{ChatConfig: tbapi.ChatConfig{ChatID: l.chatID}})
	if err != nil {
		return fmt.Errorf("failed to get chat administrators: %w", err)
	}

	for _, admin := range admins {
		if admin.User.UserName == "" && admin.User.ID == 0 {
			continue
		}
		if isSuper(admin.User.UserName, admin.User.ID) {
			continue // already in the list
		}
		l.SuperUsers = append(l.SuperUsers, fmt.Sprintf("%d", admin.User.ID))
	}

	log.Printf("[INFO] added admins, full list of supers: {%s}", strings.Join(l.SuperUsers, ", "))
	return nil
}

// deleteExtraMessages deletes additional messages specified in check results (e.g., duplicate messages)
func (l *TelegramListener) deleteExtraMessages(
	checkResults []spamcheck.Response, userID int64, username string, chatID int64, isSuper bool,
) {
	if len(checkResults) == 0 || l.Dry || l.TrainingMode {
		return
	}

	// don't delete messages from superusers
	if isSuper {
		log.Printf("[DEBUG] skip extra deletions for superuser %s (%d)", username, userID)
		return
	}

	// one deletion worker at a time keeps the overall delete rate at the intended limit
	l.extraDeletesMu.Lock()
	defer l.extraDeletesMu.Unlock()

	for _, checkResult := range checkResults {
		if !checkResult.Spam || len(checkResult.ExtraDeleteIDs) == 0 {
			continue
		}

		log.Printf("[INFO] deleting %d extra messages from user %d", len(checkResult.ExtraDeleteIDs), userID)
		for _, msgID := range checkResult.ExtraDeleteIDs {
			// add small delay to avoid rate limiting
			time.Sleep(35 * time.Millisecond)
			if _, err := l.TbAPI.Request(tbapi.DeleteMessageConfig{BaseChatMessage: tbapi.BaseChatMessage{
				MessageID:  msgID,
				ChatConfig: tbapi.ChatConfig{ChatID: chatID},
			}}); err != nil {
				// don't fail the whole operation if some messages can't be deleted
				log.Printf("[WARN] failed to delete extra message %d: %v", msgID, err)
			}
		}
	}
}

// procReaction handles a message_reaction update: checks if the reacting user is a spam bot and bans if needed.
func (l *TelegramListener) procReaction(ctx context.Context, r *tbapi.MessageReactionUpdated) error {
	if r.User == nil {
		log.Printf("[DEBUG] reaction from anonymous user, skipped")
		return nil
	}
	if !l.isChatAllowed(r.Chat.ID) {
		log.Printf("[DEBUG] reaction from unconfigured chat %d skipped", r.Chat.ID)
		return nil
	}
	// count only net new reactions; changes (👍→👎) and removals have newReactionsAdded <= 0
	newReactionsAdded := len(r.NewReaction) - len(r.OldReaction)
	if newReactionsAdded <= 0 {
		return nil
	}

	if l.isSuperForChat(r.Chat.ID, r.User.UserName, r.User.ID) {
		log.Printf("[DEBUG] superuser %s reaction ignored", r.User.UserName)
		return nil
	}

	var resp bot.Response
	for range newReactionsAdded {
		resp = onReactionInChat(l.Bot, r.Chat.ID, r.User.ID, r.User.UserName)
		if resp.BanInterval > 0 {
			break
		}
	}
	if resp.BanInterval <= 0 {
		return nil
	}

	if err := addSpamInChat(ctx, l.Locator, r.Chat.ID, r.User.ID, resp.CheckResults); err != nil {
		log.Printf("[WARN] failed to add reaction spam to locator: %v", err)
	}
	l.SpamLogger.Save(&bot.Message{From: resp.User, Text: "[reaction spam]", ChatID: r.Chat.ID}, &resp)

	banUserStr := resp.User.String()
	banReq := banRequest{
		duration: resp.BanInterval, userID: resp.User.ID, userName: banUserStr,
		chatID: r.Chat.ID, dry: l.Dry, training: l.TrainingMode, tbAPI: l.TbAPI, restrict: l.SoftBanMode,
	}
	if err := banUserOrChannel(banReq); err != nil {
		return fmt.Errorf("failed to ban reaction spammer %s: %w", banUserStr, err)
	}
	if l.adminChatID != 0 && resp.User.ID != 0 {
		l.adminHandlerForChat(r.Chat.ID).ReportReactionBan(banUserStr, resp.User)
	}
	return nil
}

// SuperUsers for moderators. Can be either username or user ID.
type SuperUsers []string

// IsSuper checks if userID or username in the list of superusers
// First it treats super as user ID, then as username
func (s SuperUsers) IsSuper(userName string, userID int64) bool {
	for _, super := range s {
		if id, err := strconv.ParseInt(super, 10, 64); err == nil {
			// super is user ID
			if userID == id {
				return true
			}
			continue
		}
		// super is username
		if strings.EqualFold(userName, super) || strings.EqualFold("/"+userName, super) {
			return true
		}
	}
	return false
}
