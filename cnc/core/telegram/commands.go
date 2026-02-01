package telegram

import (
	"cnc/core/config"
	"cnc/core/slaves"
	"fmt"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api"
	"log"
	"net"
	"time"
)

var PreviousDistribution map[string]int

func HandleCommand(bot *tgbotapi.BotAPI) error {
	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60

	updates, err := bot.GetUpdatesChan(u)
	if err != nil {
		return err
	}

	for update := range updates {
		if update.Message == nil {
			continue
		}

		if update.Message.IsCommand() {
			cmd := update.Message.Command()
			switch cmd {
			case "ping":
				start := time.Now()
				conn, err := net.Dial("tcp", "1.1.1.1:443")
				if err != nil {
					return err
				}
				conn.Close()
				duration := time.Since(start)

				var durationStr string
				if duration.Milliseconds() < 1000 {
					durationStr = fmt.Sprintf("%dms", duration.Milliseconds())
				} else {
					durationStr = fmt.Sprintf("%.2fs", duration.Seconds())
				}

				msg := tgbotapi.NewMessage(update.Message.Chat.ID, fmt.Sprintf("pong! %s", durationStr))
				_, err = bot.Send(msg)
				if err != nil {
					log.Println(err)
					return err
				}

			case "bots":
				userID := update.Message.From.ID
				if !isAdmin(userID, config.Config.Telegram.Admins) {
					msg := tgbotapi.NewMessage(update.Message.Chat.ID, "Sorry, you are not authorized to use this bot.")
					_, err := bot.Send(msg)
					if err != nil {
						log.Println(err)
					}
					continue
				}

				m := slaves.CL.Distribution()
				totalCount := slaves.CL.Count()

				message := ""
				for k, v := range m {
					change := v - PreviousDistribution[k]
					var msg string
					if change > 0 {
						msg = fmt.Sprintf("%s: %d (+%d)", k, v, change)
					} else if change < 0 {
						msg = fmt.Sprintf("%s: %d (%d)", k, v, change)
					} else {
						msg = fmt.Sprintf("%s: %d", k, v)
					}
					message += msg + "\n"
				}

				PreviousDistribution = m
				totalMsg := fmt.Sprintf("Total: %d", totalCount)
				message += totalMsg

				msg := tgbotapi.NewMessage(update.Message.Chat.ID, message)
				_, err = bot.Send(msg)
				if err != nil {
					log.Println(err)
					return err
				}
				continue
			}
		}
	}
	return nil
}
