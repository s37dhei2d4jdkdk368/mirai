package telegram

import (
	"cnc/core/config"
	"github.com/go-telegram-bot-api/telegram-bot-api"
	"log"
)

func Init() {
	bot, err := tgbotapi.NewBotAPI(config.Config.Telegram.BotToken)
	if err != nil {
		log.Printf("[telegram] Failed to initialize bot: %v", err)
		log.Printf("[telegram] Telegram features disabled. Fix bot token in config.json to enable.")
		return
	}

	bot.Debug = false

	log.Printf("[telegram] Authorized on account %s", bot.Self.UserName)

	err = HandleCommand(bot)
	if err != nil {
		log.Printf("[telegram] Error handling commands: %v", err)
	}
}
