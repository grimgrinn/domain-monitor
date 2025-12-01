package main

import (
	"domain-monitor/internal/api"
	"domain-monitor/internal/config"
	"domain-monitor/internal/googlesafebrowsing"
	"domain-monitor/internal/keitaro"
	"domain-monitor/internal/models"
	"fmt"
	"log"
	"strings"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Panic("config error:", err)
	}

	bot, err := tgbotapi.NewBotAPI(cfg.TelegramBotToken)
	if err != nil {
		log.Panic("bot creation error:", err)
	}

	bot.Debug = true
	log.Printf("bot %s started", bot.Self.UserName)

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60

	updates := bot.GetUpdatesChan(u)

	for update := range updates {
		if update.Message == nil {
			continue
		}

		log.Printf("[%s] %s", update.Message.From.UserName, update.Message.Text)

		switch {
		case update.Message.IsCommand():
			handleCommand(bot, update.Message, cfg)
		case strings.HasPrefix(update.Message.Text, "check "):
			handleChecKDomain(bot, update.Message, cfg)
		default:
			sendHelp(bot, update.Message.Chat.ID)
		}
	}
}

func handleCommand(bot *tgbotapi.BotAPI, message *tgbotapi.Message, cfg *config.Config) {
	switch message.Command() {
	case "start":
		msg := tgbotapi.NewMessage(message.Chat.ID,
			"Domain Monitor Bot \n\n"+
				"Commands: \n"+
				"/rawcheck <domain> - raw check domain\n"+
				"/check <domain> - check domain\n"+
				"/gsb <domain> - check domain with google safe browsing\n"+
				"/list - list domains from Keitaro\n"+
				"/group <name> - check by group\n"+
				"/help - help")
		bot.Send(msg)

	case "help":
		sendHelp(bot, message.Chat.ID)

	case "rawcheck":
		handleRawCheck(bot, message, cfg)

	case "check":
		handleChecKDomain(bot, message, cfg)

	case "gsb":
		handleGoogleCheck(bot, message, cfg)

	case "list":
		handleListDomains(bot, message, cfg)

	case "group":
		handleCheckGroup(bot, message, cfg)

	default:
		msg := tgbotapi.NewMessage(message.Chat.ID, "command unknown")

		bot.Send(msg)
	}
}

func handleChecKDomain(bot *tgbotapi.BotAPI, message *tgbotapi.Message, cfg *config.Config) {
	domain := strings.TrimSpace(message.CommandArguments())
	if domain == "" {
		msg := tgbotapi.NewMessage(message.Chat.ID, "enter domain: /check example.com")
		bot.Send(msg)
		return
	}

	msg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("Process %s...", domain))
	bot.Send(msg)

	result, err := api.CheckDomain(domain, cfg.VirusTotalAPIKey)
	if err != nil {
		msg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf(" Error: %v", err))
		bot.Send(msg)
		return
	}

	response := formatDetailedVT(result)
	msg = tgbotapi.NewMessage(message.Chat.ID, response)
	bot.Send(msg)
}

func handleListDomains(bot *tgbotapi.BotAPI, message *tgbotapi.Message, cfg *config.Config) {
	msg := tgbotapi.NewMessage(message.Chat.ID, "receiving domain list...")
	bot.Send(msg)

	kclient := keitaro.New(cfg.KeytaroAPIKey, cfg.KeytaroURL)
	domains, err := kclient.GetActiveDomains()
	if err != nil {
		msg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("error: %v", err))
		bot.Send(msg)
		return
	}

	if len(domains) == 0 {
		msg := tgbotapi.NewMessage(message.Chat.ID, "no active domains")
		bot.Send(msg)
		return
	}

	if len(domains) > 20 {
		domains = domains[:20]
	}

	var response strings.Builder
	response.WriteString(fmt.Sprintf("active domains (%d):\n\n", len(domains)))

	for i, domain := range domains {
		response.WriteString(fmt.Sprintf("%d. %s\n   Группа: %s\n\n",
			i+1, domain.Name, domain.Group))
	}

	if len(domains) == 20 {
		response.WriteString("..and others(show first 20)")
	}

	msg = tgbotapi.NewMessage(message.Chat.ID, response.String())
	bot.Send(msg)
}

func handleRawCheck(bot *tgbotapi.BotAPI, message *tgbotapi.Message, cfg *config.Config) {
	domain := strings.TrimSpace(message.CommandArguments())
	if domain == "" {
		msg := tgbotapi.NewMessage(message.Chat.ID, "Usage: /rawcheck example.com")
		bot.Send(msg)
		return
	}

	msg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("Getting raw data for %s...", domain))
	bot.Send(msg)

	result, err := api.CheckDomainRaw(domain, cfg.VirusTotalAPIKey)
	if err != nil {
		msg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("Error: %v", err))
		bot.Send(msg)
		return
	}

	rawData := result.RawData
	if len(rawData) > 4000 {
		rawData = rawData[:4000] + "\n... (truncated)"
	}

	response := fmt.Sprintf("Raw VT dat for %s:\n\n```json\n%s\n```", domain, rawData)

	msg = tgbotapi.NewMessage(message.Chat.ID, response)
	msg.ParseMode = "Markdown"
	bot.Send(msg)
}

func handleCheckGroup(bot *tgbotapi.BotAPI, message *tgbotapi.Message, cfg *config.Config) {
	groupName := strings.TrimSpace(message.CommandArguments())
	if groupName == "" {
		msg := tgbotapi.NewMessage(message.Chat.ID, "enter group name: /group killa")
		bot.Send(msg)
		return
	}

	msg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("checking group '%s' .... ", groupName))
	bot.Send(msg)

	kclient := keitaro.New(cfg.KeytaroAPIKey, cfg.KeytaroURL)
	domains, err := kclient.GetDomainsByGroup(groupName)
	if err != nil {
		msg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf(" Error: %v", err))
		bot.Send(msg)
		return
	}

	if len(domains) == 0 {
		msg := tgbotapi.NewMessage(message.Chat.ID, "there is no domains in group")
		bot.Send(msg)
		return
	}

	for i, domain := range domains {
		progressMsg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("check %d/%d: %s", i+1, len(domains), domain.Name))
		bot.Send(progressMsg)

		result, err := api.CheckDomain(domain.Name, cfg.VirusTotalAPIKey)
		if err != nil {
			msg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("error: %v", err))
			bot.Send(msg)
			continue
		}

		response := formatDetailedVT(result)
		msg = tgbotapi.NewMessage(message.Chat.ID, response)
		bot.Send(msg)

		if i < len(domains)-1 {
			time.Sleep(2 * time.Second)
		}
	}
}

func handleGoogleCheck(bot *tgbotapi.BotAPI, message *tgbotapi.Message, cfg *config.Config) {
	domain := strings.TrimSpace(message.CommandArguments())
	if domain == "" {
		msg := tgbotapi.NewMessage(message.Chat.ID, "Usage: /gsb example.com")
		bot.Send(msg)
		return
	}

	msg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("checking %s via Google Safe Browsing...", domain))
	bot.Send(msg)

	client := googlesafebrowsing.New(cfg.GoogleSafeBrowsingAPIKey)
	isDangerous, threats, err := client.CheckDomain(domain)

	if err != nil {
		msg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("Error: %v", err))
		bot.Send(msg)
		return
	}

	if isDangerous {
		msg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("%s is DANGEROUS\nThreats: %v", domain, threats))
		bot.Send(msg)
	} else {
		msg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("%s is SAFE (Google Safe Browsing)", domain))
		bot.Send(msg)
	}
}

func formatDetailedVT(report *models.VTDetailReport) string {

	var response strings.Builder
	response.WriteString(fmt.Sprintf("VT: %s\n", report.Domain))
	response.WriteString(fmt.Sprintf("Time: %s\n\n", report.Timestamp.Format("15:04 02.01")))

	response.WriteString("Results:\n")
	response.WriteString(fmt.Sprintf("Harmless: %d\n", report.Stats.Harmless))
	response.WriteString(fmt.Sprintf("Suspicious: %d\n", report.Stats.Suspicious))
	response.WriteString(fmt.Sprintf("Malicious: %d\n", report.Stats.Malicious))
	response.WriteString(fmt.Sprintf("Undetected: %d\n\n", report.Stats.Undetected))

	if len(report.Results.Malicious) > 0 {
		response.WriteString(fmt.Sprintf("Malicioius engines (%d):\n", len(report.Results.Malicious)))
		for _, engine := range report.Results.Malicious {
			response.WriteString(fmt.Sprintf("- %s\n", engine))
		}
		response.WriteString("\n")
	}

	if len(report.Results.Suspicious) > 0 {
		response.WriteString(fmt.Sprintf("Suspicious engines (%d):\n", len(report.Results.Suspicious)))
		for _, engine := range report.Results.Suspicious {
			response.WriteString(fmt.Sprintf("- %s\n", engine))
		}
		response.WriteString("\n")
	}

	if report.Reputation != 0 {
		response.WriteString(fmt.Sprintf("Reputation: %d\n", report.Reputation))
	}

	return response.String()
}

func sendHelp(bot *tgbotapi.BotAPI, chatID int64) {
	helpText := `Domain Monitor Bot
	
	
	Commands:
	/start - start work
	/help - show help
	
	Check domains:
	/rawcheck google.com - rawcheck domain
	/check google.com - check domain
	/gsb example.com - check domain with google safe browsing
	/list - list domains from Keitaro
	/group killa - check domains by group
	
	`

	msg := tgbotapi.NewMessage(chatID, helpText)
	bot.Send(msg)
}
