package main

import (
	"domain-monitor/internal/api"
	"domain-monitor/internal/config"
	"domain-monitor/internal/keitaro"
	"domain-monitor/internal/models"
	"encoding/json"
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
				"/detailed <domain> - detailed check domain"+
				"/rawcheck <domain> - raw check domain\n"+
				"/check <domain> - check domain\n"+
				"/list - list domains from Keitaro\n"+
				"/group <name> - check by group\n"+
				"/help - help")
		bot.Send(msg)

	case "help":
		sendHelp(bot, message.Chat.ID)

	case "detailed":
		handleDetaledCheck(bot, message, cfg)

	case "rawcheck":
		handleRawCheck(bot, message, cfg)

	case "check":
		handleChecKDomain(bot, message, cfg)

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

	status := "SAFE"
	if !result.Safe {
		status = "UNSAFE"
	}

	response := fmt.Sprintf("Domain: %s\nStatus: %s\nRisk: %d%%", result.Domain, status, result.RiskScore)

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

		status := "SAFE"
		if !result.Safe {
			status = "UNSAFE"
		}

		response := fmt.Sprintf("Domain: %s\nStatus: %s\nRisk: %d%%", result.Domain, status, result.RiskScore)
		msg = tgbotapi.NewMessage(message.Chat.ID, response)
		bot.Send(msg)

		if i < len(domains)-1 {
			time.Sleep(2 * time.Second)
		}
	}
}

func handleDetaledCheck(bot *tgbotapi.BotAPI, message *tgbotapi.Message, cfg *config.Config) {
	domain := strings.TrimSpace(message.CommandArguments())
	if domain == "" {
		msg := tgbotapi.NewMessage(message.Chat.ID, "Usage: /detailed example.com")
		bot.Send(msg)
		return
	}

	msg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("Detailed check for %s...", domain))
	bot.Send(msg)

	result, err := api.CheckDomainRaw(domain, cfg.VirusTotalAPIKey)
	if err != nil {
		msg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("Error: %v", err))
		bot.Send(msg)
		return
	}

	response := formatDetailedVTForBot(result)
	msg = tgbotapi.NewMessage(message.Chat.ID, response)
	bot.Send(msg)
}

func formatDetailedVTForBot(report *models.RawReport) string {
	var data map[string]interface{}
	json.Unmarshal([]byte(report.RawData), &data)

	attributes := data["data"].(map[string]interface{})["attributes"].(map[string]interface{})

	var response strings.Builder
	response.WriteString(fmt.Sprintf("VT: %s\n", report.Domain))
	response.WriteString(fmt.Sprintf("Time: %s\n\n", report.Timestamp.Format("15:04 02.01")))

	if stats, exists := attributes["last_analysis_stats"].(map[string]interface{}); exists {
		response.WriteString("Results:\n")
		response.WriteString(fmt.Sprintf("Harmless: %d\n", int(stats["harmless"].(float64))))
		response.WriteString(fmt.Sprintf("Suspicious: %d\n", int(stats["suspicious"].(float64))))
		response.WriteString(fmt.Sprintf("Malicious: %d\n", int(stats["malicious"].(float64))))
		response.WriteString(fmt.Sprintf("Undetected: %d\n\n", int(stats["undetected"].(float64))))
	}

	if lastAnalysis, exists := attributes["last_analysis_results"].(map[string]interface{}); exists {
		maliciousEngines := []string{}
		suspiciousEngines := []string{}

		for engine, result := range lastAnalysis {
			resultMap := result.(map[string]interface{})
			category := resultMap["category"].(string)

			if category == "malicious" {
				maliciousEngines = append(maliciousEngines, engine)
			} else if category == "suspicious" {
				suspiciousEngines = append(suspiciousEngines, engine)
			}
		}

		if len(maliciousEngines) > 0 {
			response.WriteString(fmt.Sprintf("Malicious (%d):\n", len(maliciousEngines)))
			for _, engine := range maliciousEngines {
				response.WriteString(fmt.Sprintf("- %s\n", engine))
			}
			response.WriteString("\n")
		}

		if len(suspiciousEngines) > 0 {
			response.WriteString(fmt.Sprintf("Suspicious (%d):\n", len(suspiciousEngines)))
			for _, engine := range suspiciousEngines {
				response.WriteString(fmt.Sprintf("- %s\n", engine))
			}
			response.WriteString("\n")
		}
	}

	if reputation, exists := attributes["reputation"]; exists {
		response.WriteString(fmt.Sprintf("Reputation: %d\n", int(reputation.(float64))))
	}

	return response.String()
}

func sendHelp(bot *tgbotapi.BotAPI, chatID int64) {
	helpText := `Domain Monitor Bot
	
	
	Commands:
	/start - start work
	/help - show help
	
	Check domains:
	/detailed google.com - detailed check domain
	/rawcheck google.com - rawcheck domain
	/check google.com - check domain
	/list - list domains from Keitaro
	/group killa - check domains by group
	
	`

	msg := tgbotapi.NewMessage(chatID, helpText)
	bot.Send(msg)
}
