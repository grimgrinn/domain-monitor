package main

import (
	"domain-monitor/internal/config"
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

	app, err := NewApp(cfg)
	if err != nil {
		log.Panic("app creation error:", err)
	}

	log.Printf("bot %s started", app.Bot.Self.UserName)

	err = app.InitKeitaroDomains()
	if err != nil {
		log.Printf("could not load Keitaro domains: %v", err)
	}

	app.Monitor.Start() // start monitoring
	defer app.Monitor.Stop()

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60

	updates := app.Bot.GetUpdatesChan(u)

	for update := range updates {
		if update.Message == nil {
			continue
		}

		log.Printf("[%s] %s", update.Message.From.UserName, update.Message.Text)

		switch {
		case update.Message.IsCommand():
			handleCommand(app, update.Message)
		case strings.HasPrefix(update.Message.Text, "check "):
			handleCheckDomain(app, update.Message)
		default:
			sendHelp(app, update.Message.Chat.ID)
		}
	}
}

func handleCommand(app *App, message *tgbotapi.Message) {
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
				"/watch <domain> - add domain to monitoring\n"+
				"/unwatch <domain> - remove from monitoring\n"+
				"/list_watched - show watched domains\n"+
				"/monitor_status - show monitor status\n"+
				"/test_notify - test notification system\n"+
				"/set_group - set group\n"+
				"/my_groups - my groups\n"+
				"/help - help")
		app.Bot.Send(msg)

	case "help":
		sendHelp(app, message.Chat.ID)

	case "rawcheck":
		handleRawCheck(app, message)

	case "check":
		handleCheckDomain(app, message)

	case "gsb":
		handleGoogleCheck(app, message)

	case "gsbdetail":
		handleGSBDetail(app, message)

	case "list":
		handleListDomains(app, message)

	case "group":
		handleCheckGroup(app, message)

	case "watch":
		handleWatch(app, message)

	case "unwatch":
		handleUnwatch(app, message)

	case "list_watched":
		handleListWatched(app, message)

	case "monitor_status":
		handleMonitorStatus(app, message)

	case "test_notify":
		handleTestNotifyCommand(app, message)

	case "set_group":
		handleSetGroup(app, message)

	case "init_groups":
		handleInitGroups(app, message)

	case "my_groups":
		handleMyGroups(app, message)

	case "keitaro_load":
		handleKeitaroLoad(app, message)

	default:
		msg := tgbotapi.NewMessage(message.Chat.ID, "command unknown")

		app.Bot.Send(msg)
	}
}

func handleCheckDomain(app *App, message *tgbotapi.Message) {
	domain := strings.TrimSpace(message.CommandArguments())
	if domain == "" {
		msg := tgbotapi.NewMessage(message.Chat.ID, "enter domain: /check example.com")
		app.Bot.Send(msg)
		return
	}

	msg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("Process %s...", domain))
	app.Bot.Send(msg)

	result, err := app.CheckDomain(domain)
	if err != nil {
		msg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf(" Error: %v", err))
		app.Bot.Send(msg)
		return
	}

	response := formatDetailedVT(result)
	msg = tgbotapi.NewMessage(message.Chat.ID, response)
	app.Bot.Send(msg)
}

func handleListDomains(app *App, message *tgbotapi.Message) {
	msg := tgbotapi.NewMessage(message.Chat.ID, "receiving domain list...")
	app.Bot.Send(msg)

	domains, err := app.Keitaro.GetActiveDomains()
	if err != nil {
		msg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("error: %v", err))
		app.Bot.Send(msg)
		return
	}

	if len(domains) == 0 {
		msg := tgbotapi.NewMessage(message.Chat.ID, "no active domains")
		app.Bot.Send(msg)
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
	app.Bot.Send(msg)
}

func handleRawCheck(app *App, message *tgbotapi.Message) {
	domain := strings.TrimSpace(message.CommandArguments())
	if domain == "" {
		msg := tgbotapi.NewMessage(message.Chat.ID, "Usage: /rawcheck example.com")
		app.Bot.Send(msg)
		return
	}

	msg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("Getting raw data for %s...", domain))
	app.Bot.Send(msg)

	result, err := app.CheckDomainRaw(domain)
	if err != nil {
		msg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("Error: %v", err))
		app.Bot.Send(msg)
		return
	}

	rawData := result.RawData
	if len(rawData) > 4000 {
		rawData = rawData[:4000] + "\n... (truncated)"
	}

	response := fmt.Sprintf("Raw VT dat for %s:\n\n```json\n%s\n```", domain, rawData)

	msg = tgbotapi.NewMessage(message.Chat.ID, response)
	msg.ParseMode = "Markdown"
	app.Bot.Send(msg)
}

func handleCheckGroup(app *App, message *tgbotapi.Message) {
	groupName := strings.TrimSpace(message.CommandArguments())
	if groupName == "" {
		msg := tgbotapi.NewMessage(message.Chat.ID, "enter group name: /group killa")
		app.Bot.Send(msg)
		return
	}

	msg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("checking group '%s' .... ", groupName))
	app.Bot.Send(msg)

	domains, err := app.Keitaro.GetDomainsByGroup(groupName)
	if err != nil {
		msg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf(" Error: %v", err))
		app.Bot.Send(msg)
		return
	}

	if len(domains) == 0 {
		msg := tgbotapi.NewMessage(message.Chat.ID, "there is no domains in group")
		app.Bot.Send(msg)
		return
	}

	for i, domain := range domains {
		progressMsg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("check %d/%d: %s", i+1, len(domains), domain.Name))
		app.Bot.Send(progressMsg)

		result, err := app.CheckDomain(domain.Name)
		if err != nil {
			msg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("error: %v", err))
			app.Bot.Send(msg)
			continue
		}

		response := formatDetailedVT(result)
		msg = tgbotapi.NewMessage(message.Chat.ID, response)
		app.Bot.Send(msg)

		if i < len(domains)-1 {
			time.Sleep(2 * time.Second)
		}
	}
}

func handleGoogleCheck(app *App, message *tgbotapi.Message) {
	domain := strings.TrimSpace(message.CommandArguments())
	if domain == "" {
		msg := tgbotapi.NewMessage(message.Chat.ID, "Usage: /gsb example.com")
		app.Bot.Send(msg)
		return
	}

	msg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("checking %s via Google Safe Browsing...", domain))
	app.Bot.Send(msg)

	report, err := app.GSB.GetFormattedReport(domain)

	if err != nil {
		msg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("Error: %v", err))
		app.Bot.Send(msg)
		return
	}

	msg = tgbotapi.NewMessage(message.Chat.ID, report)
	app.Bot.Send(msg)

	result, _ := app.GSB.CheckDomain(domain)
	if result != nil && result.RawResponse != "" && result.RawResponse != "{}" {
		rawMsg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("Raw API answer: \n ```json\n%s\n```", result.RawResponse))
		rawMsg.ParseMode = "Markdown"
		app.Bot.Send(rawMsg)
	}
}

func handleGSBDetail(app *App, message *tgbotapi.Message) {
	domain := strings.TrimSpace(message.CommandArguments())
	if domain == "" {
		app.Bot.Send(tgbotapi.NewMessage(message.Chat.ID, "Usage: /gsbdetail example.com"))
		return
	}

	detailed, err := app.GSB.GetDetailedResult(domain)

	if err != nil {
		app.Bot.Send(tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("Error: %v", err)))
		return
	}

	var response strings.Builder
	response.WriteString(detailed.Formatted + "\n\n")
	response.WriteString("Details: \n")
	response.WriteString(fmt.Sprintf("Checked: %s\n", detailed.CheckedAt.Format("15:04:05 02.01.2025")))
	response.WriteString(fmt.Sprintf("URL for check: %s\n", detailed.Result.CheckedURL))
	response.WriteString(fmt.Sprintf("Status: %s\n", detailed.Result.Status))

	if detailed.Result.IsDangerous {
		response.WriteString(fmt.Sprintf("Menaces qunatity: %d\n", len(detailed.Result.Threats)))
	}

	if detailed.Result.RawResponse != "" {
		rawMsg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("Full API answer:\n ```json\n%s\n", detailed.Result.RawResponse))
		rawMsg.ParseMode = "Markdown"
		app.Bot.Send(rawMsg)
	}
}

func handleWatch(app *App, message *tgbotapi.Message) {
	domain := strings.TrimSpace(message.CommandArguments())
	if domain == "" {
		msg := tgbotapi.NewMessage(message.Chat.ID, "Usage: /watch example.com")
		app.Bot.Send(msg)
		return
	}

	err := app.Storage.AddDomain(domain)
	if err != nil {
		msg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("error: %v", err))
		app.Bot.Send(msg)
		return
	}

	msg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("add %s to monitoring\n\nWill check every 6 hours", domain))
	app.Bot.Send(msg)
}

func handleListWatched(app *App, message *tgbotapi.Message) {
	domains, err := app.Storage.GetWatchedDomains()
	if err != nil {
		msg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("error: %v", err))
		app.Bot.Send(msg)
		return
	}

	if len(domains) == 0 {
		msg := tgbotapi.NewMessage(message.Chat.ID, "no domians watched")
		app.Bot.Send(msg)
		return
	}

	if len(domains) == 0 {
		msg := tgbotapi.NewMessage(message.Chat.ID, "no domains watched")
		app.Bot.Send(msg)
		return
	}

	var response strings.Builder
	response.WriteString(fmt.Sprintf("watched domains (%d):\n\n", len(domains)))

	for i, domain := range domains {
		response.WriteString(fmt.Sprintf("%d. %s\n", i+1, domain))
	}

	msg := tgbotapi.NewMessage(message.Chat.ID, response.String())
	app.Bot.Send(msg)
}

func handleUnwatch(app *App, message *tgbotapi.Message) {
	domain := strings.TrimSpace(message.CommandArguments())
	if domain == "" {
		msg := tgbotapi.NewMessage(message.Chat.ID, "Usage: /unwatch example.com")
		app.Bot.Send(msg)
		return
	}

	err := app.Storage.RemoveDomain(domain)
	if err != nil {
		msg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("error: %v", err))
		app.Bot.Send(msg)
		return
	}

	msg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("removed %s from monitoring", domain))
	app.Bot.Send(msg)
}

func handleMonitorStatus(app *App, message *tgbotapi.Message) {
	domains, err := app.Storage.GetWatchedDomains()
	if err != nil {
		msg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("error: %v", err))
		app.Bot.Send(msg)
		return
	}

	msg := tgbotapi.NewMessage(message.Chat.ID,
		fmt.Sprintf("Monitor Status\n\n"+
			"- watching %d domains\n"+
			"- checks every 6 hours (VT limits)\n"+
			"- next check in ~5 milutes \n\n"+
			"Use /list_watched to see domains",
			len(domains)))
	app.Bot.Send(msg)
}

func handleTestNotifyCommand(app *App, message *tgbotapi.Message) {
	testResult := &models.VTDetailReport{
		Domain: "test.com",
		Stats: struct {
			Harmless   int `json:"harmless"`
			Suspicious int `json:"suspicious"`
			Malicious  int `json:"malicious"`
			Undetected int `json:"undetected"`
			Total      int `json:"total"`
		}{
			Malicious:  3,
			Suspicious: 2,
			Harmless:   68,
		},
		Results: struct {
			Malicious  []string `json:"malicious"`
			Suspicious []string `json:"suspicious"`
			Harmless   []string `json:"harmless"`
			Undetected []string `json:"undetected"`
		}{
			Malicious: []string{"SomeAntiVirus", "AnotherAV", "TestEngine", "Engine4", "Engine5", "Engine6"},
		},
	}

	changes := []string{
		"MALICIOIUS DETECTED! (3 engines)",
		"Suspicious detected: 2 engiens",
	}

	msg := tgbotapi.NewMessage(message.Chat.ID,
		"Test notification sent!\n\n"+
			"Check your notifications - you should see a test message.")
	app.Bot.Send(msg)

	if app.Monitor != nil {
		notificationText := fmt.Sprintf("Change detected: %s\n\n", testResult.Domain)

		for _, change := range changes {
			notificationText += fmt.Sprintf("- %s\n", change)
		}

		notificationText += fmt.Sprintf("\nCurrent stats:\n")
		notificationText += fmt.Sprintf("Malicious: %d\n", testResult.Stats.Malicious)
		notificationText += fmt.Sprintf("Suspicious: %d\n", testResult.Stats.Suspicious)
		notificationText += fmt.Sprintf("Harmless: %d\n", testResult.Stats.Harmless)
		notificationText += fmt.Sprintf("\nMalicious engines:\n")
		for i, engine := range testResult.Results.Malicious {
			if i < 5 {
				notificationText += fmt.Sprintf("- %s\n", engine)
			}
		}

		testMsg := tgbotapi.NewMessage(message.Chat.ID, notificationText)
		app.Bot.Send(testMsg)
	}
}

func handleSetGroup(app *App, message *tgbotapi.Message) {
	if message.From.UserName != "grimgrinn" {
		msg := tgbotapi.NewMessage(message.Chat.ID, "Only admin can set group")
		app.Bot.Send(msg)
		return
	}

	args := strings.TrimSpace(message.CommandArguments())
	if args == "" {
		msg := tgbotapi.NewMessage(message.Chat.ID, "Usage: /set_group username group1 group2\n Example: /set_group kbite kbite")
		app.Bot.Send(msg)
		return
	}

	parts := strings.SplitN(args, " ", 2)
	if len(parts) != 2 {
		msg := tgbotapi.NewMessage(message.Chat.ID, "Usage: /set_group username group1 group2\n Example: /set_group kbite kbite")
		app.Bot.Send(msg)
		return
	}

	username := strings.TrimSpace(parts[0])
	groups := strings.TrimSpace(parts[1])

	err := app.Storage.SaveUserGroup(username, groups)
	if err != nil {
		msg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("Error: %v", err))
		app.Bot.Send(msg)
		return
	}

	msg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("Saved mapping:\n@%s -> %s", username, groups))
	app.Bot.Send(msg)
}

func handleInitGroups(app *App, message *tgbotapi.Message) {
	if message.From.UserName != "grimgrinn" {
		msg := tgbotapi.NewMessage(message.Chat.ID, "Only admin can init groups")
		app.Bot.Send(msg)
		return
	}

	mappings := map[string]string{
		"admin":      "admin",
		"kbite":      "kbite",
		"dzb":        "dzb",
		"dim":        "DIM",
		"skv":        "SK",
		"maxs":       "dmg",
		"stack":      "kol",
		"yol":        "Yol",
		"asdzxc123":  "RS",
		"akv":        "AKV",
		"allin":      "DR",
		"MaxP":       "MaxP",
		"Kobe":       "Kobe",
		"sapi":       "SAP",
		"tochik":     "Alabau",
		"TRUE":       "Real",
		"vlad_brius": "ZVV",
		"k1ra":       "k1ra,k1raADV",
		"bolded":     "Boldeb",
		"Slon":       "Slon",
		"Alleasy":    "Alleasy",
		"azn":        "Khal",
		"winx":       "Solo",
		"churchhell": "VV8",
		"chain_borz": "Profit",
		"hikaru":     "hikaru",
		"mur":        "Lolka",
		"santa":      "VV8",
		"mi6":        "var",
		"www95":      "www95",
		"danunax":    "acc",
		"minaev":     "Pinkaa",
		"sokrat":     "sokrat",
		"fendi":      "Fendi",
		"vix":        "Lime",
		"jink":       "Killa",
	}

	count := 0
	for username, groups := range mappings {
		err := app.Storage.SaveUserGroup(username, groups)
		if err != nil {
			log.Printf("error saving %s: %v", username, err)
		} else {
			count++
		}
	}

	msg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("initialized %d user groupos", count))
	app.Bot.Send(msg)
}

func handleMyGroups(app *App, message *tgbotapi.Message) {
	username := message.From.UserName
	groups, err := app.Storage.GetUserGroups(username)
	if err != nil {
		msg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("Error: %v", err))
		app.Bot.Send(msg)
		return
	}

	if groups == nil {
		msg := tgbotapi.NewMessage(message.Chat.ID, "You don't have any groups assigned")
		app.Bot.Send(msg)
		return
	}

	var response string
	if len(groups) == 0 {
		response = "you have empty groups (won't reveive notifications)"
	} else {
		response = fmt.Sprintf("your groups: %s", strings.Join(groups, ","))
	}

	msg := tgbotapi.NewMessage(message.Chat.ID, response)
	app.Bot.Send(msg)
}

func handleKeitaroLoad(app *App, message *tgbotapi.Message) {
	msg := tgbotapi.NewMessage(message.Chat.ID, "Loading domains from Keitaro...")
	app.Bot.Send(msg)

	err := app.Storage.LoadKeitaroDomains(app.Keitaro)
	if err != nil {
		msg = tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("Error: %v", err))
	} else {
		domains, _ := app.Storage.GetKeitaroDomains()
		msg = tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("Loaded %d domains from Keitaro\n\n Firts 5:\n%s",
			len(domains),
			strings.Join(domains[:min(5, len(domains))],
				"\n")))
	}
	app.Bot.Send(msg)
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

func sendHelp(app *App, chatID int64) {
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
	app.Bot.Send(msg)
}
