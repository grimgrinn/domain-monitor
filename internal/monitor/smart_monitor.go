package monitor

import (
	"domain-monitor/internal/api"
	"domain-monitor/internal/models"
	"domain-monitor/internal/storage"
	"fmt"
	"log"
	"math/rand"
	"sync"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

type SmartMonitor struct {
	storage   *storage.Storage
	vtAPIKey  string
	cache     map[string]time.Time
	cacheLock sync.RWMutex
	stopChan  chan struct{}
	isRunning bool
	bot       *tgbotapi.BotAPI
	chatID    int64
}

func NewSmartMonitor(storage *storage.Storage, vtAPIkey string, bot *tgbotapi.BotAPI, chatID int64) *SmartMonitor {
	return &SmartMonitor{
		storage:   storage,
		vtAPIKey:  vtAPIkey,
		cache:     make(map[string]time.Time),
		stopChan:  make(chan struct{}),
		isRunning: false,
		bot:       bot,
		chatID:    chatID,
	}
}

func (m *SmartMonitor) Start() {
	if m.isRunning {
		log.Println("Monitor is already running")
		return
	}

	m.isRunning = true
	log.Println("Smart monitor started")

	go m.run()

	go m.scheduledDailyChecks()
}

func (m *SmartMonitor) Stop() {
	if !m.isRunning {
		return
	}

	close(m.stopChan)
	m.isRunning = false
	log.Println("smart monitor stopped")
}

func (m *SmartMonitor) run() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	m.checkDomains()

	for {
		select {
		case <-ticker.C:
			m.checkDomains()
		case <-m.stopChan:
			log.Println("monitor goroutine stopping...")
			return
		}
	}
}

func (m *SmartMonitor) checkDomains() {
	domains, err := m.storage.GetWatchedDomains()
	if err != nil {
		log.Printf("error getting wathced domains: %v", err)
		return
	}

	if len(domains) == 0 {
		log.Println("no domains to check")
		return
	}

	log.Printf("checking %d domains...", len(domains))

	checkedCount := 0
	for _, domain := range domains {
		if !m.shouldCheck(domain) {
			log.Printf("skipping %s (checked recently)", domain)
			continue
		}
		m.checkDomain(domain)
		checkedCount++
		delay := 30*time.Second + time.Duration(rand.Intn(15))*time.Second
		time.Sleep(delay)
		if checkedCount < len(domains) {
			time.Sleep(30 * time.Second)
		}
	}

	log.Printf("checked %d/%d domains", checkedCount, len(domains))
}

func (m *SmartMonitor) shouldCheck(domain string) bool {
	m.cacheLock.RLock()
	lastCheck, exists := m.cache[domain]
	m.cacheLock.RUnlock()

	return !exists || time.Since(lastCheck) > 5*time.Minute
}

func (m *SmartMonitor) checkDomain(domain string) {
	log.Printf("checking domain: %s", domain)

	result, err := api.CheckDomain(domain, m.vtAPIKey)
	if err != nil {
		log.Printf("Error checking %s: %v", domain, err)
		return
	}

	prevMalicious, prevSuspicioius, err := m.storage.GetLastCheck(domain)
	if err != nil {
		log.Printf("error getting last check for %s: %v", domain, err)
		return
	}

	err = m.storage.SaveCheckResult(domain, result.Stats.Malicious, result.Stats.Suspicious)
	if err != nil {
		log.Printf("error saving check result for %s: %v", domain, err)
		return
	}

	m.cacheLock.Lock()
	m.cache[domain] = time.Now()
	m.cacheLock.Unlock()

	log.Printf("%s: malicious=%d (was %d), suspicioius=%d (was %d)",
		domain, result.Stats.Malicious, prevMalicious,
		result.Stats.Suspicious, prevSuspicioius)

	m.checkForSignificantChanges(domain, result, prevMalicious, prevSuspicioius)
}

func (m *SmartMonitor) checkForSignificantChanges(
	domain string,
	result *models.VTDetailReport,
	prevMalicious, prevSuspicious int,
) {
	var changes []string
	if prevMalicious == 0 && result.Stats.Malicious > 0 {
		changes = append(changes,
			fmt.Sprintf("MALICIOUS DETECTED! (%d engines)", result.Stats.Malicious))
	}

	if result.Stats.Malicious > prevMalicious && prevMalicious > 0 {
		changes = append(changes,
			fmt.Sprintf("More malicious engines: %d -> %d (+%d)",
				prevMalicious, result.Stats.Malicious, result.Stats.Malicious-prevMalicious))
	}

	if prevSuspicious == 0 && result.Stats.Suspicious > 0 {
		changes = append(changes,
			fmt.Sprintf("Suspicious detected: %d engines", result.Stats.Suspicious))
	}

	if result.Stats.Suspicious > prevSuspicious && prevSuspicious > 0 {
		changes = append(changes,
			fmt.Sprintf("more suspicious: %d -> %d (+%d)",
				prevSuspicious, result.Stats.Suspicious, result.Stats.Suspicious-prevSuspicious))
	}

	if len(changes) > 0 {
		// m.sendNotification(domain, result, changes)
		m.sendNotificationToGroup(domain, result, changes)
	}
}

func (m *SmartMonitor) sendNotification(
	domain string,
	result *models.VTDetailReport,
	changes []string,
) {
	if m.bot == nil {
		log.Println("Bot not initialized, cannot send notification")
		return
	}

	var messageText string
	messageText += fmt.Sprintf("change detected: %s\n\n", domain)

	for _, change := range changes {
		messageText += fmt.Sprintf("- %s\n", change)
	}

	messageText += fmt.Sprintf("\n Currents stats: \n")
	messageText += fmt.Sprintf("Malicious: %d\n", result.Stats.Malicious)
	messageText += fmt.Sprintf("Suspicious: %d\n", result.Stats.Suspicious)
	messageText += fmt.Sprintf("Harmless: %d\n", result.Stats.Harmless)

	if len(result.Results.Malicious) > 0 {
		messageText += fmt.Sprintf("\n Malicious engins: \n:")
		for i, engine := range result.Results.Malicious {
			if i < 5 {
				messageText += fmt.Sprintf("- %s\n", engine)
			}
		}
		if len(result.Results.Malicious) > 5 {
			messageText += fmt.Sprintf("... and %d more \n", len(result.Results.Malicious)-5)
		}
	}

	msg := tgbotapi.NewMessage(m.chatID, messageText)
	_, err := m.bot.Send(msg)

	if err != nil {
		log.Printf("error sending notifications: %v", err)
	} else {
		log.Printf("Notification sent for %s", domain)
	}
}

func (m *SmartMonitor) sendNotificationToGroup(domain string, result *models.VTDetailReport, changes []string) {
	domainGroup, err := m.storage.GetDomainGroup(domain)
	if err != nil {
		log.Printf(" error getting domain group for %s: %v", domain, err)
		return
	}

	if domainGroup == "" {
		log.Printf("domain %s has no group, skipping notification", domain)
		return
	}

	users, err := m.storage.GetUsersByGroup(domainGroup)
	if err != nil {
		log.Printf("error getting users for group %s: %v", domainGroup, err)
		return
	}

	if len(users) == 0 {
		log.Printf("no users found gor group %s (domain: %s)", domainGroup, domain)
		return
	}

	log.Printf("Sending notifications for %s (group: %s) to %d users: %v", domain, domainGroup, len(users), users)

	for _, username := range users {
		m.sendNotificationToUser(username, domain, result, changes)
	}
}

func (m *SmartMonitor) sendNotificationToUser(username, domain string, result *models.VTDetailReport, changes []string) {
	var messageText string
	if username != "admin" {
		messageText += fmt.Sprintf("@%s\n", username)
	}

	messageText += fmt.Sprintf("Change detected: %s\n\n", domain)

	for _, change := range changes {
		messageText += fmt.Sprintf("- %s\n", change)
	}

	messageText += fmt.Sprintf("\n Current stats:\n")
	messageText += fmt.Sprintf("Malicious: %d\n", result.Stats.Malicious)
	messageText += fmt.Sprintf("Suspicious: %d\n", result.Stats.Suspicious)
	messageText += fmt.Sprintf("Harmless: %d\n", result.Stats.Harmless)

	if len(result.Results.Malicious) > 0 {
		messageText += fmt.Sprintf("\nMalicious engines:\n")
		for _, engine := range result.Results.Malicious {
			messageText += fmt.Sprintf("- %s\n", engine)
		}
	}

	msg := tgbotapi.NewMessage(m.chatID, messageText)
	_, err := m.bot.Send(msg)

	if err != nil {
		log.Printf("error sending notificatoin to @%s: %v", username, err)
	} else {
		log.Printf("Notification sent to @%s for %s", username, domain)
	}
}

func (m *SmartMonitor) scheduledDailyChecks() {
	go func() {
		for {
			now := time.Now()
			loc := now.Location()

			var nextCheck time.Time
			morning := time.Date(now.Year(), now.Month(), now.Day(), 8, 0, 0, 0, loc)
			evening := time.Date(now.Year(), now.Month(), now.Day(), 20, 0, 0, 0, loc)

			if now.Before(morning) {
				nextCheck = morning
			} else if now.Before(evening) {
				nextCheck = evening
			} else {
				tomorrow := now.Add(24 * time.Hour)
				nextCheck = time.Date(tomorrow.Year(), tomorrow.Month(), tomorrow.Day(), 8, 0, 0, 0, loc)
			}

			waitTime := time.Until(nextCheck)
			log.Printf("Next scheduled Keitaro check: %s (in %v)", nextCheck.Format("15:04"), waitTime.Round(time.Minute))

			time.Sleep(waitTime)

			log.Println("Scheduled Keitaro check started")
			m.checkKeitaroDomains()
		}
	}()
}

func (m *SmartMonitor) checkKeitaroDomains() {
	domains, err := m.storage.GetKeitaroDomains()
	if err != nil {
		log.Printf("Error getting Keitaro domains: %v", err)
		return
	}

	log.Printf("checking %d Keitaro domains (scheduled checks)...", len(domains))

	checkedCount := 0
	for i, domain := range domains {
		if !m.shouldCheck(domain) {
			log.Printf("%d/%d: %s (skepped, checked recentrly)", i+1, len(domains), domain)
			continue
		}

		log.Printf("%d/%d: %s", i+1, len(domains), domain)
		m.checkDomain(domain)
		checkedCount++

		if i < len(domains)-1 {
			time.Sleep(30 * time.Second)
		}
	}

	log.Printf("Scheduled check completed: %d/%d domains checked", checkedCount, len(domains))
}
