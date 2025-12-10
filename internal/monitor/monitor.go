package monitor

import (
	"domain-monitor/internal/api"
	"domain-monitor/internal/keitaro"
	"domain-monitor/internal/models"
	"fmt"
	"log"
	"sync"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

type Monitor struct {
	mu            sync.RWMutex
	domains       []DomainInfo
	history       map[string][]CheckResult
	lastCheck     map[string]time.Time
	lastChange    map[string]time.Time
	bot           *tgbotapi.BotAPI
	vtAPIKey      string
	keitaroAPI    *keitaro.Client
	checkInterval time.Duration
	isRunning     bool
	stopChan      chan bool
}

type DomainInfo struct {
	Name     string    `json:"name"`
	Source   string    `json:"source"`
	AddedAt  time.Time `json:"added_at"`
	Group    string    `json:"group,omitempty"`
	Priority int       `json:"priority"`
}

type CheckResult struct {
	Timestamp time.Time             `json:"timestamp"`
	Domain    string                `json:"domain"`
	Stats     models.VTDetailReport `json:"stats"`
	RiskLevel string                `json:"risk_level"`
	Changes   []Change              `json:"changes,omitempty"`
}

type Change struct {
	Type        string      `json:"type"`
	OldValue    interface{} `json:"old_value"`
	NewValue    interface{} `json:"new_value"`
	Description string      `json:"description"`
	Severity    string      `json:"severity"`
}

func NewMonitor(bot *tgbotapi.BotAPI, vtAPIkey string, keitaroClient *keitaro.Client) *Monitor {
	return &Monitor{
		domains:       make([]DomainInfo, 0),
		history:       make(map[string][]CheckResult),
		lastCheck:     make(map[string]time.Time),
		lastChange:    make(map[string]time.Time),
		bot:           bot,
		vtAPIKey:      vtAPIkey,
		keitaroAPI:    keitaroClient,
		checkInterval: 30 * time.Minute,
		stopChan:      make(chan bool),
	}
}

func (m *Monitor) Start() error {
	if m.isRunning {
		return fmt.Errorf("monitoring already started")
	}

	m.isRunning = true
	log.Println("start monitoring system")

	go m.initialCheck()

	go m.runScheduler()

	return nil
}

func (m *Monitor) Stop() {
	if m.isRunning {
		m.stopChan <- true
		m.isRunning = false
		log.Println("monitoring stoped")
	}
}

func (m *Monitor) loadDomainsFromKeitaro() error {
	if m.keitaroAPI == nil {
		return fmt.Errorf("keitaro client not initialized")
	}

	domains, err := m.keitaroAPI.GetActiveDomains()
	if err != nil {
		return fmt.Errorf("error getting domains: %w", err)
	}

	m.domains = make([]DomainInfo, 0, len(domains))

	for _, kd := range domains {
		domainInfo := DomainInfo{
			Name:     kd.Name,
			Source:   "keitaro",
			AddedAt:  time.Now(),
			Group:    kd.Group,
			Priority: 5,
		}
		m.domains = append(m.domains, domainInfo)
	}
	log.Printf("loaded %d domains from keitaro", len(domains))
	return nil
}

func (m *Monitor) checkDomain(domain string) {
	log.Printf("checking domain: %s", domain)

	vtResult, err := api.CheckDomain(domain, m.vtAPIKey)
	if err != nil {
		log.Printf("error checking %s: %v", domain, err)
		return
	}

	result := CheckResult{
		Timestamp: time.Now(),
		Domain:    domain,
		Stats:     *vtResult,
		RiskLevel: calculateRiskLevel(vtResult),
	}

	m.mu.Lock()
	m.history[domain] = append(m.history[domain], result)
	m.lastCheck[domain] = time.Now()
	m.mu.Unlock()

	if changes := m.detectChanges(domain, result); len(changes) > 0 {
		result.Changes = changes
		m.notifyChanges(domain, result, changes)
		m.lastChange[domain] = time.Now()
	}

	log.Printf("domain %s checked. risk: %s", domain, result.RiskLevel)
}

func calculateRiskLevel(result *models.VTDetailReport) string {
	if result.Stats.Malicious > 0 {
		return "critical"
	}
	if result.Stats.Suspicious > 3 {
		return "high"
	}
	if result.Stats.Suspicious > 0 {
		return "medium"
	}
	return "low"
}

func (m *Monitor) detectChanges(domain string, newResult CheckResult) []Change {
	m.mu.RLock()
	history := m.history[domain]
	m.mu.RUnlock()

	if len(history) < 2 {
		return nil
	}

	prevResult := history[len(history)-2]
	var changes []Change

	if prevResult.Stats.Stats.Malicious != newResult.Stats.Stats.Malicious {
		change := Change{
			Type:        "malicious",
			OldValue:    prevResult.Stats.Stats.Malicious,
			NewValue:    newResult.Stats.Stats.Malicious,
			Description: fmt.Sprintf("Malicious changed: %d -> %d", prevResult.Stats.Stats.Malicious, newResult.Stats.Stats.Malicious),
		}

		if newResult.Stats.Stats.Malicious > 0 && prevResult.Stats.Stats.Malicious == 0 {
			change.Severity = "danger"
		} else if newResult.Stats.Stats.Malicious > prevResult.Stats.Stats.Malicious {
			change.Severity = "warning"
		} else {
			change.Severity = "info"
		}
		changes = append(changes, change)
	}
	return changes
}

func (m *Monitor) notifyChanges(domain string, result CheckResult, changes []Change) {
	if m.bot == nil {
		return
	}

	message := fmt.Sprintf("change detected for %s\n", domain)
	message += fmt.Sprintf("risk level: %s\n", result.RiskLevel)

	for _, change := range changes {
		message += fmt.Sprintf(" - %s\n", change.Description)
	}

	chatID := int64(131640406)
	msg := tgbotapi.NewMessage(chatID, message)

	if _, err := m.bot.Send(msg); err != nil {
		log.Printf("Error sending notifications: %v", err)
	} else {
		log.Printf("Notification sent for %s", domain)
	}
}

func (m *Monitor) initialCheck() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.loadDomainsFromKeitaro(); err != nil {
		log.Printf("error loading domains from Keitaro: %v", err)
		return
	}

	if len(m.domains) == 0 {
		log.Println("no domains for monitoring")
		return
	}

	log.Printf("initial check of %d domains...", len(m.domains))

	for _, domain := range m.domains {
		m.checkDomain(domain.Name)
		time.Sleep(2 * time.Second)
	}

	log.Println("initial check complete")
}

func (m *Monitor) runScheduler() {
	ticker := time.NewTicker(m.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.performScheduledCheck()
		case <-m.stopChan:
			return
		}
	}
}

func (m *Monitor) performScheduledCheck() {
	m.mu.RLock()
	domains := make([]string, 0, len(m.domains))
	for _, d := range m.domains {
		domains = append(domains, d.Name)
	}
	m.mu.RUnlock()

	log.Printf("scheduled check %d domains", len(m.domains))

	for i, domain := range domains {
		m.checkDomain(domain)

		if i < len(domains)-1 {
			time.Sleep(1 * time.Second)
		}
	}

	log.Printf("scheduled check completed")
}
