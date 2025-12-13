package monitor

import (
	"domain-monitor/internal/api"
	"domain-monitor/internal/storage"
	"log"
	"sync"
	"time"
)

type SmartMonitor struct {
	storage   *storage.Storage
	vtAPIKey  string
	cache     map[string]time.Time
	cacheLock sync.RWMutex
	stopChan  chan struct{}
	isRunning bool
}

func NewSmartMonitor(storage *storage.Storage, vtAPIkey string) *SmartMonitor {
	return &SmartMonitor{
		storage:   storage,
		vtAPIKey:  vtAPIkey,
		cache:     make(map[string]time.Time),
		stopChan:  make(chan struct{}),
		isRunning: false,
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

		if checkedCount < len(domains) {
			time.Sleep(10 * time.Second)
		}
	}

	log.Printf("checked %d/%d domains", checkedCount, len(domains))
}

func (m *SmartMonitor) shouldCheck(domain string) bool {
	m.cacheLock.RLock()
	lastCheck, exists := m.cache[domain]
	m.cacheLock.RUnlock()

	return !exists || time.Since(lastCheck) > 6*time.Hour
}

func (m *SmartMonitor) checkDomain(domain string) {
	log.Printf("checking domain: %s", domain)

	result, err := api.CheckDomain(domain, m.vtAPIKey)
	if err != nil {
		log.Printf("Error checking %s: %v", domain, err)
		return
	}

	m.cacheLock.Lock()
	m.cache[domain] = time.Now()
	m.cacheLock.Unlock()

	err = m.storage.SaveCheckResult(domain, result.Stats.Malicious, result.Stats.Suspicious)
	if err != nil {
		log.Printf("error saving check result for %s: %v", domain, err)
		return
	}

	log.Printf("%s: malicioius=%d", domain, result.Stats.Malicious)
}
