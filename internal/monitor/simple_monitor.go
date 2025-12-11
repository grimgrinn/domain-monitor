package monitor

import (
	"domain-monitor/internal/api"
	"domain-monitor/internal/keitaro"
	"fmt"
	"log"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

type SimpleMonitor struct {
	bot      *tgbotapi.BotAPI
	vtAPIKey string
	client   *keitaro.Client
}

func NewSimpleMonitor(bot *tgbotapi.BotAPI, vtAPIKey string, client *keitaro.Client) *SimpleMonitor {
	return &SimpleMonitor{
		bot:      bot,
		vtAPIKey: vtAPIKey,
		client:   client,
	}
}

func (sm *SimpleMonitor) Start() {
	log.Println("simple mmonitor started")

	domains, err := sm.client.GetActiveDomains()

	if err != nil {
		log.Printf("Error getting domains: %v", err)
		return
	}

	if len(domains) > 3 {
		domains = domains[:3]
	}

	log.Printf("checking %d domains...", len(domains))

	for _, domain := range domains {
		sm.checkDomain(domain.Name)
		time.Sleep(5 * time.Second)
	}

	log.Println("check complete")

	if sm.bot != nil {
		msg := tgbotapi.NewMessage(131640406,
			fmt.Sprintf("simple monitor checked %d domains", len(domains)))
		sm.bot.Send(msg)
	}
}

func (sm *SimpleMonitor) checkDomain(domain string) {
	log.Printf("checking: %s", domain)

	result, err := api.CheckDomain(domain, sm.vtAPIKey)
	if err != nil {
		log.Printf("error checking %s: %v", domain, err)
		return
	}

	log.Printf("%s: Malicioius=%d, Suspicious=%d", domain, result.Stats.Malicious, result.Stats.Suspicious)
}
