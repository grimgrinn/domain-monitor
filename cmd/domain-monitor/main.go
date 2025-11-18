package main

import (
	"domain-monitor/internal/api"
	"domain-monitor/internal/config"
	"domain-monitor/internal/keitaro"
	"fmt"
	"os"
	"time"
)

func main() {
	fmt.Println("=== Domain Monitor ===")
	fmt.Println("Загружаем настройки...")

	// Загружаем конфиг
	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Printf("Ошибка загрузки config.yaml: %v\n", err)
		return
	}

	kclient := keitaro.New(cfg.KeytaroAPIKey, cfg.KeytaroURL)

	var domains []keitaro.Domain
	if len(os.Args) > 1 {
		groupName := os.Args[1]
		domains, err = kclient.GetDomainsByGroup(groupName)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		fmt.Printf("cheching group '%s' (%d domains)\n\n", groupName, len(domains))
	} else {
		domains, err = kclient.GetActiveDomains()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		if len(domains) > 10 {
			domains = domains[:10]
			fmt.Printf("too many domains check first 10 \n\n")
		} else {
			fmt.Printf("checking %d active domians\n\n", len(domains))
		}
	}

	for i, domain := range domains {
		fmt.Printf("%d, %s (group: %s)\n", i+1, domain.Name, domain.Group)

		result, err := api.CheckDomain(domain.Name, cfg.VirusTotalAPIKey)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		} else if result.Safe {
			fmt.Printf("Safe (%d%% risk)\n", result.RiskScore)
		} else {
			fmt.Printf("Dangerous (%d%% risk)\n", result.RiskScore)
		}

		if i < len(domains)-1 {
			fmt.Printf("wait for 2 seconds...\n\n")
			time.Sleep(2 * time.Second)
		}
	}

	fmt.Printf("\n %d domains was checked\n", len(domains))
}
