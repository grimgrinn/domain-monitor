package main

import (
	"domain-monitor/internal/api"
	"domain-monitor/internal/config"
	"fmt"
	"os"
)

func main() {
	fmt.Println("=== Domain Monitor ===")
	fmt.Println("Загружаем настройки...")

	// Загружаем конфиг
	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Printf("Ошибка загрузки config.yaml: %v\n", err)
		fmt.Println("Создайте файл config.yaml с API ключами")
		return
	}

	fmt.Println("Настройки загружены!")
	fmt.Println()

	// Проверяем домены из командной строки
	if len(os.Args) < 2 {
		fmt.Println("Использование:")
		fmt.Println("  domain-monitor <domain1> <domain2> ...")
		fmt.Println()
		fmt.Println("Пример:")
		fmt.Println("  domain-monitor google.com github.com")
		return
	}

	domains := os.Args[1:]
	fmt.Printf("Проверяем %d домен(ов):\n", len(domains))

	for i, domain := range domains {
		fmt.Printf("\n%d. Домен: %s\n", i+1, domain)

		// Проверяем домен через VirusTotal
		result, err := api.CheckDomain(domain, cfg.VirusTotalAPIKey)
		if err != nil {
			fmt.Printf("   Ошибка проверки: %v\n", err)
			continue
		}

		// Показываем результат
		if result.Safe {
			fmt.Printf("   ✅ БЕЗОПАСНЫЙ (риск: %d%%)\n", result.RiskScore)
		} else {
			fmt.Printf("   ❌ ОПАСНЫЙ (риск: %d%%)\n", result.RiskScore)
		}
	}

	fmt.Println("\n=== Проверка завершена ===")
}
