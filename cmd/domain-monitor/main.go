/*
package main

import (

	"domain-monitor/internal/api"
	"fmt"
	"os"

)

	func main() {
		if len(os.Args) < 2 {
			fmt.Println("usage: domain-monitor <domain1> <domain2> ,,,")
			os.Exit(1)
		}

		domains := os.Args[1:]

		fmt.Println("checking domains...")
		for _, domain := range domains {
			result, err := api.CheckDomain(domain)
			if err != nil {
				fmt.Printf("error checking checking %s: %v\n", domain, err)
				continue
			}

			status := "SAFE"
			if !result.Safe {
				status = "UNSAFE"
			}

			fmt.Printf("Domain: %s\nStatus: %s\nRisk: %d%%\n\n", result.Domain, status, result.RiskScore)
		}

}
*/
package main

import (
	"domain-monitor/internal/api"
	"fmt"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("🔍 Domain Monitor - VirusTotal API Checker")
		fmt.Println("Usage: domain-monitor <domain1> <domain2> ...")
		fmt.Println("Example: domain-monitor google.com github.com badsite.com")
		fmt.Println("\nSet VIRUSTOTAL_API_KEY environment variable for real checks")
		os.Exit(1)
	}

	domains := os.Args[1:]

	fmt.Printf("🔍 Checking %d domain(s)...\n", len(domains))
	fmt.Println("⏳ Please wait...")
	fmt.Println()

	for i, domain := range domains {
		fmt.Printf("%d. Checking: %s\n", i+1, domain)

		result, err := api.CheckDomain(domain)
		if err != nil {
			fmt.Printf("   ❌ Error: %v\n\n", err)
			continue
		}

		status := "🟢 SAFE"
		if !result.Safe {
			status = "🔴 UNSAFE"
		}

		riskLevel := "Low"
		if result.RiskScore > 50 {
			riskLevel = "HIGH"
		} else if result.RiskScore > 20 {
			riskLevel = "Medium"
		}

		fmt.Printf("   📊 Status: %s\n", status)
		fmt.Printf("   📈 Risk Score: %d%% (%s)\n", result.RiskScore, riskLevel)
		fmt.Printf("   ⏰ Checked: %s\n", result.Timestamp.Format("15:04:05"))
		fmt.Println()

		// Небольшая пауза между запросами чтобы не спамить API
		if i < len(domains)-1 {
			time.Sleep(1 * time.Second)
		}
	}

	fmt.Println("✅ Check completed!")
}
