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
