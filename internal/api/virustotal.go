package api

import (
	"domain-monitor/internal/models"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

type VirusTotalResponse struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Harmless   int `json:"harmless"`
			} `json:"last analysis stats"`
			Reputation int `json:"reputation"`
		} `json: "attributes"`
	} `json:"data"`
}

func CheckDomain(domain string) (*models.Report, error) {
	apiKey := os.Getenv("VIRUSTOTAL_API")
	if apiKey == "" {
		return demoCheck(domain), nil
	}

	url := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s", domain)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request failed: %v", err)
	}

	req.Header.Set("x-apikey", apiKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return demoCheck(domain), nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return demoCheck(domain), nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return demoCheck(domain), nil
	}

	var result VirusTotalResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return demoCheck(domain), nil
	}

	stats := result.Data.Attributes.LastAnalysisStats
	totalEngines := stats.Malicious + stats.Suspicious + stats.Harmless + stats.Undetected

	var riskScore int
	if totalEngines > 0 {
		riskScore = (stats.Malicious * 100) / totalEngines
	} else {
		riskScore = 0
	}

	isSafe := riskScore < 5

	return &models.Report{
		Domain:    domain,
		Safe:      isSafe,
		RiskScore: riskScore,
		Timestamp: time.Now(),
	}, nil
}

func demoCheck(domain string) *models.Report {
	safeDomains := map[string]bool{
		"google.com":    true,
		"github.com":    true,
		"example.com":   true,
		"microsoft.com": true,
	}

	isSafe := safeDomains[domain]
	riskScore := 0
	if !isSafe {
		riskScore = 30
	}

	return &models.Report{
		Domain:    domain,
		Safe:      isSafe,
		RiskScore: riskScore,
		Timestamp: time.Now(),
	}

}
