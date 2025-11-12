package api

import (
	"domain-monitor/internal/models"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

func CheckDomain(domain string, apiKey string) (*models.Report, error) {
	fmt.Printf(" send req to vt...\b")

	url := fmt.Sprintf("http://www.virustotal.com/api/v3/domains/%s", domain)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("request error: %v", err)
	}

	req.Header.Set("x-apikey", apiKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connection error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API error: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Request patsing error: %v", err)
	}

	var result struct {
		Data struct {
			Attributes struct {
				LastAanalysisStats struct {
					Malicious int `json:"malicious"`
					Harmless  int `json:"harmless"`
				} `json:"last_analysis_stats"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("JSON parsing error: %v", err)
	}

	stats := result.Data.Attributes.LastAanalysisStats
	total := stats.Malicious + stats.Harmless

	var riskScore int
	if total > 0 {
		riskScore = (stats.Malicious * 100) / total
	}

	isSafe := riskScore < 10

	fmt.Printf("Got answer: %d antiviruses find menaces\n", stats.Malicious)

	return &models.Report{
		Domain:    domain,
		Safe:      isSafe,
		RiskScore: riskScore,
		Timestamp: time.Now(),
	}, nil
}
