package api

import (
	"domain-monitor/internal/models"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type RawVRResponse struct {
	Data  json.RawMessage `json:"data"`
	Error *VTError        `json:"error,omitempty"`
}

type VTError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func CheckDomainRaw(domain string, apiKey string) (*models.RawReport, error) {
	fmt.Printf("send req to vt for %s\n", domain)

	url := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s", domain)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("request error: %v", err)
	}

	req.Header.Set("x-apikey", apiKey)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connection error: %v", err)
	}

	defer resp.Body.Close()

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response error: %v", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API returned HTTP %d: %s", resp.StatusCode, string(rawBody))
	}

	var rawResp RawVRResponse
	if err := json.Unmarshal(rawBody, &rawResp); err != nil {
		return nil, fmt.Errorf("JSON parsing error: %v", err)
	}

	if rawResp.Error != nil {
		return nil, fmt.Errorf("VT API error: %s - %s", rawResp.Error.Code, rawResp.Error.Message)
	}

	fmt.Printf("Received raw data from VirusTotal (%d bytes)\n", len(rawBody))

	return &models.RawReport{
		Domain:    domain,
		RawData:   string(rawBody),
		Timestamp: time.Now(),
	}, nil
}

func CheckDomain(domain string, apiKey string) (*models.VTDetailReport, error) {
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

	return parseVTResponse(domain, body)
}

func parseVTResponse(domain string, body []byte) (*models.VTDetailReport, error) {
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("JSON parsing error: %v", err)
	}

	attributes := data["data"].(map[string]interface{})["attributes"].(map[string]interface{})

	report := &models.VTDetailReport{
		Domain:    domain,
		Timestamp: time.Now(),
	}

	if stats, exists := attributes["last_analysis_stats"].(map[string]interface{}); exists {
		report.Stats.Harmless = int(stats["harmless"].(float64))
		report.Stats.Suspicious = int(stats["suspicious"].(float64))
		report.Stats.Malicious = int(stats["malicious"].(float64))
		report.Stats.Undetected = int(stats["undetected"].(float64))
		report.Stats.Total = report.Stats.Harmless + report.Stats.Suspicious + report.Stats.Malicious + report.Stats.Undetected
	}

	if lastAnalysis, exists := attributes["last_analysis_results"].(map[string]interface{}); exists {
		report.Results.Malicious = []string{}
		report.Results.Suspicious = []string{}
		report.Results.Harmless = []string{}
		report.Results.Undetected = []string{}

		for engine, results := range lastAnalysis {
			resultMap := results.(map[string]interface{})
			category := resultMap["category"].(string)

			switch category {
			case "malicious":
				report.Results.Malicious = append(report.Results.Malicious, engine)
			case "suspicious":
				report.Results.Suspicious = append(report.Results.Suspicious, engine)
			case "harmless":
				report.Results.Harmless = append(report.Results.Harmless, engine)
			case "undetected":
				report.Results.Undetected = append(report.Results.Undetected, engine)
			}
		}
	}

	if reputation, exists := attributes["reputation"]; exists {
		report.Reputation = int(reputation.(float64))
	}

	if categories, exists := attributes["categories"]; exists {
		report.Categories = make(map[string]string)
		for engine, category := range categories.(map[string]interface{}) {
			report.Categories[engine] = category.(string)
		}
	}

	if lastAnalysis, exists := attributes["last_analysis_date"]; exists {
		report.LastAnalysis = int64(lastAnalysis.(float64))
	}

	return report, nil
}

func CheckDomainSimple(domain string, apiKey string) (*models.Report, error) {
	detailed, err := CheckDomain(domain, apiKey)
	if err != nil {
		return nil, err
	}

	return &models.Report{
		Domain:    domain,
		Safe:      detailed.Stats.Malicious == 0 && detailed.Stats.Suspicious == 0,
		RiskScore: (detailed.Stats.Malicious * 100) / detailed.Stats.Total,
		Timestamp: detailed.Timestamp,
	}, nil
}
