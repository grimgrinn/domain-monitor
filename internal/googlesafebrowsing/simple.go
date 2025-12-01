package googlesafebrowsing

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type Client struct {
	APIKey string
}

func New(apiKey string) *Client {
	return &Client{APIKey: apiKey}
}

func (c *Client) CheckDomain(domain string) (bool, []string, error) {
	url := fmt.Sprintf("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=%s", c.APIKey)

	request := map[string]interface{}{
		"client": map[string]interface{}{
			"clientId":      "domain-monitor",
			"clientVersion": "1.0",
		},
		"threatInfo": map[string]interface{}{
			"threatTypes": []string{
				"MALWARE",
				"SOCIAL_ENGINEERING",
				"UNWANTED_SOFTWARE",
			},
			"platformTypes":    []string{"ANY_PLATFORM"},
			"threatEntryTypes": []string{"URL"},
			"threatEntries": []map[string]string{
				{"url": "http://" + domain},
			},
		},
	}

	jsonData, _ := json.Marshal(request)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return false, nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, nil, fmt.Errorf("parse failed: %v", err)
	}

	if matches, ok := result["matches"].([]interface{}); ok && len(matches) > 0 {
		threatTypes := []string{}
		for _, match := range matches {
			if m, ok := match.(map[string]interface{}); ok {
				if threatType, ok := m["threatType"].(string); ok {
					threatTypes = append(threatTypes, strings.ToLower(threatType))
				}
			}
		}
		return true, threatTypes, nil
	}

	return false, nil, nil
}
