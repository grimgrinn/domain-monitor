package googlesafebrowsing

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	apiKey string
	client *http.Client
}

type GSBResponse struct {
	Matches []struct {
		ThreatType      string `json:"threatType"`
		PlatformType    string `json:"platformType"`
		ThreatEntryType string `json:"threatEntryType"`
		Threat          struct {
			URL string `json:"url"`
		} `json:"threat"`
		CacheDuration       string `json:"cacheDuration,omitempty"`
		ThreatEntryMetadata struct {
			Entries []struct {
				Key   string `json:"key"`
				Value string `json:"value"`
			} `json:"entries,omitempty"`
		} `json:"threatEntryMetadata,omitempty"`
	} `json:"matches"`
}

type Result struct {
	IsDangerous bool     `json:"is_dangerous"`
	Threats     []string `json:"threats,omitempty"`
	RawResponse string   `json:"raw_response,omitempty"`
	CheckedURL  string   `json:"checked_url"`
	Status      string   `json:"status"`
}

type DetailedResult struct {
	Result    *Result   `json:"result"`
	Formatted string    `json:"formatted"`
	CheckedAt time.Time `json:"checked_at"`
}

func New(apiKey string) *Client {
	return &Client{
		apiKey: apiKey,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *Client) CheckDomain(domain string) (*Result, error) {
	urlToCheck := formatURL(domain)
	responseBody, err := c.makeRequest(urlToCheck)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return c.parseResponse(urlToCheck, responseBody)
}

func (c *Client) Check(domain string) (bool, []string, error) {
	result, err := c.CheckDomain(domain)
	if err != nil {
		return false, nil, err
	}
	return result.IsDangerous, result.Threats, nil
}

func (c *Client) makeRequest(url string) ([]byte, error) {
	request := map[string]interface{}{
		"client": map[string]interface{}{
			"clientId":       "domain-monitor",
			"clientVersioin": "1.0",
		},
		"threatInfo": map[string]interface{}{
			"threatTypes": []string{
				"MALWARE",
				"SOCIAL_ENGINEERING",
				"UNWANTED_SOFTWARE",
				"POTENTIALLY_HARMFULL_APPLICATION",
			},
			"platformTypes":    []string{"ANY_PLATFORM"},
			"threatEntryTypes": []string{"URL"},
			"threatEntries": []map[string]string{
				{"url": url},
			},
		},
	}

	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	apiURL := fmt.Sprintf("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=%s", c.apiKey)
	resp, err := c.client.Post(apiURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return body, fmt.Errorf("API error %d", resp.StatusCode)
	}

	return body, nil
}

func (c *Client) parseResponse(checkedURL string, responseBody []byte) (*Result, error) {
	result := &Result{
		CheckedURL:  checkedURL,
		RawResponse: string(responseBody),
	}

	if len(responseBody) == 0 || string(responseBody) == "{}" {
		result.Status = "SAFE"
		result.IsDangerous = false
		return result, nil
	}

	var apiResponse GSBResponse
	if err := json.Unmarshal(responseBody, &apiResponse); err != nil {
		result.Status = "PARSE_ERROR"
		return result, fmt.Errorf("parse JSON: %w", err)
	}

	if len(apiResponse.Matches) > 0 {
		result.IsDangerous = true
		result.Status = "DANGEROUS"

		threats := make([]string, 0, len(apiResponse.Matches))
		for _, match := range apiResponse.Matches {
			threats = append(threats, match.ThreatType)
		}
		result.Threats = threats
	} else {
		result.IsDangerous = false
		result.Status = "SAFE"
	}

	return result, nil
}

func formatURL(domain string) string {
	if len(domain) > 7 && (domain[:7] == "http://" || domain[:8] == "https://") {
		return domain
	}

	return "http://" + domain + "/"
}

func (c *Client) GetRawResponse(domain string) (string, error) {
	urlToCheck := formatURL(domain)
	responseBody, err := c.makeRequest(urlToCheck)
	if err != nil {
		return "", err
	}

	return string(responseBody), nil
}

func (c *Client) GetDetailedResult(domain string) (*DetailedResult, error) {
	result, err := c.CheckDomain(domain)
	if err != nil {
		return nil, err
	}

	detailed := &DetailedResult{
		Result:    result,
		Formatted: c.FormatResult(result),
		CheckedAt: time.Now(),
	}

	return detailed, nil
}

func (c *Client) FormatResult(result *Result) string {
	var response strings.Builder

	response.WriteString(fmt.Sprintf("checking: %s\n", result.CheckedURL))
	response.WriteString(fmt.Sprintf("status: %s\n", result.Status))

	if result.IsDangerous {
		response.WriteString("found menaces: \n")
		for i, threat := range result.Threats {
			response.WriteString(fmt.Sprintf("%d. %s\n", i+1, threat))
		}
	} else {
		response.WriteString("thre is on menaces")
	}

	response.WriteString(fmt.Sprintf("\n Answer type: %s", c.GetResponseType(result.RawResponse)))

	return response.String()
}

func (c *Client) GetResponseType(rawResponse string) string {
	if rawResponse == "" {
		return "raw response"
	}
	if rawResponse == "{}" {
		return "empy json object"
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(rawResponse), &data); err != nil {
		return "unvaild JSON"
	}

	if matches, ok := data["matches"]; ok {
		if matchesSlice, ok := matches.([]interface{}); ok && len(matchesSlice) > 0 {
			return fmt.Sprintf("%d menaces found", len(matchesSlice))
		}
	}
	return "SAFE (no matches field)"
}

func (c *Client) GetFormattedReport(domain string) (string, error) {
	result, err := c.CheckDomain(domain)
	if err != nil {
		return "", err
	}

	return c.FormatResult(result), nil
}

func (c *Client) CheckAndFormat(domain string) (string, error) {
	return c.GetFormattedReport(domain)
}
