package keitaro

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type Client struct {
	ApiKey  string
	BaseURL string
}

type Domain struct {
	ID   int    `json: "id"`
	Name string `json:"name"`
}

func New(apiKey, baseURL string) *Client {
	return &Client{
		ApiKey:  apiKey,
		BaseURL: baseURL,
	}
}

func (c *Client) GetDomains() ([]Domain, error) {
	url := c.BaseURL + "/domains"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Api-Key", c.ApiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var domains []Domain
	if err := json.Unmarshal(body, &domains); err != nil {
		return nil, err
	}

	return domains, nil
}
