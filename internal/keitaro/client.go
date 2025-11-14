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
	ID      int    `json: "id"`
	Name    string `json:"name"`
	Group   string `json:"group"`
	State   string `json:"state"`
	GroupID int    `json:"group_id"`
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

func (c *Client) GetActiveDomains() ([]Domain, error) {
	domains, err := c.GetDomains()
	if err != nil {
		return nil, err
	}

	var active []Domain
	for _, domain := range domains {
		if domain.State == "active" {
			active = append(active, domain)
		}
	}

	return active, nil
}

func (c *Client) GetDomainsByGroup(groupName string) ([]Domain, error) {
	domains, err := c.GetDomains()
	if err != nil {
		return nil, err
	}

	var filtered []Domain
	for _, domain := range domains {
		if domain.Group == groupName {
			filtered = append(filtered, domain)
		}
	}

	return filtered, nil
}

func (c *Client) GetDomainsLimit(limit int) ([]Domain, error) {
	domains, err := c.GetDomains()
	if err != nil {
		return nil, err
	}

	if limit > len(domains) {
		limit = len(domains)
	}

	return domains[:limit], nil
}
