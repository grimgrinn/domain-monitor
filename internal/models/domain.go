package models

import "time"

type Report struct {
	Domain    string    `json:"domain"`
	Safe      bool      `json:"safe"`
	RiskScore int       `json:"risk_score"`
	Timestamp time.Time `json:"timestamp"`
}

type RawReport struct {
	Domain    string    `json:"domain"`
	RawData   string    `json:"raw_data"`
	Timestamp time.Time `json:"timestamp"`
}

type VTDetailReport struct {
	Domain    string    `json:"domain"`
	Timestamp time.Time `json:"timestamp"`

	Stats struct {
		Harmless   int `json:"harmless"`
		Suspicious int `json:"suspicious"`
		Malicious  int `json:"malicious"`
		Undetected int `json:"undetected"`
		Total      int `json:"total"`
	} `json:"stats"`

	Results struct {
		Malicious  []string `json:"malicious"`
		Suspicious []string `json:"suspicious"`
		Harmless   []string `json:"harmless"`
		Undetected []string `json:"undetected"`
	} `json:"results"`

	Reputation   int               `json:"reputation"`
	Categories   map[string]string `json:"categories"`
	LastAnalysis int64             `json:"last_analysis"`
}
