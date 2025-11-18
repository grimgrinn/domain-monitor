package models

import "time"

type Report struct {
	Domain    string    `json:"domain"`
	Safe      bool      `json:"safe"`
	RiskScore int       `json:"risk_store"`
	Timestamp time.Time `json:"timestamp"`
}

type RawReport struct {
	Domain    string    `json:"domain:`
	RawData   string    `json:"raw_data:`
	Timestamp time.Time `json:"timestamp"`
}
