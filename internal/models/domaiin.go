package models

import "time"

type Report struct {
	Domain    string    `json:"domain"`
	Safe      bool      `json:"safe"`
	RiskScore int       `json:"risk_store"`
	Timestamp time.Time `json:"timestamp"`
}
