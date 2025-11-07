package api

import (
	"domain-monitor/internal/models"
	"time"
)

func CheckDomain(domain string) (*models.Report, error) {
	return &models.Report{
		Domain:    domain,
		Safe:      true,
		RiskScore: 0,
		Timestamp: time.Now(),
	}, nil
}
