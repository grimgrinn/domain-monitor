package storage

import (
	"database/sql"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func InitDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", "./monitor.db")
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS watched_domains (
			id INTEGER PRIMARY KEY,
			domain TEXT UNIQUE,
			added_at DATETIME,
			last_status TEXT DEFAULT 'unknown'
		);

		CREATE TABLE IF NOT EXISTS checks (
			id INTEGER PRIMARY KEY,
			domain TEXT,
			malicious INTEGER,
			checkec_at DATETIME
		);
	`)

	return db, err
}
func AddDomain(db *sql.DB, domain string) error {
	_, err := db.Exec(
		"INSERT OR IGNORE INTO watched_domains (domain, added_at) VALUES (?, ?)",
		domain, time.Now(),
	)
	return err
}

func GetWatchedDomains(db *sql.DB) ([]string, error) {
	rows, err := db.Query("SELECT domain FROM watched_domains")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var domain string
		rows.Scan(&domain)
		domains = append(domains, domain)
	}

	return domains, nil
}
