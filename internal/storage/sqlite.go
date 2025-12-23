package storage

import (
	"database/sql"
	"domain-monitor/internal/keitaro"
	"log"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

type Storage struct {
	db *sql.DB
}

func NewStorage(dbPath string) (*Storage, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS watched_domains (
            domain TEXT PRIMARY KEY,
            added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_status TEXT DEFAULT 'unknown',
			source TEXT DEFAULT 'user',
			is_keitaro BOOLEAN DEFAULT 0
        );
        
        CREATE TABLE IF NOT EXISTS domain_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT,
            malicious INTEGER DEFAULT 0,
            suspicious INTEGER DEFAULT 0,
            checked_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

		CREATE TABLE IF NOT EXISTS user_groups (
			telegram_username TEXT PRIMARY KEY,
			keitaro_groups TEXT, 
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
    `)

	if err != nil {
		return nil, err
	}

	storage := &Storage{db: db}

	//mirgration due to no erase existing data
	if err := storage.migrateAddKeitarGroupColumn(); err != nil {

		log.Printf("Miragration warning: %v", err)
	}

	return storage, nil
}

func (s *Storage) migrateAddKeitarGroupColumn() error {
	var columnExists bool
	err := s.db.QueryRow(`
		SELECT COUNT(*) > 0
		FROM pragma_table_info('watched_domains')
		WHERE name = 'keitaro_group'
	`).Scan(&columnExists)

	if err != nil {
		log.Printf("Warning chekcing column: %v", err)
		return err
	}

	if !columnExists {
		log.Println("Adding keitaro_group column to watched_domains...")
		_, err := s.db.Exec(`
			ALTER TABLE watched_domains
			ADD COLUMN keitaro_group TEXT DEFAULT ''
		`)
		if err != nil {
			log.Printf("Error adding column: %v", err)
			return err
		}
		log.Println("keitaro_group column added")
	} else {
		log.Println("keitaro_group column already exists")
	}

	return nil
}

func (s *Storage) GetKeitaroDomains() ([]string, error) {
	rows, err := s.db.Query(
		"SELECT domain FROM watched_domains WHERE source = 'keitaro' ORDER BY added_at",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, err
		}
		domains = append(domains, domain)
	}

	return domains, nil
}

func (s *Storage) LoadKeitaroDomains(keitaroClient *keitaro.Client) error {
	_, err := s.db.Exec("DELETE FROM watched_domains WHERE source = 'keitaro'")
	if err != nil {
		return err
	}
	domains, err := keitaroClient.GetActiveDomains()
	if err != nil {
		return err
	}

	if len(domains) > 250 {
		domains = domains[:250]
	}

	for _, d := range domains {
		_, err := s.db.Exec(`
			INSERT INTO watched_domains (domain, source, is_keitaro, keitaro_group)
			VALUES (?, 'keitaro', 1, ?)
			`, d.Name, d.Group)
		if err != nil {
			log.Printf("error saving domain %s: %v", d.Name, err)
		}
	}

	log.Printf("Loaded %d domains from Keitaro", len(domains))
	return nil
}

func (s *Storage) AddDomain(domain string) error {
	_, err := s.db.Exec(
		"INSERT OR IGNORE INTO watched_domains (domain) VALUES (?)",
		domain,
	)
	return err
}

func (s *Storage) RemoveDomain(domain string) error {
	_, err := s.db.Exec("DELETE FROM watched_domains WHERE domain = ?", domain)
	return err
}

func (s *Storage) GetWatchedDomains() ([]string, error) {
	rows, err := s.db.Query("SELECT domain FROM watched_domains ORDER BY added_at")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, err
		}
		domains = append(domains, domain)
	}

	return domains, nil
}

func (s *Storage) SaveCheckResult(domain string, malicious, suspicious int) error {
	_, err := s.db.Exec(
		"INSERT INTO domain_checks (domain, malicious, suspicious) VALUES (?, ?, ?)",
		domain, malicious, suspicious,
	)
	return err
}

func (s *Storage) GetLastCheck(domain string) (malicious, suspicious int, err error) {
	err = s.db.QueryRow(`
		SELECT malicious, suspicious
		FROM domain_checks
		WHERE domain = ?
		ORDER BY checked_at DESC
		LIMIT 1
	`, domain).Scan(&malicious, &suspicious)

	if err == sql.ErrNoRows {
		return 0, 0, nil
	}

	return malicious, suspicious, err
}

func (s *Storage) Close() error {
	return s.db.Close()
}

func (s *Storage) SaveUserGroup(username, groups string) error {
	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO user_groups
		(telegram_username, keitaro_groups, updated_at)
		VALUES (?, ?, CURRENT_TIMESTAMP)
	`, username, groups)
	return err
}

func (s *Storage) GetUserGroups(username string) ([]string, error) {
	var groupsStr string
	err := s.db.QueryRow(
		"SELECT keitaro_groups FROM user_groups WHERE telegram_username = ?",
		username,
	).Scan(&groupsStr)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var groups []string
	for _, g := range strings.Split(groupsStr, ",") {
		groups = append(groups, strings.TrimSpace(g))
	}
	return groups, nil
}

func (s *Storage) GetAllUserMappings() (map[string][]string, error) {
	rows, err := s.db.Query(
		"SELECT telegram_username, keitaro_groups FROM user_groups",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	mappings := make(map[string][]string)
	for rows.Next() {
		var username, groupsStr string
		if err := rows.Scan(&username, &groupsStr); err != nil {
			return nil, err
		}

		var groups []string
		if groupsStr != "" {
			for _, g := range strings.Split(groupsStr, ",") {
				groups = append(groups, strings.TrimSpace(g))
			}
		}
		mappings[username] = groups
	}

	return mappings, nil
}
