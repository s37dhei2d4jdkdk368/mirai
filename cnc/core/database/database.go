package database

import (
	"cnc/core/utils"
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

type Database struct {
	db *sql.DB
}

var DatabaseConnection *Database

func NewDatabase(dbURL string) error {
	dsn := "file:assets/cnc.db?_busy_timeout=5000&_journal_mode=WAL&_cache=shared"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		utils.Errorf("Failed to open database: %v", err)
		return err
	}

	db.SetMaxOpenConns(10)

	createTables(db)
	createEvent(db)

	DatabaseConnection = &Database{db}
	return nil
}

func (db *Database) UpdateUser(username string, field string, value interface{}) error {
	query := fmt.Sprintf("UPDATE users SET `%s` = ? WHERE username = ?", field)
	_, err := db.db.Exec(query, value, username)
	return err
}
