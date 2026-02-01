package database

import (
    "cnc/core/utils"
    "database/sql"
    "fmt"
    "log"
    "math/rand"
    "time"

    "golang.org/x/crypto/bcrypt"
)

func createTables(db *sql.DB) {

    _, err := db.Exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            max_bots INTEGER NOT NULL DEFAULT -1,
            admin INTEGER NOT NULL DEFAULT 0,
            reseller INTEGER NOT NULL DEFAULT 0,
            superuser INTEGER NOT NULL DEFAULT 0,
            vip INTEGER NOT NULL DEFAULT 0,
            maxAttacks INTEGER NOT NULL DEFAULT 100,
            totalAttacks INTEGER NOT NULL DEFAULT 0,
            expiry INTEGER NOT NULL,
            maxTime INTEGER NOT NULL DEFAULT 60,
            cooldown INTEGER NOT NULL DEFAULT 100,
            parent TEXT NOT NULL
        );
    `)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("")

    _, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            time_sent INTEGER NOT NULL,
            duration INTEGER NOT NULL,
            command TEXT NOT NULL,
            max_bots INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    `)
    if err != nil {
        log.Fatal(err)
    }

    var count int
    err = db.QueryRow("SELECT COUNT(*) FROM users WHERE username = 'admin'").Scan(&count)
    if err != nil {
        log.Fatal(err)
    }

    if count == 0 {
        // Generate a more secure password
        defaultPassword := generateRandomString(16)
        hashedPassword, err := bcrypt.GenerateFromPassword([]byte(defaultPassword), bcrypt.DefaultCost)
        if err != nil {
            log.Fatal(err)
        }

        expiry := time.Now().Add(999 * 24 * time.Hour).Unix()

        _, err = db.Exec(`
            INSERT INTO users (username, password, max_bots, admin, reseller, superuser, vip, maxAttacks, totalAttacks, expiry, maxTime, cooldown, parent)
            VALUES (?, ?, -1, 1, 1, 1, 1, 9999, 0, ?, 60, 10, 'sql')
        `, "admin", hashedPassword, expiry)
        if err != nil {
            log.Fatal(err)
        }

        utils.Successf("Created default admin user with credentials:")
        utils.Successf("Username: admin")
        utils.Successf("Password: %s", defaultPassword)
        utils.Successf("Please change this password after first login!")
    }
}

func createEvent(db *sql.DB) {

}

func generateRandomString(length int) string {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    result := make([]byte, length)
    for i := 0; i < length; i++ {
        result[i] = charset[rand.Intn(len(charset))]
    }
    return string(result)
}
