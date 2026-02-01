package masters

import (
	"cnc/core/masters/sessions"
	"fmt"
	"sync"
	"time"
)

type TimeoutInfo struct {
	Timeout  time.Time
	Duration int
	KickUser bool
}

var (
	timeoutMutex sync.Mutex
	timeouts     = make(map[string]TimeoutInfo)
)

func UserTimeout(username string, duration int) (string, bool) {
	timeoutMutex.Lock()
	defer timeoutMutex.Unlock()

	if _, exists := timeouts[username]; exists {
		return "User is already timed out.", false
	}

	expirationTime := time.Now().Add(time.Duration(duration) * time.Minute)

	timeouts[username] = TimeoutInfo{
		Timeout:  expirationTime,
		Duration: duration,
		KickUser: true,
	}

	if timeouts[username].KickUser {
		msg, success := KickUser(username)
		if !success {
			return msg, false
		}
	}

	return fmt.Sprintf("User %s has been timed out for %d minutes.", username, duration), true
}

func UserUntimeout(username string) (string, bool) {
	timeoutMutex.Lock()
	defer timeoutMutex.Unlock()

	if timeoutInfo, exists := timeouts[username]; exists {
		delete(timeouts, username)

		if timeoutInfo.KickUser {
		}

		return fmt.Sprintf("User %s has been untimed out.", username), true
	}

	return "User is not currently timed out.", false
}

func KickUser(username string) (msg string, success bool) {
	sessions.SessionMutex.Lock()
	defer sessions.SessionMutex.Unlock()

	for id, session := range sessions.Sessions {
		if session.Username == username {
			err := session.Conn.Close()
			if err != nil {
				return fmt.Sprintf("Could not kick user: %v", err), false
			}
			delete(sessions.Sessions, id)
			return fmt.Sprintf("User %s disconnected successfully", username), true
		}
	}
	return fmt.Sprintf("User %s not found in any session", username), false
}

func isTimedOut(username string) bool {
	timeoutMutex.Lock()
	defer timeoutMutex.Unlock()

	if timeoutInfo, exists := timeouts[username]; exists {
		remainingDuration := timeoutInfo.Timeout.Sub(time.Now()) 
		if remainingDuration > 0 {
			return true
		}
		delete(timeouts, username) 
	}
	return false
}
