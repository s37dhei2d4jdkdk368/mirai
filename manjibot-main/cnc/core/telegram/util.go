package telegram

import "strconv"

func isAdmin(userID int, admins []string) bool { 
	uidStr := strconv.Itoa(userID)

	for _, admin := range admins {
		if admin == uidStr {
			return true
		}
	}

	return false
}
