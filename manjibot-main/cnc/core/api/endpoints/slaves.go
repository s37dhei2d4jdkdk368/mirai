package endpoints

import (
	"cnc/core/database"
	"cnc/core/slaves"
	"sort"

	"github.com/gin-gonic/gin"
)

var cat map[string]int

func Slaves(c *gin.Context) {
	username := c.Query("username")
	password := c.Query("password")

	gin.SetMode(gin.ReleaseMode)
	loggedIn, userInfo, err := database.DatabaseConnection.TryLogin(username, password, c.ClientIP())
	if err != nil || !loggedIn {
		c.JSON(401, gin.H{"message": "Authentication failed"})
		return
	}

	
	
	
	

	if userInfo.Username != "amplified" {
		c.JSON(401, gin.H{"message": "You are not tuff enough"})
		return
	}

	m := slaves.CL.Distribution()

	changes := make(map[string]int)
	for key, value := range m {
		change := value - cat[key]
		changes[key] = change
	}

	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return len(keys[i]) < len(keys[j])
	})

	sortedMap := make(map[string]map[string]interface{})
	for _, key := range keys {
		entry := map[string]interface{}{
			"value":  m[key],
			"change": changes[key],
		}
		sortedMap[key] = entry
	}

	cat = m
	c.JSON(200, sortedMap)
}
