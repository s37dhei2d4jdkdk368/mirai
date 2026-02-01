package endpoints

import (
	"cnc/core/database"
	"cnc/core/utils"
	"encoding/json"
	"io/ioutil"
	"time"

	"github.com/gin-gonic/gin"
)

type Preset struct {
	Preset         string `json:"preset"`
	Description    string `json:"description"`
	MaxBots        int    `json:"maxBots"`
	Duration       int    `json:"duration"`
	Cooldown       int    `json:"cooldown"`
	UserMaxAttacks int    `json:"userMaxAttacks"`
	Expiry         string `json:"expiry"`
	IsAdmin        bool   `json:"isAdmin"`
	IsReseller     bool   `json:"isReseller"`
	IsVip          bool   `json:"isVip"`
}

func Adduser(c *gin.Context) {
	username := c.Query("username")
	password := c.Query("password")

	gin.SetMode(gin.ReleaseMode)

	loggedIn, userInfo, err := database.DatabaseConnection.TryLogin(username, password, c.ClientIP())
	if err != nil || !loggedIn {
		response := `{
    "success": false,
    "error": "Authentication failed"
}`
		c.Data(401, "application/json; charset=utf-8", []byte(response))
		return
	}

	if !userInfo.Admin {
		response := `{
    "success": false,
    "error": "You are not allowed to create users"
}`
		c.Data(401, "application/json; charset=utf-8", []byte(response))
		return
	}

	NewUser := c.Query("newuser")
	NewPass := c.Query("newpass")
	presetName := c.Query("preset")

	if NewUser == "" || NewPass == "" || presetName == "" {
		response := `{
    "success": false,
    "error": "Please provide a username, password, and preset to add the user. (newuser= newpass= preset=)"
}`
		c.Data(500, "application/json; charset=utf-8", []byte(response))
		return
	}

	presets, err := loadPresetsFromFile("assets/presets.json")
	if err != nil {
		response := `{
			"success": false,
			"error": "Error loading presets: ` + err.Error() + `"
		}`
		c.Data(500, "application/json; charset=utf-8", []byte(response))
		return
	}

	selectedPreset, presetExists := presets[presetName]
	if !presetExists {
		response := `{
			"success": false,
			"error": "The specified preset does not exist"
		}`
		c.Data(400, "application/json; charset=utf-8", []byte(response))
		return
	}

	expiryDuration, err := utils.ParseDuration(selectedPreset.Expiry)
	if err != nil {
		response := `{
    "success": false,
    "error": "` + err.Error() + `"
}`
		c.Data(500, "application/json; charset=utf-8", []byte(response))
		return
	}

	expiry := time.Now().Add(expiryDuration).Unix()

	if database.DatabaseConnection.CreateUser(NewUser,
		NewPass,
		"api",
		selectedPreset.MaxBots,
		selectedPreset.UserMaxAttacks,
		selectedPreset.Duration,
		selectedPreset.Cooldown,
		selectedPreset.IsAdmin,
		selectedPreset.IsReseller,
		selectedPreset.IsVip,
		expiry) {
		response := `{
    "success": true,
    "message": "user created successfully"
}`
		c.Data(200, "application/json; charset=utf-8", []byte(response))
		return
	} else {
		response := `{
    "success": false,
    "error": "unknown error, try again later..."
}`
		c.Data(500, "application/json; charset=utf-8", []byte(response))
		return
	}
}

func loadPresetsFromFile(filename string) (map[string]Preset, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var presets []Preset
	err = json.Unmarshal(data, &presets)
	if err != nil {
		return nil, err
	}

	presetMap := make(map[string]Preset)
	for _, preset := range presets {
		presetMap[preset.Preset] = preset
	}

	return presetMap, nil
}
