package masters

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func HexToAnsi(hexCode string) string {
	hexCode = strings.TrimPrefix(hexCode, "#")
	if len(hexCode) != 6 {
		return ""
	}
	r, _ := strconv.ParseInt(hexCode[0:2], 16, 64)
	g, _ := strconv.ParseInt(hexCode[2:4], 16, 64)
	b, _ := strconv.ParseInt(hexCode[4:6], 16, 64)
	return fmt.Sprintf("\x1b[38;2;%d;%d;%dm", r, g, b)
}

type ThemeConfig struct {
	Primary   string `json:"primary"`
	Secondary string `json:"secondary"`
}

func LoadThemeConfig(theme string) (string, string) {
	defaultPrimary := "#B00000"
	defaultSecondary := "#ECEF9A"

	if theme == "" {
		theme = "kairo"
	}

	themePath := "assets/branding/" + theme + "/theme.json"
	data, err := os.ReadFile(themePath)
	if err != nil {
		return defaultPrimary, defaultSecondary
	}

	var config ThemeConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return defaultPrimary, defaultSecondary
	}

	if config.Primary == "" {
		config.Primary = defaultPrimary
	}
	if config.Secondary == "" {
		config.Secondary = defaultSecondary
	}

	return config.Primary, config.Secondary
}
