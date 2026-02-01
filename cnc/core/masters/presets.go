package masters

import (
	"encoding/json"
	"io/ioutil"
)

type PresetInfo struct {
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

var Presets []PresetInfo

func parsePresetsJSON(filename string) error {
	presetData, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(presetData, &Presets); err != nil {
		return err
	}

	return nil
}
