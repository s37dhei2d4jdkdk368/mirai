package masters

import (
	"cnc/core/masters/sessions"
	"net"
)

type Admin struct {
	conn                        net.Conn
	Session                     *sessions.Session
	Theme                       string
	PrimaryColor                string
	SecondaryColor              string
	PreviousDistribution        map[string]int
	PreviousDistributionCores   map[string]int
	PreviousDistributionCountry map[string]int
	PreviousDistributionArch    map[string]int
	PreviousDistributionISP     map[string]int
	MaxDistribution             map[string]int
	MaxDistributionCores        map[string]int
	MaxDistributionCountry      map[string]int
	MaxDistributionArch         map[string]int
	MaxDistributionISP          map[string]int
	PreviousTotalBots           int
	MaxTotalBots                int
	IsSSH                       bool
	Username                    string
	CommandHistory              []string
	HistoryIndex                int
	CursorPos                   int
}

func NewAdmin(conn net.Conn) *Admin {
	return &Admin{
		conn:                        conn,
		Session:                     nil,
		PreviousDistribution:        make(map[string]int),
		PreviousDistributionCores:   make(map[string]int),
		PreviousDistributionCountry: make(map[string]int),
		PreviousDistributionArch:    make(map[string]int),
		PreviousDistributionISP:     make(map[string]int),
		MaxDistribution:             make(map[string]int),
		MaxDistributionCores:        make(map[string]int),
		MaxDistributionCountry:      make(map[string]int),
		MaxDistributionArch:         make(map[string]int),
		MaxDistributionISP:          make(map[string]int),
	}
}
