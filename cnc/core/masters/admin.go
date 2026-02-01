package masters

import (
    "cnc/core/masters/sessions"
    "fmt"
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
    Username                    string
    CommandHistory              []string
    HistoryIndex                int
    CursorPos                   int
    // SSH-specific fields
    isSSH      bool
    sshSession *SSHSession
}

func NewAdmin(conn net.Conn) *Admin {
    return &Admin{
        conn:                        conn,
        Session:                     nil,
        isSSH:                       false,
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

func NewSSHAdmin(sshSession *SSHSession) *Admin {
    return &Admin{
        conn:        sshSession,
        Session:     nil,
        isSSH:       true,
        sshSession:  sshSession,
        Username:    sshSession.Username,
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

// Printf writes formatted output to the connection
func (a *Admin) Printf(format string, args ...interface{}) {
    if a.isSSH && a.sshSession != nil {
        msg := fmt.Sprintf(format, args...)
        a.sshSession.Write([]byte(msg))
    } else if a.conn != nil {
        msg := fmt.Sprintf(format, args...)
        a.conn.Write([]byte(msg))
    }
}

// Println writes a line to the connection
func (a *Admin) Println(args ...interface{}) {
    if a.isSSH && a.sshSession != nil {
        msg := fmt.Sprintln(args...)
        a.sshSession.Write([]byte(msg))
    } else if a.conn != nil {
        msg := fmt.Sprintln(args...)
        a.conn.Write([]byte(msg))
    }
}

func (a *Admin) Clear() {
    if a.isSSH && a.sshSession != nil {
        // Send clear screen sequence for SSH
        a.Printf("\033[2J\033[H")
    } else if a.conn != nil {
        // Send clear screen sequence
        a.Printf("\x1B[2J\x1B[H")
    }
}
