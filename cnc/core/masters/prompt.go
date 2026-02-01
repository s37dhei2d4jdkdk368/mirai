package masters

import (
	"cnc/core/utils"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

var commands []string

func init() {
	loadCommands()
}

func loadCommands() {
	data, err := os.ReadFile("assets/commands.json")
	if err != nil {
		fmt.Println("Error loading commands.json:", err)
		return
	}
	if err := json.Unmarshal(data, &commands); err != nil {
		fmt.Println("Error parsing commands.json:", err)
	}
}

func (a *Admin) findSuggestion(current string) string {
	if current == "" {
		return ""
	}
	for _, cmd := range commands {
		
		if a.Session != nil && !a.Session.Account.Admin {
			isAdminCmd := false
			adminPrefixes := []string{"bots", "users", "ongoing", "broadcast", "sessions", "clogs", "fake", "add", "attacks"}
			for _, prefix := range adminPrefixes {
				if strings.HasPrefix(cmd, prefix) {
					isAdminCmd = true
					break
				}
			}
			if isAdminCmd {
				continue
			}
		}
		if strings.HasPrefix(cmd, current) {
			return cmd[len(current):]
		}
	}
	return ""
}

func (a *Admin) ReadLine(prompt string, masked bool) (string, error) {
	line := make([]byte, 0, 2048)
	a.CursorPos = 0
	a.HistoryIndex = len(a.CommandHistory)

	
	if prompt != "" {
		a.Printf(prompt)
	}

	for {
		buf := make([]byte, 32)
		n, err := a.conn.Read(buf)
		if err != nil || n == 0 {
			return "", err
		}

		for i := 0; i < n; i++ {
			b := buf[i]

			if b == 0x1B { 
				if i+2 < n && buf[i+1] == '[' {
					handled := true
					switch buf[i+2] {
					case 'A': 
						if a.HistoryIndex > 0 {
							a.HistoryIndex--
							line = []byte(a.CommandHistory[a.HistoryIndex])
							a.CursorPos = len(line)
							a.Printf("\r\x1b[K%s%s", prompt, string(line))
							suggestion := a.findSuggestion(string(line))
							if suggestion != "" {
								a.Printf("\x1b[90m%s\x1b[0m", suggestion)
							}
							a.Printf("\x1b[%dG", utils.AnsiStringLength(prompt)+a.CursorPos+1)
						}
					case 'B': 
						if a.HistoryIndex < len(a.CommandHistory) {
							a.HistoryIndex++
							if a.HistoryIndex == len(a.CommandHistory) {
								line = []byte("")
							} else {
								line = []byte(a.CommandHistory[a.HistoryIndex])
							}
							a.CursorPos = len(line)
							a.Printf("\r\x1b[K%s%s", prompt, string(line))
							suggestion := a.findSuggestion(string(line))
							if suggestion != "" {
								a.Printf("\x1b[90m%s\x1b[0m", suggestion)
							}
							a.Printf("\x1b[%dG", utils.AnsiStringLength(prompt)+a.CursorPos+1)
						}
					case 'C': 
						if a.CursorPos < len(line) {
							a.Printf("\x1b[C")
							a.CursorPos++
						}
					case 'D': 
						if a.CursorPos > 0 {
							a.Printf("\x1b[D")
							a.CursorPos--
						}
					default:
						handled = false
					}
					if handled {
						i += 2
						continue
					}
				}
			}

			switch b {
			case 0x03: 
				a.Printf("^C\r\n")
				return "", nil
			case 0x0D, 0x0A: 
				res := string(line)
				if !masked && len(res) > 0 {
					if len(a.CommandHistory) == 0 || a.CommandHistory[len(a.CommandHistory)-1] != res {
						a.CommandHistory = append(a.CommandHistory, res)
					}
				}
				a.Printf("\r\n")
				return res, nil
			case 0x7F, 0x08: 
				if a.CursorPos > 0 {
					line = append(line[:a.CursorPos-1], line[a.CursorPos:]...)
					a.CursorPos--

					
					a.Printf("\r\x1b[K%s%s", prompt, string(line))
					if !masked && a.CursorPos == len(line) {
						suggestion := a.findSuggestion(string(line))
						if suggestion != "" {
							a.Printf("\x1b[90m%s\x1b[0m", suggestion)
						}
					}
					
					a.Printf("\x1b[%dG", utils.AnsiStringLength(prompt)+a.CursorPos+1)
				}
			case 0x09: 
				if !masked && a.CursorPos == len(line) {
					current := string(line)
					suggestion := a.findSuggestion(current)
					if suggestion != "" {
						line = append(line, []byte(suggestion)...)
						a.Printf(suggestion)
						a.CursorPos += len(suggestion)
					}
				}
			default:
				if b >= 32 && b <= 126 {
					if masked {
						line = append(line, b)
						a.Printf("*")
						a.CursorPos++
					} else {
						
						newLine := make([]byte, len(line)+1)
						copy(newLine, line[:a.CursorPos])
						newLine[a.CursorPos] = b
						copy(newLine[a.CursorPos+1:], line[a.CursorPos:])
						line = newLine
						a.CursorPos++

						
						a.Printf("\r\x1b[K%s%s", prompt, string(line))

						
						if a.CursorPos == len(line) {
							suggestion := a.findSuggestion(string(line))
							if suggestion != "" {
								a.Printf("\x1b[90m%s\x1b[0m", suggestion)
							}
						}

						
						a.Printf("\x1b[%dG", utils.AnsiStringLength(prompt)+a.CursorPos+1)
					}
				}
			}
		}
	}
}
