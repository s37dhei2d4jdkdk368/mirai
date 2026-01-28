package database

import "strings"

func parseCommand(command string) (method, target, dport, length string) {
	parts := strings.Split(command, " ")

	if len(parts) < 3 {
		return "N/A", "N/A", "N/A", "N/A"
	}

	method = parts[0]
	target = parts[1]

	
	if len(parts) >= 5 && (strings.HasPrefix(method, "!")) {
		dport = parts[2]
		length = parts[4]
	}

	for _, part := range parts[2:] {
		if strings.HasPrefix(part, "dport=") {
			dport = strings.TrimPrefix(part, "dport=")
		}
		if strings.HasPrefix(part, "len=") {
			length = strings.TrimPrefix(part, "len=")
			length = strings.TrimPrefix(length, "size=")
		}
	}

	if dport == "" {
		dport = "65535 (not specified)"
	}
	if length == "" {
		length = "512 (not specified)"
	}

	return method, target, dport, length
}
