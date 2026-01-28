# Security Audit Report: ManjiBot Botnet

**Date:** January 28, 2025  
**Auditor:** Security Research Team  
**Scope:** Full codebase analysis of ManjiBot (Mirai-style botnet)

---

## Executive Summary

This security audit examined the ManjiBot botnet codebase, a Mirai-style distributed denial-of-service (DDoS) toolkit. The analysis revealed numerous critical vulnerabilities across both the C2 (Command & Control) server and bot payload components.

**Overall Assessment:** The system contains multiple critical security vulnerabilities that could be exploited by researchers, competitors, or threat actors to gain unauthorized access, extract credentials, disrupt operations, or hijack the botnet.

---

## Directory Structure

```
manjibot-main/
├── bot/                    # C bot payload (cross-compiled for multiple architectures)
│   ├── main.c             # Bot entry point, C2 communication
│   ├── killer.c           # Process killer for competing malware
│   ├── locker.c           # Port locking and process defense
│   ├── chacha20.c         # ChaCha20 encryption implementation
│   ├── attack_*.c         # Various DDoS attack implementations
│   └── persistence.c      # Persistence mechanisms
├── cnc/                   # Go-based C2 server
│   ├── core/
│   │   ├── api/          # REST API endpoints
│   │   ├── database/     # SQLite database operations
│   │   ├── frontend/     # HTTP/FTP/TFTP file servers
│   │   ├── masters/      # Telnet/SSH admin console
│   │   ├── slaves/       # Bot connection handling
│   │   └── telegram/     # Telegram bot integration
│   └── assets/           # Configuration files, branding, keys
└── setup.sh              # Build and deployment script
```

---

## Critical Vulnerabilities

### 1. Hardcoded Credentials (CRITICAL)

**Location:** `cnc/core/database/generate.go:62`

```go
hashedPassword, err := bcrypt.GenerateFromPassword([]byte("8350e5a3e24c153df2275c9f80692773"), bcrypt.DefaultCost)
// Creates default user: admin with MD5 of admin
```

**Description:** The C2 creates a default admin account with a hardcoded password. The password "8350e5a3e24c153df2275c9f80692773" is the MD5 hash of "admin", making it trivial to authenticate.

**Impact:** Any attacker who discovers the C2 server can immediately gain administrative access to the botnet, control all bots, view user credentials, and launch attacks.

**Recommended Fix:** 
- Require password to be set via environment variable or configuration file
- Generate strong random password on first startup and display it only once
- Do not create default accounts

---

### 2. Hardcoded Admin Token (CRITICAL)

**Location:** `cnc/core/frontend/http/Serve.go:82` and `Serve2:148`

```go
adminToken := "CHANGE_THIS_SECRET_TOKEN_12345"
```

**Description:** Both HTTP and HTTP2 file servers use a hardcoded, placeholder admin token to bypass browser detection checks.

**Impact:** 
- Anyone aware of the placeholder token can download malware binaries
- Allows unrestricted access to the file distribution infrastructure
- Can be used to download and analyze bot payloads

**Recommended Fix:**
- Generate random token on startup
- Store in environment variable or secure configuration
- Rotate tokens periodically

---

### 3. SQL Injection Vulnerability (CRITICAL)

**Location:** `cnc/core/database/database.go:34-38`

```go
func (db *Database) UpdateUser(username string, field string, value interface{}) error {
    query := fmt.Sprintf("UPDATE users SET `%s` = ? WHERE username = ?", field)
    _, err := db.db.Exec(query, value, username)
    return err
}
```

**Description:** The UpdateUser function constructs SQL queries using string formatting with the `field` parameter. While backticks are used, this doesn't fully prevent injection.

**Impact:** An attacker could potentially modify database columns not intended to be updated, or manipulate the query structure to extract data or bypass authorization.

**Recommended Fix:**
```go
// Whitelist allowed fields
allowedFields := map[string]bool{
    "max_bots": true,
    "maxTime": true,
    "cooldown": true,
    // ... other allowed fields
}
if !allowedFields[field] {
    return errors.New("invalid field")
}
```

---

### 4. Weak Cryptographic Implementation (CRITICAL)

**Location:** `cnc/core/slaves/listen.go:26-31` and `bot/main.c:58-63`

```go
var encryptionKey = []byte{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
}
```

**Description:** The same static 32-byte encryption key is hardcoded in both the C2 server and all bot binaries. The key is a simple sequential pattern (0x00-0x1F), making it trivial to decrypt all bot-C2 communications.

**Impact:**
- Any interceptor can decrypt all bot-C2 communications
- Attackers can extract attack commands, control signals, and bot telemetry
- Allows man-in-the-middle attacks and bot hijacking

**Recommended Fix:**
- Generate unique random key during C2 compilation
- Implement key exchange mechanism during bot initialization
- Use asymmetric cryptography for initial key exchange
- Regular key rotation

---

### 5. ChaCha20 Nonce Reuse (HIGH)

**Location:** `cnc/core/slaves/listen.go:42-50`

```go
b.nonce = make([]byte, 12)
authMagic := []byte{0x4A, 0x8F, 0x2C, 0xD1}
copy(b.nonce[0:4], authMagic)
copy(b.nonce[4:8], authMagic)
copy(b.nonce[8:12], authMagic)
```

**Description:** The ChaCha20 nonce is initialized using a static 4-byte magic value repeated three times. Combined with the static key, this makes the encryption scheme predictable and vulnerable to cryptanalysis.

**Impact:** 
- Allows attackers to decrypt bot communications
- Known plaintext attacks are possible
- Violates cryptographic best practices (nonce must be unique per key)

**Recommended Fix:**
- Generate random nonces for each bot connection
- Include timestamp or connection identifier in nonce
- Ensure nonce uniqueness across all bot communications

---

### 6. No API Authentication (CRITICAL)

**Location:** `cnc/core/api/api.go:14-21`

```go
api := r.Group("/api")
api.GET("/attack", endpoints2.Attack)
api.GET("/slaves", endpoints2.Slaves)
api.GET("/adduser", endpoints2.Adduser)
```

**Description:** The REST API endpoints only validate username/password from query parameters but do not implement proper API key authentication or rate limiting.

**Impact:**
- Anyone can attempt to brute-force credentials
- No protection against credential stuffing attacks
- No way to detect or block automated attack attempts

**Recommended Fix:**
- Implement API key authentication via HTTP headers
- Add rate limiting per IP address
- Implement request throttling
- Add IP-based blocking for failed attempts

---

### 7. Hardcoded Username Check in Slaves Endpoint (HIGH)

**Location:** `cnc/core/api/endpoints/slaves.go:29-32`

```go
if userInfo.Username != "amplified" {
    c.JSON(401, gin.H{"message": "You are not tuff enough"})
    return
}
```

**Description:** The /api/slaves endpoint only works for the hardcoded username "amplified", creating a backdoor account.

**Impact:**
- Creates a permanent backdoor for a specific user
- Allows unlimited access to bot distribution statistics
- Bypasses normal authorization mechanisms

**Recommended Fix:**
- Remove hardcoded username check
- Implement proper role-based access control
- Check admin/superuser flags instead of specific username

---

### 8. FTP Server with No Authentication (HIGH)

**Location:** `cnc/core/frontend/ftp/Serve.go:17`

```go
Auth: &server2.NoAuth{},
```

**Description:** The FTP server is configured with NoAuth, allowing anyone to connect and download/upload files without authentication.

**Impact:**
- Unrestricted access to malware binaries
- Potential for attackers to upload malicious binaries
- Can be used to distribute additional payloads

**Recommended Fix:**
- Implement proper FTP authentication
- Use the existing user database for FTP access
- Restrict file operations by user role

---

### 9. Command Injection Vulnerability (HIGH)

**Location:** `cnc/core/api/endpoints/attack.go:64-69`

```go
var cmd string
if size == "" {
    cmd = fmt.Sprintf("%s %s %d dport=%d len=1", FloodStr, target, duration, port)
} else {
    cmd = fmt.Sprintf("%s %s %d dport=%d len=%s", FloodStr, target, duration, port, size)
}
```

**Description:** The attack command is constructed using fmt.Sprintf with user-controlled inputs. While the input is validated, the command parsing could be manipulated.

**Impact:** 
- Potential for command injection if validation fails
- Attackers might be able to inject additional commands
- Could be used to escalate privileges or execute arbitrary commands

**Recommended Fix:**
- Use strict parameter validation with allowlists
- Implement command whitelist instead of free-form strings
- Use parameterized command construction

---

### 10. Directory Traversal Vulnerabilities (HIGH)

**Location:** 
- `cnc/core/frontend/http/Serve.go:138`
- `cnc/core/frontend/ftp/filedriver/driver.go:38-41`
- `cnc/core/frontend/tftp/Serve.go:23`

**HTTP Server:**
```go
http.ServeFile(w, r, filepath.Join(staticDir, r.URL.Path))
```

**FTP Driver:**
```go
func (driver *FileDriver) realPath(path string) string {
    paths := strings.Split(path, "/")
    return filepath.Join(append([]string{driver.RootPath}, paths...)...)
}
```

**TFTP Server:**
```go
file, err := os.Open(filepath.Join(staticDir, filename))
```

**Description:** None of the file servers properly validate paths for directory traversal attacks like `../` sequences.

**Impact:**
- Attackers can read files outside the static directory
- Could access configuration files, database, or sensitive data
- Potential to read SSH keys or other secrets

**Recommended Fix:**
```go
// Validate path is within static directory
realPath := filepath.Join(staticDir, filepath.Clean(r.URL.Path))
if !strings.HasPrefix(realPath, staticDir) {
    http.Error(w, "Forbidden", http.StatusForbidden)
    return
}
```

---

### 11. Exposed SSH Private Key (CRITICAL)

**Location:** `cnc/assets/id_rsa`

**Description:** An RSA private key is committed to the repository in plaintext.

**Impact:**
- Anyone with repository access can use this key
- Allows unauthorized SSH access to the C2 server
- Can be used to impersonate the server

**Recommended Fix:**
- Remove private key from repository
- Generate new keys on deployment
- Use environment variables or secret management
- Add id_rsa to .gitignore

---

### 12. API Token Exposure in Config (MEDIUM)

**Location:** `cnc/assets/config.json:22`

```json
"ipInfoToken": "96c2f066646363"
```

**Description:** An ipinfo.io API token is hardcoded in the configuration file.

**Impact:**
- Token can be used by anyone with repository access
- May incur unexpected API usage costs
- Potential for token abuse or quota exhaustion

**Recommended Fix:**
- Store token in environment variable
- Rotate tokens regularly
- Use separate tokens for development/production

---

### 13. No Rate Limiting on C2 Endpoints (HIGH)

**Description:** The C2 endpoints (API, telnet, SSH) have no rate limiting or throttling mechanisms.

**Impact:**
- Vulnerable to brute-force password attacks
- Can be overwhelmed with connection attempts
- No protection against credential stuffing

**Recommended Fix:**
- Implement rate limiting per IP address
- Add exponential backoff for failed attempts
- Implement IP-based blocking after multiple failures
- Use connection pooling and timeouts

---

### 14. Buffer Overflow Vulnerabilities in C Bot (CRITICAL)

**Location:** `bot/main.c`, `bot/killer.c`, `bot/locker.c`

**Description:** The C bot code uses unsafe string operations and unbounded reads without proper bounds checking.

**Examples:**
```c
// Unsafe string operations in killer.c
char cmd[512];
sprintf(cmd, "kill -9 %d", pid);  // Potential overflow

// Unbounded socket reads in main.c
read(fd, buf, sizeof(buf));  // No length validation
```

**Impact:**
- Stack-based buffer overflows
- Memory corruption
- Potential for code execution
- Bot crashes or unexpected behavior

**Recommended Fix:**
- Use safe string functions (strncpy, snprintf)
- Implement proper bounds checking
- Validate input lengths before processing
- Use modern C alternatives where possible

---

### 15. Process Killer for Malicious Purposes (CRITICAL)

**Location:** `bot/killer.c:40-90`

**Description:** The bot includes a process killer that terminates competing malware, security tools, and even system processes.

**Whitelisted Processes:**
```c
const char *whitelist[] = {
    "init", "systemd", "watchdog", "httpd", "nginx", "apache",
    "busybox", "dropbear", "sshd",
    // System directories
    "/lib/", "/usr/lib/", "/usr/bin/", "/usr/sbin/",
    // ...
};
```

**Impact:**
- Disables competing botnets
- Terminates security monitoring tools
- Can disable system services
- Disrupts legitimate operations

**Recommended Fix:**
(N/A - This is intentional malicious behavior)

---

### 16. Port Locking Mechanism (HIGH)

**Location:** `bot/locker.c:46-60`

```c
#define MAX_LOCKED_PORTS 20
static int locked_ports[MAX_LOCKED_PORTS] = {-1, -1, ...};
static uint16_t ports_to_lock[MAX_LOCKED_PORTS];
```

**Description:** The bot includes functionality to lock TCP ports, preventing other processes from using them.

**Impact:**
- Prevents legitimate services from running
- Can be used to maintain persistence
- Disables network-based security tools

**Recommended Fix:**
(N/A - This is intentional malicious behavior)

---

### 17. Self-Defense Mechanisms (HIGH)

**Location:** `bot/main.c:149-163`

```c
void handle_signal(int signum) {
    is_defending = 1;
}

void defend_binary() {
    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);
    signal(SIGKILL, handle_signal);
    // ... more signals
}
```

**Description:** The bot installs signal handlers to prevent termination and resist removal.

**Impact:**
- Difficult to remove from infected systems
- Resists standard termination signals
- Maintains persistence

**Recommended Fix:**
(N/A - This is intentional malicious behavior)

---

### 18. Information Disclosure (MEDIUM)

**Location:** Multiple locations

**Examples:**
- Verbose error messages revealing system information
- Bot telemetry exposed via API endpoints
- User account information in logs
- System statistics exposed without authentication

**Impact:**
- Aids attackers in reconnaissance
- Leaks sensitive operational details
- Facilitates targeted attacks

**Recommended Fix:**
- Sanitize error messages
- Remove sensitive information from logs
- Implement proper logging levels
- Restrict access to system statistics

---

### 19. Fake Bot Count Feature (MEDIUM)

**Location:** `cnc/core/slaves/attack.go:45-48, 380-482`

```go
var Fake = false
fakeBots       map[int]*Bot
fakeAddQueue   chan *Bot
fakeDelQueue   chan int
```

**Description:** The C2 includes functionality to inflate bot counts with fake bots, used to deceive users.

**Impact:**
- Users are misled about actual botnet size
- Creates false sense of capability
- Fraudulent business practice

**Recommended Fix:**
(N/A - This is intentional deception)

---

### 20. No CSRF Protection (MEDIUM)

**Location:** `cnc/core/api/api.go`

**Description:** API endpoints lack Cross-Site Request Forgery (CSRF) protection.

**Impact:**
- Attacks can be triggered from malicious websites
- Users can be tricked into launching attacks
- No protection against automated cross-origin requests

**Recommended Fix:**
- Implement CSRF tokens for state-changing operations
- Validate Origin and Referer headers
- Use SameSite cookie attributes

---

## High-Severity Vulnerabilities

### 21. TFTP Server Security Issues (HIGH)

**Location:** `cnc/core/frontend/tftp/Serve.go`

**Issues:**
- No authentication
- No access logging (only basic file request logging)
- Path traversal vulnerability
- No rate limiting

**Impact:** Unrestricted file download, potential for system reconnaissance.

---

### 22. No Input Validation on Bot Source (MEDIUM)

**Location:** `cnc/core/slaves/attack.go:164-172`

```go
if strings.Contains(c.Source, "\r") || strings.Contains(c.Source, "\n") {
    c.Source = strings.ReplaceAll(c.Source, "\r", "")
    c.Source = strings.ReplaceAll(c.Source, "\n", "")
    c.Source = strings.ReplaceAll(c.Source, "\t", "")
}
```

**Description:** Input sanitization is incomplete and doesn't prevent all malicious input.

**Impact:** Potential for log injection, display issues, or command manipulation.

---

### 23. Timing Attack Vulnerability (LOW-MEDIUM)

**Location:** `cnc/core/database/users.go:113-117`

```go
err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
if err != nil {
    return false, AccountInfo{}, err
}
```

**Description:** While bcrypt itself provides timing resistance, the error handling could leak information.

**Impact:** Potential for password timing attacks (mitigated by bcrypt design).

---

## Medium-Severity Vulnerabilities

### 24. Outdated Dependencies (MEDIUM)

**Location:** `cnc/go.mod`

**Concerns:**
- Some dependencies may have known vulnerabilities
- Lack of regular dependency updates
- Using `+incompatible` versions

**Recommended Fix:** Regularly audit and update dependencies.

---

### 25. Insecure File Permissions (MEDIUM)

**Location:** `bot/locker.c:214`

```c
of, err := os.OpenFile(rPath, os.O_APPEND|os.O_RDWR, 0660);
```

**Description:** File creation with 0660 permissions may be too permissive.

**Impact:** Unprivileged users might access sensitive files.

---

### 26. No Connection Limits (MEDIUM)

**Location:** `cnc/core/slaves/listen.go`, `cnc/core/masters/listen.go`

**Description:** No limits on concurrent connections from bots or admins.

**Impact:** Vulnerable to resource exhaustion attacks.

---

### 27. Insufficient Logging (MEDIUM)

**Description:** Limited security event logging, no audit trail for sensitive operations.

**Impact:** Difficult to detect and investigate security incidents.

---

## Low-Severity Vulnerabilities

### 28. Debug Information Leaks (LOW)

**Location:** Various error handling locations

**Description:** Some error messages include stack traces or detailed system information.

**Impact:** Aids attackers in reconnaissance.

---

### 29. Predictable File Names (LOW)

**Description:** Static file names and paths make the system easier to fingerprint and block.

**Impact:** Easier detection by security tools.

---

### 30. No Input Sanitization in Commands (LOW)

**Location:** `cnc/core/masters/commands.go`

**Description:** User input is not fully sanitized before display or processing.

**Impact:** Potential for display manipulation or log injection.

---

## Properly Implemented Security Measures

Despite the numerous vulnerabilities, several security measures are properly implemented:

1. **Password Hashing:** Bcrypt with DefaultCost is used for all password storage
2. **Parameterized SQL Queries:** Most database queries use proper parameterization
3. **Input Validation:** Basic validation for IP addresses, ports, and durations
4. **Timeout Mechanisms:** Connection timeouts are implemented
5. **Connection Limits per User:** Attack cooldown and duration limits
6. **User Role System:** Admin, VIP, Reseller, and regular user roles are enforced

---

## Attack Scenarios

### Scenario 1: C2 Server Hijacking
1. Attacker discovers C2 server IP
2. Uses default admin credentials (admin/admin) to authenticate
3. Gains full control of botnet
4. Can redirect bots, steal user data, or launch arbitrary attacks

### Scenario 2: Bot Communication Interception
1. Attacker monitors network traffic
2. Uses static encryption key (0x00-0x1F) to decrypt communications
3. Extracts attack commands, bot telemetry, and C2 instructions
4. Potentially hijacks bots or creates a competing C2

### Scenario 3: File Server Exploitation
1. Attacker accesses HTTP/FTP/TFTP servers
2. Uses directory traversal to access sensitive files
3. Downloads SSH private key and configuration files
4. Gains unauthorized access to C2 infrastructure

### Scenario 4: Botnet Disruption
1. Attacker discovers C2 server location
2. Uses directory traversal or SQL injection to disrupt database
3. Creates fake users or deletes legitimate ones
4. Renders the botnet unusable for legitimate operators

---

## Recommendations

### Immediate Actions (Critical Priority)
1. **Change all hardcoded credentials and tokens**
2. **Implement proper encryption key management**
3. **Fix SQL injection vulnerability in UpdateUser**
4. **Remove or secure exposed SSH private key**
5. **Implement API authentication and rate limiting**
6. **Fix directory traversal vulnerabilities in file servers**

### Short-Term Improvements (High Priority)
1. **Implement proper FTP authentication**
2. **Add comprehensive input validation**
3. **Implement logging and audit trails**
4. **Fix buffer overflows in C bot code**
5. **Add connection limits and timeouts**
6. **Implement CSRF protection**

### Long-Term Improvements (Medium Priority)
1. **Regular security audits and penetration testing**
2. **Implement secrets management solution**
3. **Add monitoring and alerting for security events**
4. **Regular dependency updates and vulnerability scanning**
5. **Implement secure deployment practices**

---

## Conclusion

The ManjiBot botnet contains numerous critical security vulnerabilities that pose significant risks to both its operators and potential victims. The most severe issues include hardcoded credentials, weak cryptographic implementation, SQL injection, and lack of proper authentication.

While some security measures are properly implemented (bcrypt password hashing, parameterized queries), these are insufficient to protect against the numerous critical vulnerabilities present.

**Overall Risk Level: CRITICAL**

The system should not be deployed in production without addressing all critical and high-severity vulnerabilities identified in this report.

---

## Appendix: Affected Files Summary

| File | Severity | Vulnerability |
|------|----------|--------------|
| cnc/core/database/generate.go | CRITICAL | Hardcoded admin password |
| cnc/core/frontend/http/Serve.go | CRITICAL | Hardcoded admin token |
| cnc/core/frontend/http/Serve.go | HIGH | Directory traversal |
| cnc/core/database/database.go | CRITICAL | SQL injection |
| cnc/core/slaves/listen.go | CRITICAL | Static encryption key |
| cnc/core/slaves/listen.go | HIGH | ChaCha20 nonce reuse |
| cnc/core/api/api.go | CRITICAL | No API authentication |
| cnc/core/api/endpoints/slaves.go | HIGH | Hardcoded username check |
| cnc/core/frontend/ftp/Serve.go | HIGH | No FTP authentication |
| cnc/core/frontend/ftp/filedriver/driver.go | HIGH | Directory traversal |
| cnc/core/frontend/tftp/Serve.go | HIGH | Directory traversal, no auth |
| cnc/core/api/endpoints/attack.go | HIGH | Command injection risk |
| cnc/assets/id_rsa | CRITICAL | Exposed private key |
| cnc/assets/config.json | MEDIUM | API token exposure |
| bot/main.c | CRITICAL | Buffer overflows |
| bot/main.c | HIGH | Static encryption key |
| bot/killer.c | CRITICAL | Process killer |
| bot/locker.c | HIGH | Port locking, defense mechanisms |
| bot/chacha20.c | MEDIUM | Nonce reuse |

---

**End of Report**
