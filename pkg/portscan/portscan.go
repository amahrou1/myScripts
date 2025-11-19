package portscan

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
)

type Scanner struct {
	OutputDir    string
	TopPorts     int
	ExcludePorts string
	Verbose      bool
}

type NaabuResult struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	IP   string `json:"ip"`
}

// NewScanner creates a new port scanner
func NewScanner(outputDir string) *Scanner {
	return &Scanner{
		OutputDir:    outputDir,
		TopPorts:     5000,
		ExcludePorts: "80,443",
		Verbose:      true,
	}
}

// Run executes port scanning on targets
func (s *Scanner) Run(liveSubsFile, shodanIPsFile string) error {
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)
	red := color.New(color.FgRed, color.Bold)

	yellow.Println("\n═══════════════════════════════════════════════════════")
	yellow.Println("[STEP 3] Port Scanning")
	yellow.Println("═══════════════════════════════════════════════════════")

	// Check if naabu is installed
	if _, err := exec.LookPath("naabu"); err != nil {
		red.Println("✗ naabu not found in PATH")
		yellow.Println("→ Please install naabu: go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest")
		return fmt.Errorf("naabu not installed")
	}

	// Prepare targets
	var targets []string

	// Load live subdomains
	if _, err := os.Stat(liveSubsFile); err == nil {
		subs, err := s.readLines(liveSubsFile)
		if err == nil {
			// Clean URLs - remove http:// and https://
			for _, sub := range subs {
				cleaned := strings.TrimPrefix(sub, "http://")
				cleaned = strings.TrimPrefix(cleaned, "https://")
				cleaned = strings.Split(cleaned, "/")[0]
				if cleaned != "" {
					targets = append(targets, cleaned)
				}
			}
			cyan.Printf("→ Loaded %d live subdomains for port scanning\n", len(subs))
		}
	} else {
		yellow.Printf("⚠ Live subdomains file not found: %s\n", liveSubsFile)
	}

	// Load Shodan IPs
	if _, err := os.Stat(shodanIPsFile); err == nil {
		ips, err := s.readLines(shodanIPsFile)
		if err == nil {
			// Clean URLs - remove http:// and https:// prefixes
			for _, ip := range ips {
				cleaned := strings.TrimPrefix(ip, "http://")
				cleaned = strings.TrimPrefix(cleaned, "https://")
				cleaned = strings.Split(cleaned, "/")[0]
				cleaned = strings.Split(cleaned, ":")[0] // Remove port if present
				if cleaned != "" {
					targets = append(targets, cleaned)
				}
			}
			cyan.Printf("→ Loaded %d Shodan IPs for port scanning\n", len(ips))
		}
	} else {
		yellow.Printf("⚠ Shodan IPs file not found: %s\n", shodanIPsFile)
	}

	if len(targets) == 0 {
		red.Println("✗ No targets found for port scanning")
		yellow.Printf("→ Live subdomains file: %s (not found or empty)\n", liveSubsFile)
		yellow.Printf("→ Shodan IPs file: %s (not found or empty)\n", shodanIPsFile)
		yellow.Println("→ Ensure Step 1 (subdomain enumeration) completed successfully")
		return fmt.Errorf("no targets found for port scanning")
	}

	cyan.Printf("→ Total targets for port scanning: %d\n", len(targets))
	cyan.Printf("→ Scanning top %d ports (excluding %s)\n", s.TopPorts, s.ExcludePorts)

	// Create targets file for naabu
	targetsFile := filepath.Join(s.OutputDir, "portscan-targets.txt")
	if err := s.writeLines(targetsFile, targets); err != nil {
		return fmt.Errorf("failed to create targets file: %v", err)
	}
	defer os.Remove(targetsFile)

	// Run naabu port scan
	cyan.Println("→ Running naabu port scan (this may take a while)...")

	naabuOutput := filepath.Join(s.OutputDir, "naabu-results.json")
	defer os.Remove(naabuOutput)

	if err := s.runNaabu(targetsFile, naabuOutput); err != nil {
		red.Printf("✗ Port scan error: %v\n", err)
		return err
	}

	// Parse naabu results
	cyan.Println("→ Parsing port scan results...")
	openPorts, err := s.parseNaabuResults(naabuOutput)
	if err != nil {
		return fmt.Errorf("failed to parse results: %v", err)
	}

	if len(openPorts) == 0 {
		cyan.Println("→ No open ports found (excluding 80, 443)")
		return nil
	}

	cyan.Printf("→ Found %d open ports\n", len(openPorts))

	// Build URLs for httpx verification
	cyan.Println("→ Building URLs for verification...")
	urls := s.buildURLs(openPorts)
	cyan.Printf("→ Created %d URLs to verify\n", len(urls))

	// Verify with httpx
	cyan.Println("→ Verifying live services with httpx...")
	liveURLs, err := s.verifyWithHttpx(urls)
	if err != nil {
		red.Printf("✗ Verification error: %v\n", err)
		return err
	}

	if len(liveURLs) == 0 {
		cyan.Println("→ No live services found on discovered ports")
		return nil
	}

	// Save results
	openPortsFile := filepath.Join(s.OutputDir, "open-ports.txt")
	if err := s.writeLines(openPortsFile, liveURLs); err != nil {
		return fmt.Errorf("failed to save results: %v", err)
	}

	green.Printf("✓ Found %d live services on non-standard ports\n", len(liveURLs))
	green.Printf("✓ Results saved to: %s\n", openPortsFile)

	yellow.Println("═══════════════════════════════════════════════════════")
	green.Println("         PORT SCANNING COMPLETE")
	yellow.Println("═══════════════════════════════════════════════════════")

	return nil
}

// runNaabu executes naabu port scanner
func (s *Scanner) runNaabu(targetsFile, outputFile string) error {
	cyan := color.New(color.FgCyan)

	args := []string{
		"-list", targetsFile,
		"-top-ports", fmt.Sprintf("%d", s.TopPorts),
		"-exclude-ports", s.ExcludePorts,
		"-json",
		"-o", outputFile,
		"-silent",
	}

	cyan.Printf("→ Command: naabu %s\n", strings.Join(args, " "))

	cmd := exec.Command("naabu", args...)

	// Stream output in real-time
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start naabu: %v", err)
	}

	// Print stderr (progress)
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			fmt.Println(scanner.Text())
		}
	}()

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("naabu scan failed: %v", err)
	}

	return nil
}

// parseNaabuResults parses JSON output from naabu
func (s *Scanner) parseNaabuResults(outputFile string) ([]string, error) {
	file, err := os.Open(outputFile)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	defer file.Close()

	var results []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		var result NaabuResult
		if err := json.Unmarshal([]byte(scanner.Text()), &result); err != nil {
			continue
		}

		// Format as host:port
		hostPort := fmt.Sprintf("%s:%d", result.Host, result.Port)
		results = append(results, hostPort)
	}

	return results, scanner.Err()
}

// buildURLs creates http and https URLs from host:port combinations
func (s *Scanner) buildURLs(hostPorts []string) []string {
	var urls []string

	for _, hp := range hostPorts {
		// Try both http and https
		urls = append(urls, "http://"+hp)
		urls = append(urls, "https://"+hp)
	}

	return urls
}

// verifyWithHttpx verifies which URLs are live using httpx
func (s *Scanner) verifyWithHttpx(urls []string) ([]string, error) {
	cyan := color.New(color.FgCyan)
	cyan.Printf("→ Verifying %d URLs with httpx...\n", len(urls))

	// Create temp file with URLs
	tempFile := filepath.Join(s.OutputDir, "httpx-verify-urls.txt")
	if err := s.writeLines(tempFile, urls); err != nil {
		return nil, err
	}
	defer os.Remove(tempFile)

	// Run httpx
	cmd := exec.Command("httpx", "-l", tempFile, "-silent")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("httpx verification failed: %v", err)
	}

	// Parse httpx results
	var liveURLs []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url != "" {
			liveURLs = append(liveURLs, url)
		}
	}

	return liveURLs, nil
}

// readLines reads lines from a file
func (s *Scanner) readLines(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
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

// writeLines writes lines to a file
func (s *Scanner) writeLines(filename string, lines []string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range lines {
		writer.WriteString(line + "\n")
	}

	return writer.Flush()
}
