package portscan

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
)

type Scanner struct {
	OutputDir    string
	ScanAllPorts bool   // if true (default), scan all 65535 ports with -p-
	ExcludePorts string
	Verbose      bool
}

// NewScanner creates a new port scanner
func NewScanner(outputDir string) *Scanner {
	return &Scanner{
		OutputDir:    outputDir,
		ScanAllPorts: true, // Default: scan all ports
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

	// Check if nmap is installed
	if _, err := exec.LookPath("nmap"); err != nil {
		red.Println("✗ nmap not found in PATH")
		yellow.Println("→ Please install nmap: sudo apt-get install nmap")
		return fmt.Errorf("nmap not installed")
	}

	// Prepare targets
	var targets []string

	// Load live subdomains
	if _, err := os.Stat(liveSubsFile); err == nil {
		subs, err := s.readLines(liveSubsFile)
		if err == nil {
			// Clean URLs - remove http:// and https://
			for _, sub := range subs {
				cleaned := s.cleanTarget(sub)
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
				cleaned := s.cleanTarget(ip)
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
	if s.ScanAllPorts {
		cyan.Printf("→ Scanning all 65535 ports (excluding %s)\n", s.ExcludePorts)
	} else {
		cyan.Printf("→ Scanning common ports (excluding %s)\n", s.ExcludePorts)
	}

	// Create targets file for nmap (clean hostnames/IPs without http/https)
	targetsFile := filepath.Join(s.OutputDir, "portscan-targets.txt")
	if err := s.writeLines(targetsFile, targets); err != nil {
		return fmt.Errorf("failed to create targets file: %v", err)
	}
	defer os.Remove(targetsFile)

	// Run nmap port scan
	cyan.Println("→ Running nmap port scan (this may take a while)...")

	nmapOutput := filepath.Join(s.OutputDir, "nmap-results.gnmap")
	defer os.Remove(nmapOutput)

	if err := s.runNmap(targetsFile, nmapOutput); err != nil {
		red.Printf("✗ Port scan error: %v\n", err)
		return err
	}

	// Parse nmap results
	cyan.Println("→ Parsing port scan results...")
	openPorts, err := s.parseNmapResults(nmapOutput)
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

// runNmap executes nmap port scanner
func (s *Scanner) runNmap(targetsFile, outputFile string) error {
	cyan := color.New(color.FgCyan)

	// Build nmap arguments
	args := []string{
		"-iL", targetsFile,
	}

	// Add port scan range
	if s.ScanAllPorts {
		args = append(args, "-p-") // Scan all 65535 ports
	} else {
		args = append(args, "--top-ports", "1000") // Fallback: top 1000 ports
	}

	// Add remaining arguments
	args = append(args,
		"--exclude-ports", s.ExcludePorts,
		"-Pn",     // Skip host discovery (treat all hosts as online)
		"-oG", outputFile,
		"-T4",     // Aggressive timing
		"--open",  // Only show open ports
	)

	cyan.Printf("→ Command: nmap %s\n", strings.Join(args, " "))

	cmd := exec.Command("nmap", args...)

	// Stream output in real-time
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start nmap: %v", err)
	}

	// Print stdout/stderr (progress)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "Nmap scan report") || strings.Contains(line, "Discovered") {
				fmt.Println(line)
			}
		}
	}()

	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			fmt.Println(scanner.Text())
		}
	}()

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("nmap scan failed: %v", err)
	}

	return nil
}

// parseNmapResults parses grepable output from nmap
func (s *Scanner) parseNmapResults(outputFile string) ([]string, error) {
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
		line := scanner.Text()

		// Parse grepable format: Host: <ip> (<hostname>)	Ports: <port>/<state>/<proto>/<owner>/<service>/<rpcinfo>/<version>
		if !strings.HasPrefix(line, "Host:") {
			continue
		}

		// Extract host and ports
		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			continue
		}

		// Get host
		hostPart := strings.TrimPrefix(parts[0], "Host: ")
		hostFields := strings.Fields(hostPart)
		if len(hostFields) == 0 {
			continue
		}
		host := hostFields[0]

		// Get ports
		for _, part := range parts[1:] {
			if !strings.HasPrefix(part, "Ports:") {
				continue
			}

			portsStr := strings.TrimPrefix(part, "Ports: ")
			portEntries := strings.Split(portsStr, ",")

			for _, entry := range portEntries {
				entry = strings.TrimSpace(entry)
				fields := strings.Split(entry, "/")
				if len(fields) < 2 {
					continue
				}

				port := fields[0]
				state := fields[1]

				// Only include open ports
				if state == "open" {
					hostPort := fmt.Sprintf("%s:%s", host, port)
					results = append(results, hostPort)
				}
			}
		}
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

// cleanTarget removes URL schemes, paths, and ports to get clean hostname/IP for nmap
func (s *Scanner) cleanTarget(target string) string {
	// Remove http:// or https://
	cleaned := strings.TrimPrefix(target, "http://")
	cleaned = strings.TrimPrefix(cleaned, "https://")

	// Remove path (everything after first /)
	cleaned = strings.Split(cleaned, "/")[0]

	// Remove port (everything after :)
	cleaned = strings.Split(cleaned, ":")[0]

	// Trim whitespace
	cleaned = strings.TrimSpace(cleaned)

	// Validate: ensure no scheme remains
	if strings.Contains(cleaned, "://") {
		return ""
	}

	return cleaned
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
