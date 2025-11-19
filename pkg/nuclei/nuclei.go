package nuclei

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
	OutputDir         string
	DefaultTemplates  string
	CustomTemplates   string
	Severities        []string
	Verbose           bool
}

// NewScanner creates a new Nuclei scanner
func NewScanner(outputDir string) *Scanner {
	return &Scanner{
		OutputDir:        outputDir,
		DefaultTemplates: "/root/nuclei-templates",
		CustomTemplates:  "/root/test123",
		Severities:       []string{"medium", "high", "critical"},
		Verbose:          true,
	}
}

// Run executes Nuclei scanning on subdomains and IPs
func (s *Scanner) Run(subdomainsFile, shodanIPsFile string) error {
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)
	red := color.New(color.FgRed, color.Bold)

	yellow.Println("\n═══════════════════════════════════════════════════════")
	yellow.Println("[STEP 2] Nuclei Vulnerability Scanning")
	yellow.Println("═══════════════════════════════════════════════════════")

	// Prepare targets
	var targets []string

	// Load subdomains
	if _, err := os.Stat(subdomainsFile); err == nil {
		subs, err := s.readLines(subdomainsFile)
		if err == nil {
			targets = append(targets, subs...)
			cyan.Printf("→ Loaded %d subdomains for scanning\n", len(subs))
		}
	} else {
		yellow.Printf("⚠ Subdomains file not found: %s\n", subdomainsFile)
	}

	// Load Shodan IPs
	if _, err := os.Stat(shodanIPsFile); err == nil {
		ips, err := s.readLines(shodanIPsFile)
		if err == nil {
			targets = append(targets, ips...)
			cyan.Printf("→ Loaded %d Shodan IPs for scanning\n", len(ips))
		}
	} else {
		yellow.Printf("⚠ Shodan IPs file not found: %s\n", shodanIPsFile)
	}

	if len(targets) == 0 {
		return fmt.Errorf("no targets found for Nuclei scanning")
	}

	cyan.Printf("→ Total targets for Nuclei: %d\n", len(targets))

	// Create targets file
	targetsFile := filepath.Join(s.OutputDir, "nuclei-targets.txt")
	if err := s.writeLines(targetsFile, targets); err != nil {
		return fmt.Errorf("failed to create targets file: %v", err)
	}
	defer os.Remove(targetsFile)

	// Check template directories
	templatesExist := s.checkTemplates()
	if !templatesExist {
		return fmt.Errorf("no template directories found")
	}

	// Run Nuclei scans
	cyan.Println("→ Starting Nuclei scans (this may take a while)...")
	cyan.Printf("→ Scanning with severities: %s\n", strings.Join(s.Severities, ", "))

	nucleiOutput := filepath.Join(s.OutputDir, "nuclei.txt")

	// Run Nuclei with both template directories
	if err := s.runNucleiScan(targetsFile, nucleiOutput); err != nil {
		red.Printf("✗ Nuclei scan error: %v\n", err)
		return err
	}

	// Count findings
	findings, err := s.countFindings(nucleiOutput)
	if err == nil && findings > 0 {
		green.Printf("✓ Nuclei found %d vulnerabilities\n", findings)
		green.Printf("✓ Results saved to: %s\n", nucleiOutput)
	} else if findings == 0 {
		cyan.Println("→ No vulnerabilities found")
	}

	yellow.Println("═══════════════════════════════════════════════════════")
	green.Println("         NUCLEI SCANNING COMPLETE")
	yellow.Println("═══════════════════════════════════════════════════════")

	return nil
}

// checkTemplates verifies template directories exist
func (s *Scanner) checkTemplates() bool {
	cyan := color.New(color.FgCyan)
	yellow := color.New(color.FgYellow)

	defaultExists := false
	customExists := false

	if _, err := os.Stat(s.DefaultTemplates); err == nil {
		cyan.Printf("✓ Default templates found: %s\n", s.DefaultTemplates)
		defaultExists = true
	} else {
		yellow.Printf("⚠ Default templates not found: %s\n", s.DefaultTemplates)
	}

	if _, err := os.Stat(s.CustomTemplates); err == nil {
		cyan.Printf("✓ Custom templates found: %s\n", s.CustomTemplates)
		customExists = true
	} else {
		yellow.Printf("⚠ Custom templates not found: %s\n", s.CustomTemplates)
	}

	return defaultExists || customExists
}

// runNucleiScan executes the Nuclei scan
func (s *Scanner) runNucleiScan(targetsFile, outputFile string) error {
	cyan := color.New(color.FgCyan)

	// Build nuclei command
	args := []string{
		"-l", targetsFile,
		"-severity", strings.Join(s.Severities, ","),
		"-o", outputFile,
		"-stats",
		"-silent",
	}

	// Add default templates if they exist
	if _, err := os.Stat(s.DefaultTemplates); err == nil {
		args = append(args, "-t", s.DefaultTemplates)
	}

	// Add custom templates if they exist
	if _, err := os.Stat(s.CustomTemplates); err == nil {
		args = append(args, "-t", s.CustomTemplates)
	}

	cyan.Println("→ Running Nuclei...")
	cyan.Printf("→ Command: nuclei %s\n", strings.Join(args, " "))

	cmd := exec.Command("nuclei", args...)

	// Stream output in real-time
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start nuclei: %v", err)
	}

	// Print stdout in real-time
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			fmt.Println(scanner.Text())
		}
	}()

	// Print stderr in real-time (progress updates on same line)
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			// Check if this is a progress line (contains Templates: or RPS:)
			if strings.Contains(line, "Templates:") || strings.Contains(line, "RPS:") {
				// Print with carriage return to update same line
				fmt.Printf("\r%s", line)
			} else {
				// Regular line, print with newline
				fmt.Println(line)
			}
		}
		// Print newline after progress is done
		fmt.Println()
	}()

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("nuclei scan failed: %v", err)
	}

	return nil
}

// countFindings counts the number of findings in the output file
func (s *Scanner) countFindings(outputFile string) (int, error) {
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		return 0, nil
	}

	lines, err := s.readLines(outputFile)
	if err != nil {
		return 0, err
	}

	return len(lines), nil
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
