package vulnscan

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
	OutputDir   string
	Concurrency int // Max concurrent scans (default: 10)
	Verbose     bool
}

// NewScanner creates a new vulnerability scanner
func NewScanner(outputDir string) *Scanner {
	return &Scanner{
		OutputDir:   outputDir,
		Concurrency: 10, // Safe concurrency limit
		Verbose:     true,
	}
}

// Run executes vulnerability scanning on params.txt and live-js.txt
func (s *Scanner) Run(paramsFile, jsFile string) error {
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)
	red := color.New(color.FgRed, color.Bold)

	yellow.Println("\n═══════════════════════════════════════════════════════════════")
	yellow.Println("[STEP 6] Vulnerability Scanning (XSS)")
	yellow.Println("═══════════════════════════════════════════════════════════════")

	// Check and install gf if needed
	cyan.Println("→ Checking for required tools...")
	if err := s.ensureGfInstalled(); err != nil {
		red.Printf("✗ Failed to install gf: %v\n", err)
		return err
	}

	// Check other required tools
	if err := s.checkTools(); err != nil {
		red.Printf("✗ Missing required tools: %v\n", err)
		yellow.Println("→ Please install: kxss, dalfox")
		return err
	}
	green.Println("✓ All required tools are available")

	// Check if input files exist
	hasParams := false
	hasJS := false

	if _, err := os.Stat(paramsFile); err == nil {
		hasParams = true
	}

	if _, err := os.Stat(jsFile); err == nil {
		hasJS = true
	}

	if !hasParams && !hasJS {
		yellow.Println("⚠ No parameter URLs or JS files found, skipping vulnerability scanning")
		return nil
	}

	// Run XSS scanning
	if hasParams || hasJS {
		cyan.Println("\n→ Starting XSS vulnerability scanning...")
		if err := s.runXSSScan(paramsFile, jsFile); err != nil {
			yellow.Printf("⚠ XSS scan error: %v\n", err)
		}
	}

	yellow.Println("\n═══════════════════════════════════════════════════════════════")
	green.Println("         VULNERABILITY SCANNING COMPLETE")
	yellow.Println("═══════════════════════════════════════════════════════════════")

	return nil
}

// ensureGfInstalled checks if gf is installed and installs if missing
func (s *Scanner) ensureGfInstalled() error {
	cyan := color.New(color.FgCyan)
	green := color.New(color.FgGreen)

	// Check if gf is already installed
	if _, err := exec.LookPath("gf"); err == nil {
		cyan.Println("→ gf is already installed")
		return nil
	}

	cyan.Println("→ gf not found, installing...")

	// Install gf
	cmd := exec.Command("go", "install", "github.com/tomnomnom/gf@latest")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to install gf: %v", err)
	}

	// Install gf patterns
	cyan.Println("→ Installing gf patterns...")
	patternsDir := filepath.Join(os.Getenv("HOME"), ".gf")
	if err := os.MkdirAll(patternsDir, 0755); err != nil {
		return fmt.Errorf("failed to create .gf directory: %v", err)
	}

	// Clone gf patterns repository
	cmd = exec.Command("git", "clone",
		"https://github.com/1ndianl33t/Gf-Patterns",
		filepath.Join(patternsDir, "temp-patterns"))

	if err := cmd.Run(); err != nil {
		// Try alternative patterns repo
		cmd = exec.Command("git", "clone",
			"https://github.com/dwisiswant0/gf-secrets",
			filepath.Join(patternsDir, "temp-patterns"))
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to clone gf patterns: %v", err)
		}
	}

	// Copy patterns to .gf directory
	tempPatterns := filepath.Join(patternsDir, "temp-patterns")
	cmd = exec.Command("sh", "-c", fmt.Sprintf("cp %s/*.json %s/ 2>/dev/null || true", tempPatterns, patternsDir))
	cmd.Run()

	// Clean up
	os.RemoveAll(tempPatterns)

	green.Println("✓ gf installed successfully")
	return nil
}

// checkTools verifies required tools are installed
func (s *Scanner) checkTools() error {
	requiredTools := []string{
		"kxss",
		"dalfox",
	}

	var missing []string
	for _, tool := range requiredTools {
		if _, err := exec.LookPath(tool); err != nil {
			missing = append(missing, tool)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing tools: %s", strings.Join(missing, ", "))
	}

	return nil
}

// runXSSScan performs XSS vulnerability scanning
func (s *Scanner) runXSSScan(paramsFile, jsFile string) error {
	cyan := color.New(color.FgCyan)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)

	cyan.Println("→ Progress: 0% (Filtering URLs with gf patterns)")

	// Combine params and JS files for XSS testing
	var inputURLs []string

	if _, err := os.Stat(paramsFile); err == nil {
		urls, _ := s.readLines(paramsFile)
		inputURLs = append(inputURLs, urls...)
	}

	if _, err := os.Stat(jsFile); err == nil {
		urls, _ := s.readLines(jsFile)
		inputURLs = append(inputURLs, urls...)
	}

	if len(inputURLs) == 0 {
		yellow.Println("⚠ No URLs to scan for XSS")
		return nil
	}

	// Create combined input file
	combinedFile := filepath.Join(s.OutputDir, "xss-scan-input.txt")
	if err := s.writeLines(combinedFile, inputURLs); err != nil {
		return err
	}
	defer os.Remove(combinedFile)

	// Filter URLs with gf for XSS patterns
	cyan.Println("→ Progress: 10% (Filtering XSS candidates with gf)")
	xssFilteredFile := filepath.Join(s.OutputDir, "params-filtered-xss.txt")

	cmd := exec.Command("sh", "-c", fmt.Sprintf("cat %s | gf xss | sort -u > %s", combinedFile, xssFilteredFile))
	if err := cmd.Run(); err != nil {
		yellow.Printf("⚠ gf filtering failed, using all URLs: %v\n", err)
		// Use all URLs if gf fails
		if err := s.writeLines(xssFilteredFile, inputURLs); err != nil {
			return err
		}
	}

	filteredURLs, err := s.readLines(xssFilteredFile)
	if err != nil || len(filteredURLs) == 0 {
		yellow.Println("⚠ No XSS candidate URLs found after filtering")
		return nil
	}

	cyan.Printf("→ Found %d potential XSS URLs after filtering\n", len(filteredURLs))

	// Step 1: Run kxss for fast detection
	cyan.Println("→ Progress: 30% (Running kxss for quick detection)")
	kxssResultsFile := filepath.Join(s.OutputDir, "kxss-results.txt")

	cmd = exec.Command("sh", "-c", fmt.Sprintf("cat %s | kxss | tee %s", xssFilteredFile, kxssResultsFile))
	if err := cmd.Run(); err != nil {
		yellow.Printf("⚠ kxss scan error: %v\n", err)
		return err
	}

	kxssResults, err := s.readLines(kxssResultsFile)
	if err != nil || len(kxssResults) == 0 {
		cyan.Println("→ kxss found no potential XSS vulnerabilities")
		return nil
	}

	cyan.Printf("→ kxss found %d potential XSS URLs\n", len(kxssResults))

	// Step 2: Confirm with dalfox
	cyan.Println("→ Progress: 60% (Confirming with dalfox - this may take a while)")
	xssVulnFile := filepath.Join(s.OutputDir, "xss-vulnerable.txt")

	cmd = exec.Command("dalfox",
		"file", kxssResultsFile,
		"-o", xssVulnFile,
		"--silence",
		"--skip-bav", // Skip bad verification
		"--follow-redirects",
		"--worker", fmt.Sprintf("%d", s.Concurrency),
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		yellow.Printf("⚠ dalfox scan completed with warnings\n")
	}

	// Parse dalfox output to count vulnerabilities
	vulnCount := 0
	if _, err := os.Stat(xssVulnFile); err == nil {
		vulns, _ := s.readLines(xssVulnFile)
		vulnCount = len(vulns)
	}

	cyan.Println("→ Progress: 100% (XSS scanning complete)")

	if vulnCount > 0 {
		green.Printf("✓ Found %d confirmed XSS vulnerabilities\n", vulnCount)
		green.Printf("✓ Results saved to: %s\n", xssVulnFile)
	} else {
		cyan.Println("→ No confirmed XSS vulnerabilities found")
	}

	// Save kxss results separately
	green.Printf("✓ kxss results saved to: %s\n", kxssResultsFile)
	green.Printf("✓ Filtered XSS candidates saved to: %s\n", xssFilteredFile)

	// Print summary from output
	if s.Verbose && len(output) > 0 {
		fmt.Println(string(output))
	}

	return nil
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
		fmt.Fprintln(writer, line)
	}

	return writer.Flush()
}
