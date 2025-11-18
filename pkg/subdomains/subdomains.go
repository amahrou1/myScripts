package subdomains

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

type Enumerator struct {
	Domain     string
	OutputDir  string
	Wordlist   string
	Resolvers  string
	Verbose    bool
}

type Result struct {
	Tool        string
	Subdomains  []string
	Error       error
	Duration    time.Duration
}

// NewEnumerator creates a new subdomain enumerator
func NewEnumerator(domain, outputDir string) *Enumerator {
	return &Enumerator{
		Domain:    domain,
		OutputDir: outputDir,
		Wordlist:  "/root/myLists/subdomains.txt",
		Resolvers: "/root/myLists/resolvers.txt",
		Verbose:   true,
	}
}

// Run executes the full subdomain enumeration workflow
func (e *Enumerator) Run() error {
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)

	green.Printf("\n[*] Starting Subdomain Enumeration for: %s\n", e.Domain)
	green.Printf("[*] Output Directory: %s\n\n", e.OutputDir)

	// Create output directory
	if err := os.MkdirAll(e.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Step 1: Wildcard Detection
	yellow.Println("═══════════════════════════════════════════════════════")
	yellow.Println("[Step 1/5] Wildcard DNS Detection")
	yellow.Println("═══════════════════════════════════════════════════════")

	hasWildcard := e.detectWildcard()
	if hasWildcard {
		red.Println("⚠ Wildcard DNS detected! Brute force will be skipped.")
	} else {
		green.Println("✓ No wildcard detected. Brute force will be performed.")
	}

	// Step 2: Passive Enumeration
	yellow.Println("\n═══════════════════════════════════════════════════════")
	yellow.Println("[Step 2/5] Passive Subdomain Enumeration")
	yellow.Println("═══════════════════════════════════════════════════════")

	passiveSubs, err := e.runPassiveEnumeration()
	if err != nil {
		red.Printf("✗ Passive enumeration error: %v\n", err)
	}
	cyan.Printf("✓ Found %d subdomains from passive sources\n", len(passiveSubs))

	// Step 3: Brute Force (if no wildcard)
	var bruteSubs []string
	if !hasWildcard {
		yellow.Println("\n═══════════════════════════════════════════════════════")
		yellow.Println("[Step 3/5] Brute Force Enumeration (massdns)")
		yellow.Println("═══════════════════════════════════════════════════════")

		bruteSubs, err = e.runBruteForce()
		if err != nil {
			red.Printf("✗ Brute force error: %v\n", err)
		} else {
			cyan.Printf("✓ Found %d subdomains from brute force\n", len(bruteSubs))
		}
	} else {
		yellow.Println("\n[Step 3/5] Brute Force - SKIPPED (wildcard detected)")
	}

	// Step 4: Combine and Deduplicate
	yellow.Println("\n═══════════════════════════════════════════════════════")
	yellow.Println("[Step 4/5] Deduplication and Sorting")
	yellow.Println("═══════════════════════════════════════════════════════")

	allSubs := e.deduplicateSubdomains(passiveSubs, bruteSubs)
	cyan.Printf("✓ Total unique subdomains: %d\n", len(allSubs))

	// Save all subdomains
	allSubsFile := filepath.Join(e.OutputDir, "all-subdomains.txt")
	if err := e.writeToFile(allSubsFile, allSubs); err != nil {
		return err
	}
	green.Printf("✓ Saved all subdomains to: %s\n", allSubsFile)

	// Step 5: Live Host Detection
	yellow.Println("\n═══════════════════════════════════════════════════════")
	yellow.Println("[Step 5/5] Live Host Detection (httpx)")
	yellow.Println("═══════════════════════════════════════════════════════")

	liveSubs, err := e.detectLiveHosts(allSubs)
	if err != nil {
		red.Printf("✗ Live detection error: %v\n", err)
	}

	// Save live subdomains
	liveSubsFile := filepath.Join(e.OutputDir, "live-subdomains.txt")
	if err := e.writeToFile(liveSubsFile, liveSubs); err != nil {
		return err
	}

	// Summary
	green.Println("\n═══════════════════════════════════════════════════════")
	green.Println("           ENUMERATION COMPLETE")
	green.Println("═══════════════════════════════════════════════════════")
	green.Printf("Total Subdomains Found: %d\n", len(allSubs))
	green.Printf("Live Subdomains: %d\n", len(liveSubs))
	green.Printf("Results saved in: %s\n", e.OutputDir)
	green.Println("═══════════════════════════════════════════════════════\n")

	return nil
}

// detectWildcard checks if the domain has wildcard DNS configured
func (e *Enumerator) detectWildcard() bool {
	cyan := color.New(color.FgCyan)
	cyan.Print("→ Testing for wildcard DNS... ")

	testSubdomains := []string{
		"test321123." + e.Domain,
		"testingforwildcard." + e.Domain,
		"plsdontgimmearesult." + e.Domain,
	}

	cmd := exec.Command("dig", "@1.1.1.1", "A,CNAME",
		fmt.Sprintf("{%s}", strings.Join(testSubdomains, ",")), "+short")

	output, err := cmd.Output()
	if err != nil {
		return false
	}

	return len(strings.TrimSpace(string(output))) > 0
}

// runPassiveEnumeration runs all passive enumeration tools concurrently
func (e *Enumerator) runPassiveEnumeration() ([]string, error) {
	tools := []struct {
		name string
		cmd  []string
	}{
		{"amass", []string{"amass", "enum", "-passive", "-norecursive", "-noalts", "-d", e.Domain}},
		{"subfinder", []string{"subfinder", "-d", e.Domain, "-all", "-silent"}},
		{"assetfinder", []string{"assetfinder", "-subs-only", e.Domain}},
		{"findomain", []string{"findomain", "-t", e.Domain, "--quiet"}},
	}

	var wg sync.WaitGroup
	results := make(chan Result, len(tools))

	for _, tool := range tools {
		wg.Add(1)
		go func(toolName string, cmdArgs []string) {
			defer wg.Done()
			e.runTool(toolName, cmdArgs, results)
		}(tool.name, tool.cmd)
	}

	wg.Wait()
	close(results)

	// Collect all results
	var allSubs []string
	red := color.New(color.FgRed)
	cyan := color.New(color.FgCyan)

	for result := range results {
		if result.Error != nil {
			red.Printf("✗ %s failed: %v\n", result.Tool, result.Error)
		} else {
			cyan.Printf("✓ %s: %d subdomains (%.2fs)\n",
				result.Tool, len(result.Subdomains), result.Duration.Seconds())
			allSubs = append(allSubs, result.Subdomains...)
		}
	}

	return allSubs, nil
}

// runTool executes a single enumeration tool
func (e *Enumerator) runTool(toolName string, cmdArgs []string, results chan<- Result) {
	start := time.Now()

	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	output, err := cmd.Output()

	result := Result{
		Tool:     toolName,
		Duration: time.Since(start),
	}

	if err != nil {
		result.Error = err
		results <- result
		return
	}

	// Parse subdomains from output
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			result.Subdomains = append(result.Subdomains, line)
		}
	}

	results <- result
}

// runBruteForce performs brute force enumeration using massdns
func (e *Enumerator) runBruteForce() ([]string, error) {
	cyan := color.New(color.FgCyan)
	cyan.Println("→ Generating wordlist...")

	// Check if wordlist exists
	if _, err := os.Stat(e.Wordlist); os.IsNotExist(err) {
		return nil, fmt.Errorf("wordlist not found: %s", e.Wordlist)
	}

	// Generate hosts-wordlist.txt
	hostsFile := filepath.Join(e.OutputDir, "hosts-wordlist.txt")
	if err := e.generateHostsWordlist(hostsFile); err != nil {
		return nil, err
	}
	defer os.Remove(hostsFile)

	cyan.Println("→ Running massdns (this may take a while)...")

	// Run massdns
	massdnsOut := filepath.Join(e.OutputDir, "massdns.out")
	cmd := exec.Command("massdns",
		"-r", e.Resolvers,
		"-t", "A",
		"-o", "S",
		"-w", massdnsOut,
		hostsFile,
	)

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("massdns failed: %v", err)
	}
	defer os.Remove(massdnsOut)

	// Parse massdns output
	cyan.Println("→ Parsing massdns results...")
	subdomains, err := e.parseMassdnsOutput(massdnsOut)
	if err != nil {
		return nil, err
	}

	return subdomains, nil
}

// generateHostsWordlist creates the hosts wordlist for massdns
func (e *Enumerator) generateHostsWordlist(outputFile string) error {
	inFile, err := os.Open(e.Wordlist)
	if err != nil {
		return err
	}
	defer inFile.Close()

	outFile, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer outFile.Close()

	scanner := bufio.NewScanner(inFile)
	writer := bufio.NewWriter(outFile)

	for scanner.Scan() {
		subdomain := strings.TrimSpace(scanner.Text())
		if subdomain != "" {
			writer.WriteString(subdomain + "." + e.Domain + "\n")
		}
	}

	return writer.Flush()
}

// parseMassdnsOutput parses massdns output and extracts subdomains
func (e *Enumerator) parseMassdnsOutput(massdnsFile string) ([]string, error) {
	file, err := os.Open(massdnsFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	subdomainMap := make(map[string]bool)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) > 0 {
			subdomain := strings.TrimSuffix(fields[0], ".")
			subdomainMap[subdomain] = true
		}
	}

	var subdomains []string
	for sub := range subdomainMap {
		subdomains = append(subdomains, sub)
	}

	return subdomains, nil
}

// detectLiveHosts uses httpx to find live hosts
func (e *Enumerator) detectLiveHosts(subdomains []string) ([]string, error) {
	cyan := color.New(color.FgCyan)
	cyan.Printf("→ Checking %d subdomains for live hosts...\n", len(subdomains))

	// Write subdomains to temp file
	tempFile := filepath.Join(e.OutputDir, "temp-subs.txt")
	if err := e.writeToFile(tempFile, subdomains); err != nil {
		return nil, err
	}
	defer os.Remove(tempFile)

	// Run httpx
	cmd := exec.Command("httpx", "-l", tempFile, "-silent")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("httpx failed: %v", err)
	}

	var liveSubs []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			liveSubs = append(liveSubs, line)
		}
	}

	green := color.New(color.FgGreen)
	green.Printf("✓ Found %d live hosts\n", len(liveSubs))

	return liveSubs, nil
}

// deduplicateSubdomains combines and deduplicates subdomain lists
func (e *Enumerator) deduplicateSubdomains(lists ...[]string) []string {
	subdomainMap := make(map[string]bool)

	for _, list := range lists {
		for _, subdomain := range list {
			subdomain = strings.TrimSpace(subdomain)
			if subdomain != "" {
				subdomainMap[subdomain] = true
			}
		}
	}

	var unique []string
	for sub := range subdomainMap {
		unique = append(unique, sub)
	}

	sort.Strings(unique)
	return unique
}

// writeToFile writes a list of strings to a file
func (e *Enumerator) writeToFile(filename string, lines []string) error {
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
