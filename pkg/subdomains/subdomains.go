package subdomains

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

type Enumerator struct {
	Domain        string
	OutputDir     string
	Wordlist      string
	VHostWordlist string
	Resolvers     string
	ShodanAPIKey  string
	PythonScript  string
	SkipVHost     bool
	Verbose       bool
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
		Domain:        domain,
		OutputDir:     outputDir,
		Wordlist:      "/root/myLists/subdomains.txt",
		VHostWordlist: "/root/myLists/vhost-wordlist.txt",
		Resolvers:     "/root/myLists/resolvers.txt",
		ShodanAPIKey:  "j8PrRv5fW2Ox7Vt8PBJIdNokQv5lsBD1",
		PythonScript:  "/root/tools/subdomain-enum/subdomain-Enum.py",
		SkipVHost:     false,
		Verbose:       true,
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
	yellow.Println("[Step 5/6] Live Host Detection (httpx)")
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
	cyan.Printf("✓ Found %d live hosts\n", len(liveSubs))

	// Collect Shodan IPs (always, regardless of VHost fuzzing)
	yellow.Println("\n═══════════════════════════════════════════════════════")
	yellow.Println("[Bonus] Shodan IP Collection")
	yellow.Println("═══════════════════════════════════════════════════════")

	shodanIPs := e.getIPsFromShodan()
	if len(shodanIPs) > 0 {
		cyan.Printf("→ Found %d IPs from Shodan SSL certificates\n", len(shodanIPs))
		shodanIPsFile := filepath.Join(e.OutputDir, "shodan-ips.txt")
		if err := e.writeToFile(shodanIPsFile, shodanIPs); err == nil {
			green.Printf("✓ Saved Shodan IPs to: %s\n", shodanIPsFile)
		}
	} else {
		cyan.Println("→ No IPs found from Shodan")
	}

	// Step 6: VHost Fuzzing
	if e.SkipVHost {
		yellow.Println("\n[Step 6/6] VHost Fuzzing - SKIPPED (use without -skip-vhost to enable)")
	} else {
		yellow.Println("\n═══════════════════════════════════════════════════════")
		yellow.Println("[Step 6/6] VHost Fuzzing (Hidden Subdomains)")
		yellow.Println("═══════════════════════════════════════════════════════")

		vhostSubs, err := e.runVHostFuzzing(allSubs)
		if err != nil {
			red.Printf("✗ VHost fuzzing error: %v\n", err)
		} else if len(vhostSubs) > 0 {
		cyan.Printf("✓ Found %d new subdomains via VHost fuzzing\n", len(vhostSubs))

		// Merge vhost results with all subdomains
		allSubs = e.deduplicateSubdomains(allSubs, vhostSubs)

		// Update all-subdomains.txt with vhost results
		if err := e.writeToFile(allSubsFile, allSubs); err != nil {
			return err
		}

		// Save vhost-specific results
		vhostFile := filepath.Join(e.OutputDir, "vhost-subdomains.txt")
		if err := e.writeToFile(vhostFile, vhostSubs); err != nil {
			return err
		}
		green.Printf("✓ Saved vhost subdomains to: %s\n", vhostFile)

		// Check if vhost subdomains are live
		liveVhostSubs, err := e.detectLiveHosts(vhostSubs)
		if err == nil && len(liveVhostSubs) > 0 {
			// Merge with live subdomains
			liveSubs = e.deduplicateSubdomains(liveSubs, liveVhostSubs)
			if err := e.writeToFile(liveSubsFile, liveSubs); err != nil {
				return err
			}
			cyan.Printf("✓ Found %d live vhost subdomains\n", len(liveVhostSubs))
		}
		} else {
			cyan.Println("→ No new subdomains found via VHost fuzzing")
		}
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

	// Calculate total number of sources (tools + additional sources)
	totalSources := len(tools) + 4 // 4 additional sources: wayback, crt.sh, subshodan, python script

	var wg sync.WaitGroup
	results := make(chan Result, totalSources)

	// Run command-line tools
	for _, tool := range tools {
		wg.Add(1)
		go func(toolName string, cmdArgs []string) {
			defer wg.Done()
			e.runTool(toolName, cmdArgs, results)
		}(tool.name, tool.cmd)
	}

	// Run Web Archive (Wayback Machine)
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.runWaybackMachine(results)
	}()

	// Run crt.sh (Certificate Transparency)
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.runCrtSh(results)
	}()

	// Run subshodan if API key is provided
	if e.ShodanAPIKey != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.runSubshodan(results)
		}()
	} else {
		// Send empty result if no API key
		results <- Result{Tool: "subshodan", Error: fmt.Errorf("no API key provided")}
	}

	// Run Python subdomain-enum script if it exists
	if _, err := os.Stat(e.PythonScript); err == nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.runPythonScript(results)
		}()
	} else {
		// Silently skip if script doesn't exist (don't report as error)
		// No result sent - tool won't appear in output
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

// runWaybackMachine fetches subdomains from Web Archive
func (e *Enumerator) runWaybackMachine(results chan<- Result) {
	start := time.Now()
	result := Result{
		Tool:     "wayback",
		Duration: time.Since(start),
	}

	url := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=text&fl=original&collapse=urlkey", e.Domain)

	resp, err := http.Get(url)
	if err != nil {
		result.Error = err
		results <- result
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Error = err
		results <- result
		return
	}

	// Extract domains from URLs
	subdomainMap := make(map[string]bool)
	lines := strings.Split(string(body), "\n")

	re := regexp.MustCompile(`https?://([^/]+)`)
	for _, line := range lines {
		matches := re.FindStringSubmatch(line)
		if len(matches) > 1 {
			domain := strings.TrimPrefix(matches[1], "www.")
			if strings.HasSuffix(domain, "."+e.Domain) || domain == e.Domain {
				subdomainMap[domain] = true
			}
		}
	}

	for subdomain := range subdomainMap {
		result.Subdomains = append(result.Subdomains, subdomain)
	}

	result.Duration = time.Since(start)
	results <- result
}

// runCrtSh fetches subdomains from Certificate Transparency logs
func (e *Enumerator) runCrtSh(results chan<- Result) {
	start := time.Now()
	result := Result{
		Tool:     "crt.sh",
		Duration: time.Since(start),
	}

	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", e.Domain)

	resp, err := http.Get(url)
	if err != nil {
		result.Error = err
		results <- result
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Error = err
		results <- result
		return
	}

	// Check if response is HTML (error page) instead of JSON
	bodyStr := string(body)
	if strings.HasPrefix(strings.TrimSpace(bodyStr), "<") {
		result.Error = fmt.Errorf("rate limited or API unavailable")
		results <- result
		return
	}

	// Parse JSON response
	var certs []struct {
		NameValue string `json:"name_value"`
	}

	if err := json.Unmarshal(body, &certs); err != nil {
		result.Error = fmt.Errorf("invalid response format")
		results <- result
		return
	}

	// Extract unique subdomains
	subdomainMap := make(map[string]bool)
	for _, cert := range certs {
		domains := strings.Split(cert.NameValue, "\n")
		for _, domain := range domains {
			domain = strings.TrimSpace(domain)
			domain = strings.Replace(domain, "*.", "", -1)
			if domain != "" && (strings.HasSuffix(domain, "."+e.Domain) || domain == e.Domain) {
				subdomainMap[domain] = true
			}
		}
	}

	for subdomain := range subdomainMap {
		result.Subdomains = append(result.Subdomains, subdomain)
	}

	result.Duration = time.Since(start)
	results <- result
}

// runSubshodan runs subshodan tool with Shodan API
func (e *Enumerator) runSubshodan(results chan<- Result) {
	start := time.Now()
	result := Result{
		Tool:     "subshodan",
		Duration: time.Since(start),
	}

	cmd := exec.Command("subshodan", "-d", e.Domain, "-s", e.ShodanAPIKey)
	output, err := cmd.Output()

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

	result.Duration = time.Since(start)
	results <- result
}

// runPythonScript runs the Python subdomain enumeration script
func (e *Enumerator) runPythonScript(results chan<- Result) {
	start := time.Now()
	result := Result{
		Tool:     "python-enum",
		Duration: time.Since(start),
	}

	// Create temporary output file
	tempFile := filepath.Join(e.OutputDir, "python-temp.txt")
	defer os.Remove(tempFile)

	// Prepare input for the Python script
	// The script asks for: 1) output file name, 2) domain name
	input := fmt.Sprintf("%s\n%s\n", tempFile, e.Domain)

	cmd := exec.Command("python3", e.PythonScript)
	cmd.Stdin = strings.NewReader(input)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// Silently skip - don't report error
		// The script likely has API issues or requires authentication
		return
	}

	// Read subdomains from the temp file
	if _, err := os.Stat(tempFile); os.IsNotExist(err) {
		// Script didn't create output - silently skip
		return
	}

	file, err := os.Open(tempFile)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			result.Subdomains = append(result.Subdomains, line)
		}
	}

	// Only send result if we actually found subdomains
	if len(result.Subdomains) > 0 {
		result.Duration = time.Since(start)
		results <- result
	}
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

	return liveSubs, nil
}

// runVHostFuzzing performs virtual host fuzzing to discover hidden subdomains
func (e *Enumerator) runVHostFuzzing(knownSubdomains []string) ([]string, error) {
	cyan := color.New(color.FgCyan)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)

	cyan.Println("→ Collecting IPs for VHost fuzzing...")

	// Step 1: Extract IPs from known subdomains
	subdomainIPs := e.extractIPsFromSubdomains(knownSubdomains)
	cyan.Printf("→ Extracted %d unique IPs from subdomains\n", len(subdomainIPs))

	// Step 2: Get IPs from Shodan via SSL certificates
	shodanIPs := e.getIPsFromShodan()
	cyan.Printf("→ Found %d IPs from Shodan SSL certificates (for VHost fuzzing)\n", len(shodanIPs))

	// Combine all IPs
	allIPs := e.deduplicateIPs(subdomainIPs, shodanIPs)

	if len(allIPs) == 0 {
		return nil, fmt.Errorf("no IPs found for VHost fuzzing")
	}

	cyan.Printf("→ Total unique IPs: %d\n", len(allIPs))

	// Step 3: Filter out CDN/Cloud IPs
	filteredIPs := e.filterCDNCloudIPs(allIPs)
	if len(filteredIPs) < len(allIPs) {
		yellow.Printf("→ Filtered out %d CDN/Cloud IPs\n", len(allIPs)-len(filteredIPs))
	}

	if len(filteredIPs) == 0 {
		return nil, fmt.Errorf("no non-CDN IPs available for VHost fuzzing")
	}

	// Step 4: Limit to top 50 most common IPs
	targetIPs := e.selectTopIPs(filteredIPs, knownSubdomains, 50)
	cyan.Printf("→ Selected top %d IPs for VHost fuzzing\n", len(targetIPs))

	// Check if VHost wordlist exists
	if _, err := os.Stat(e.VHostWordlist); os.IsNotExist(err) {
		yellow.Printf("⚠ VHost wordlist not found: %s\n", e.VHostWordlist)
		yellow.Println("→ Using main wordlist (this may be slower)")
		e.VHostWordlist = e.Wordlist
	}

	// Step 5: Run VHost fuzzing on selected IPs
	cyan.Printf("→ Starting VHost fuzzing on %d IPs...\n", len(targetIPs))

	var newSubdomains []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Limit concurrent ffuf instances to avoid overwhelming the system
	semaphore := make(chan struct{}, 5)

	for idx, ip := range targetIPs {
		wg.Add(1)
		go func(targetIP string, index int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Progress tracking
			cyan.Printf("  [%d/%d] Testing %s\n", index+1, len(targetIPs), targetIP)

			subs := e.fuzzVHost(targetIP)
			if len(subs) > 0 {
				mu.Lock()
				newSubdomains = append(newSubdomains, subs...)
				green.Printf("    ✓ Found %d potential vhosts on %s\n", len(subs), targetIP)
				mu.Unlock()
			}
		}(ip, idx)
	}

	wg.Wait()

	// Deduplicate and filter out already known subdomains
	uniqueNew := e.filterNewSubdomains(newSubdomains, knownSubdomains)

	if len(uniqueNew) > 0 {
		green.Printf("✓ VHost fuzzing discovered %d new subdomains\n", len(uniqueNew))
	}

	return uniqueNew, nil
}

// extractIPsFromSubdomains resolves subdomains to IPs
func (e *Enumerator) extractIPsFromSubdomains(subdomains []string) []string {
	ipMap := make(map[string]bool)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Limit concurrent resolutions
	semaphore := make(chan struct{}, 50)

	for _, subdomain := range subdomains {
		wg.Add(1)
		go func(sub string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Remove protocol if present
			sub = strings.TrimPrefix(sub, "http://")
			sub = strings.TrimPrefix(sub, "https://")
			sub = strings.Split(sub, "/")[0]

			// Use dig to resolve
			cmd := exec.Command("dig", "+short", sub, "A")
			output, err := cmd.Output()
			if err != nil {
				return
			}

			// Parse IPs from output
			scanner := bufio.NewScanner(strings.NewReader(string(output)))
			for scanner.Scan() {
				ip := strings.TrimSpace(scanner.Text())
				// Validate IP format (basic check)
				if matched, _ := regexp.MatchString(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`, ip); matched {
					mu.Lock()
					ipMap[ip] = true
					mu.Unlock()
				}
			}
		}(subdomain)
	}

	wg.Wait()

	var ips []string
	for ip := range ipMap {
		ips = append(ips, ip)
	}

	return ips
}

// getIPsFromShodan gets IPs from Shodan using SSL certificate search
func (e *Enumerator) getIPsFromShodan() []string {
	if e.ShodanAPIKey == "" {
		return nil
	}

	cyan := color.New(color.FgCyan)
	cyan.Println("→ Querying Shodan for IPs via SSL certificates...")

	// Status codes to search for
	statusCodes := []string{"200", "403", "401", "404", "503", "301", "302", "307"}
	ipMap := make(map[string]bool)

	for _, code := range statusCodes {
		query := fmt.Sprintf(`Ssl.cert.subject.CN:"%s" %s`, e.Domain, code)

		cmd := exec.Command("shodan", "search", query, "--fields", "ip_str")
		output, err := cmd.Output()

		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(strings.NewReader(string(output)))
		for scanner.Scan() {
			ip := strings.TrimSpace(scanner.Text())
			if ip != "" {
				ipMap[ip] = true
			}
		}
	}

	var ips []string
	for ip := range ipMap {
		ips = append(ips, ip)
	}

	return ips
}

// filterCDNCloudIPs filters out known CDN and Cloud provider IPs
func (e *Enumerator) filterCDNCloudIPs(ips []string) []string {
	// Common CDN/Cloud IP ranges (simplified check)
	cdnPrefixes := []string{
		"104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.", "104.23.", "104.24.", "104.25.", "104.26.", "104.27.", "104.28.", "104.29.", "104.30.", "104.31.", // Cloudflare
		"172.64.", "172.65.", "172.66.", "172.67.", "172.68.", "172.69.", "172.70.", "172.71.", // Cloudflare
		"173.245.", "103.21.", "103.22.", "103.31.", "141.101.", "108.162.", "190.93.", "188.114.", "197.234.", "198.41.", // Cloudflare
		"13.32.", "13.33.", "13.35.", "99.84.", "143.204.", "144.220.", // CloudFront
		"54.", "3.", "52.", "18.", "35.", // AWS (broad match)
		"34.", "35.", "104.154.", "104.155.", "104.196.", "104.197.", "104.198.", "104.199.", // Google Cloud
		"13.64.", "13.65.", "13.66.", "13.67.", "13.68.", "13.69.", "13.70.", "13.71.", "13.72.", "13.73.", "13.74.", "13.75.", // Azure
		"40.", "52.", "104.", "137.", "138.", "139.", "168.", // Azure (broad match)
		"151.101.", "185.199.", // Fastly
		"192.229.", "205.251.", // Akamai/AWS
	}

	var filtered []string
	for _, ip := range ips {
		isCDN := false
		for _, prefix := range cdnPrefixes {
			if strings.HasPrefix(ip, prefix) {
				isCDN = true
				break
			}
		}
		if !isCDN {
			filtered = append(filtered, ip)
		}
	}

	return filtered
}

// selectTopIPs selects the top N most frequently occurring IPs
func (e *Enumerator) selectTopIPs(ips []string, subdomains []string, limit int) []string {
	// Count how many subdomains point to each IP
	ipCount := make(map[string]int)

	// Build a map of subdomain -> IP for quick lookup
	subToIP := make(map[string]string)
	for _, subdomain := range subdomains {
		// Clean subdomain
		sub := strings.TrimPrefix(subdomain, "http://")
		sub = strings.TrimPrefix(sub, "https://")
		sub = strings.Split(sub, "/")[0]

		// Quick DNS lookup
		cmd := exec.Command("dig", "+short", sub, "A")
		output, err := cmd.Output()
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(strings.NewReader(string(output)))
		for scanner.Scan() {
			ip := strings.TrimSpace(scanner.Text())
			if matched, _ := regexp.MatchString(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`, ip); matched {
				subToIP[sub] = ip
				ipCount[ip]++
				break
			}
		}
	}

	// Create a slice of IP with their counts
	type ipWithCount struct {
		ip    string
		count int
	}

	var ipCounts []ipWithCount
	for _, ip := range ips {
		ipCounts = append(ipCounts, ipWithCount{
			ip:    ip,
			count: ipCount[ip],
		})
	}

	// Sort by count (descending)
	sort.Slice(ipCounts, func(i, j int) bool {
		return ipCounts[i].count > ipCounts[j].count
	})

	// Select top N
	result := make([]string, 0, limit)
	for i := 0; i < len(ipCounts) && i < limit; i++ {
		result = append(result, ipCounts[i].ip)
	}

	return result
}

// fuzzVHost runs ffuf for VHost fuzzing on a single IP
func (e *Enumerator) fuzzVHost(ip string) []string {
	// Create temp output file for ffuf results
	tempFile := filepath.Join(e.OutputDir, fmt.Sprintf("vhost-ffuf-%s.txt", strings.Replace(ip, ".", "-", -1)))
	defer os.Remove(tempFile)

	// Run ffuf for VHost fuzzing
	// Using VHost wordlist and filtering by status codes
	cmd := exec.Command("ffuf",
		"-w", e.VHostWordlist,
		"-u", fmt.Sprintf("http://%s", ip),
		"-H", fmt.Sprintf("Host: FUZZ.%s", e.Domain),
		"-mc", "200,403,401,404,503,301,302,307",
		"-o", tempFile,
		"-of", "json",
		"-t", "50",
		"-timeout", "10",
		"-s", // Silent mode
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return nil
	}

	// Read and parse ffuf JSON output
	data, err := os.ReadFile(tempFile)
	if err != nil {
		return nil
	}

	var ffufResult struct {
		Results []struct {
			Input struct {
				FUZZ string `json:"FUZZ"`
			} `json:"input"`
			Status int `json:"status"`
			Length int `json:"length"`
		} `json:"results"`
	}

	if err := json.Unmarshal(data, &ffufResult); err != nil {
		return nil
	}

	// Extract subdomains from results
	var subdomains []string
	for _, result := range ffufResult.Results {
		if result.Input.FUZZ != "" {
			subdomain := result.Input.FUZZ + "." + e.Domain
			subdomains = append(subdomains, subdomain)
		}
	}

	return subdomains
}

// deduplicateIPs combines and deduplicates IP lists
func (e *Enumerator) deduplicateIPs(lists ...[]string) []string {
	ipMap := make(map[string]bool)

	for _, list := range lists {
		for _, ip := range list {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				ipMap[ip] = true
			}
		}
	}

	var unique []string
	for ip := range ipMap {
		unique = append(unique, ip)
	}

	return unique
}

// filterNewSubdomains returns only new subdomains not in known list
func (e *Enumerator) filterNewSubdomains(discovered, known []string) []string {
	knownMap := make(map[string]bool)
	for _, sub := range known {
		knownMap[strings.ToLower(strings.TrimSpace(sub))] = true
	}

	newMap := make(map[string]bool)
	for _, sub := range discovered {
		subLower := strings.ToLower(strings.TrimSpace(sub))
		if !knownMap[subLower] && subLower != "" {
			newMap[subLower] = true
		}
	}

	var newSubs []string
	for sub := range newMap {
		newSubs = append(newSubs, sub)
	}

	sort.Strings(newSubs)
	return newSubs
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
