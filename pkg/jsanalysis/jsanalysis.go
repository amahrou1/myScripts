package jsanalysis

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/fatih/color"
)

type Analyzer struct {
	OutputDir    string
	Domain       string
	Concurrency  int // Max concurrent JS file processing
	UseTrufflehog bool // Enable deep secret scanning with trufflehog
	Verbose      bool
}

// NewAnalyzer creates a new JS analyzer
func NewAnalyzer(outputDir, domain string) *Analyzer {
	return &Analyzer{
		OutputDir:    outputDir,
		Domain:       domain,
		Concurrency:  10, // Process 10 JS files concurrently
		UseTrufflehog: true,
		Verbose:      true,
	}
}

// Run executes all JS analysis tasks
func (a *Analyzer) Run(liveJSFile string) error {
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)
	red := color.New(color.FgRed, color.Bold)

	yellow.Println("\n═══════════════════════════════════════════════════════")
	yellow.Println("[STEP 2.3] JavaScript File Analysis")
	yellow.Println("═══════════════════════════════════════════════════════")

	// Check if live-js.txt exists
	if _, err := os.Stat(liveJSFile); os.IsNotExist(err) {
		yellow.Printf("⚠ No JavaScript files found: %s\n", liveJSFile)
		yellow.Println("→ Skipping JavaScript analysis")
		return nil
	}

	// Check required tools
	cyan.Println("→ Checking required tools...")
	if err := a.checkTools(); err != nil {
		red.Printf("✗ Missing required tools: %v\n", err)
		yellow.Println("→ Install with: go install github.com/BishopFox/jsluice/cmd/jsluice@latest")
		if a.UseTrufflehog {
			yellow.Println("→ Install trufflehog: https://github.com/trufflesecurity/trufflehog")
		}
		return err
	}
	green.Println("✓ All required tools are available")

	// Load JS URLs
	jsURLs, err := a.readLines(liveJSFile)
	if err != nil {
		return fmt.Errorf("failed to read JS file: %v", err)
	}

	if len(jsURLs) == 0 {
		yellow.Println("⚠ No JavaScript URLs to analyze")
		return nil
	}

	cyan.Printf("→ Found %d JavaScript files to analyze\n", len(jsURLs))

	// Task 1: Extract secrets and sensitive information
	cyan.Println("\n→ Task 1: Extracting secrets and sensitive information...")
	if err := a.extractSecrets(jsURLs); err != nil {
		yellow.Printf("⚠ Secret extraction error: %v\n", err)
	} else {
		green.Println("✓ Secret extraction complete")
	}

	// Task 2: Extract endpoints for fuzzing
	cyan.Println("\n→ Task 2: Extracting endpoints for fuzzing...")
	if err := a.extractEndpoints(jsURLs); err != nil {
		yellow.Printf("⚠ Endpoint extraction error: %v\n", err)
	} else {
		green.Println("✓ Endpoint extraction complete")
	}

	// Task 3: Extract domain-specific links
	cyan.Println("\n→ Task 3: Extracting domain-specific links...")
	if err := a.extractDomainLinks(jsURLs); err != nil {
		yellow.Printf("⚠ Domain link extraction error: %v\n", err)
	} else {
		green.Println("✓ Domain link extraction complete")
	}

	yellow.Println("\n═══════════════════════════════════════════════════════")
	green.Println("         JAVASCRIPT ANALYSIS COMPLETE")
	yellow.Println("═══════════════════════════════════════════════════════")

	return nil
}

// checkTools verifies required tools are installed
func (a *Analyzer) checkTools() error {
	requiredTools := []string{
		"jsluice",
		"httpx",
		"curl",
	}

	// Add optional tools
	optionalTools := []string{}
	if a.UseTrufflehog {
		optionalTools = append(optionalTools, "trufflehog")
	}

	var missing []string
	for _, tool := range requiredTools {
		if _, err := exec.LookPath(tool); err != nil {
			missing = append(missing, tool)
		}
	}

	// Check optional tools (warn but don't fail)
	var missingOptional []string
	for _, tool := range optionalTools {
		if _, err := exec.LookPath(tool); err != nil {
			missingOptional = append(missingOptional, tool)
		}
	}

	if len(missingOptional) > 0 {
		yellow := color.New(color.FgYellow)
		yellow.Printf("→ Optional tools missing (will use alternatives): %s\n", strings.Join(missingOptional, ", "))
		// Disable trufflehog if not found
		if strings.Contains(strings.Join(missingOptional, ","), "trufflehog") {
			a.UseTrufflehog = false
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing required tools: %s", strings.Join(missing, ", "))
	}

	return nil
}

// extractSecrets finds secrets, API keys, tokens in JS files
// Output format: URL followed by found secrets
func (a *Analyzer) extractSecrets(jsURLs []string) error {
	cyan := color.New(color.FgCyan)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)
	magenta := color.New(color.FgMagenta)

	secretsFile := filepath.Join(a.OutputDir, "js-secrets.txt")
	file, err := os.Create(secretsFile)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	var mu sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, a.Concurrency)

	totalProcessed := 0
	totalSecrets := 0

	cyan.Printf("→ Processing %d JavaScript files with %d workers...\n", len(jsURLs), a.Concurrency)

	for _, jsURL := range jsURLs {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(url string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			// Download JS content
			content, err := a.downloadJS(url)
			if err != nil {
				yellow.Printf("⚠ Failed to download %s: %v\n", url, err)
				return
			}

			// Extract secrets using jsluice
			secrets := a.extractSecretsFromContent(content, url)

			// If trufflehog is available, use it for deep scanning
			if a.UseTrufflehog {
				truffleSecrets := a.scanWithTrufflehog(content, url)
				secrets = append(secrets, truffleSecrets...)
			}

			// Deduplicate secrets
			secrets = a.deduplicateSecrets(secrets)

			mu.Lock()
			totalProcessed++
			if len(secrets) > 0 {
				totalSecrets += len(secrets)
				// Write URL header
				writer.WriteString(fmt.Sprintf("\n%s\n%s\n", strings.Repeat("=", 80), url))
				writer.WriteString(fmt.Sprintf("%s\n\n", strings.Repeat("=", 80)))

				// Write secrets
				for _, secret := range secrets {
					writer.WriteString(fmt.Sprintf("  %s\n", secret))
				}
				writer.Flush()

				magenta.Printf("→ %s: Found %d secrets\n", url, len(secrets))
			}
			cyan.Printf("\r→ Progress: %d/%d files processed", totalProcessed, len(jsURLs))
			mu.Unlock()
		}(jsURL)
	}

	wg.Wait()
	fmt.Println() // New line after progress

	if totalSecrets > 0 {
		green.Printf("✓ Found %d total secrets/sensitive data\n", totalSecrets)
		green.Printf("✓ Results saved to: %s\n", secretsFile)
	} else {
		cyan.Println("→ No secrets found in JavaScript files")
	}

	return nil
}

// extractEndpoints extracts API endpoints and paths for fuzzing
// Output: Clean paths without domains (e.g., api/admin, test/user)
func (a *Analyzer) extractEndpoints(jsURLs []string) error {
	cyan := color.New(color.FgCyan)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)

	endpointsFile := filepath.Join(a.OutputDir, "endpoints-fuzzing.txt")

	// Use map to store unique endpoints
	endpointMap := make(map[string]bool)
	var mu sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, a.Concurrency)

	totalProcessed := 0

	cyan.Printf("→ Extracting endpoints from %d JavaScript files...\n", len(jsURLs))

	for _, jsURL := range jsURLs {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(url string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			// Download JS content
			content, err := a.downloadJS(url)
			if err != nil {
				return
			}

			// Method 1: Extract endpoints using jsluice and regex patterns
			endpoints := a.extractEndpointsFromContent(content)

			// Method 2: Extract quoted endpoints using grep-like pattern matching
			// This catches patterns like "/api/endpoint" in quotes
			quotedEndpoints := a.extractQuotedEndpoints(content)

			mu.Lock()
			totalProcessed++
			// Add all endpoints from both methods
			for _, endpoint := range endpoints {
				endpointMap[endpoint] = true
			}
			for _, endpoint := range quotedEndpoints {
				endpointMap[endpoint] = true
			}
			cyan.Printf("\r→ Progress: %d/%d files processed, %d unique endpoints found", totalProcessed, len(jsURLs), len(endpointMap))
			mu.Unlock()
		}(jsURL)
	}

	wg.Wait()
	fmt.Println() // New line after progress

	// Convert map to sorted slice
	endpoints := make([]string, 0, len(endpointMap))
	for endpoint := range endpointMap {
		endpoints = append(endpoints, endpoint)
	}

	if len(endpoints) == 0 {
		yellow.Println("⚠ No endpoints found in JavaScript files")
		return nil
	}

	// Save endpoints
	if err := a.writeLines(endpointsFile, endpoints); err != nil {
		return fmt.Errorf("failed to save endpoints: %v", err)
	}

	green.Printf("✓ Extracted %d unique endpoints\n", len(endpoints))
	green.Printf("✓ Results saved to: %s\n", endpointsFile)

	return nil
}

// extractDomainLinks extracts links ending with target domain and verifies them
func (a *Analyzer) extractDomainLinks(jsURLs []string) error {
	cyan := color.New(color.FgCyan)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)

	// Use map to store unique links
	linkMap := make(map[string]bool)
	var mu sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, a.Concurrency)

	totalProcessed := 0

	cyan.Printf("→ Extracting links for domain: %s\n", a.Domain)

	for _, jsURL := range jsURLs {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(url string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			// Download JS content
			content, err := a.downloadJS(url)
			if err != nil {
				return
			}

			// Extract all URLs using jsluice
			urls := a.extractURLsFromContent(content)

			// Filter by domain
			for _, extractedURL := range urls {
				if a.isDomainMatch(extractedURL) {
					mu.Lock()
					linkMap[extractedURL] = true
					mu.Unlock()
				}
			}

			mu.Lock()
			totalProcessed++
			cyan.Printf("\r→ Progress: %d/%d files processed, %d domain links found", totalProcessed, len(jsURLs), len(linkMap))
			mu.Unlock()
		}(jsURL)
	}

	wg.Wait()
	fmt.Println() // New line after progress

	if len(linkMap) == 0 {
		yellow.Printf("⚠ No links found for domain: %s\n", a.Domain)
		return nil
	}

	// Convert map to slice
	links := make([]string, 0, len(linkMap))
	for link := range linkMap {
		links = append(links, link)
	}

	cyan.Printf("→ Found %d unique domain links, verifying with httpx...\n", len(links))

	// Verify links with httpx
	liveLinks, err := a.verifyLinksWithHttpx(links)
	if err != nil {
		return fmt.Errorf("failed to verify links: %v", err)
	}

	if len(liveLinks) == 0 {
		yellow.Println("⚠ No live links found after verification")
		return nil
	}

	// Save live links
	linksFile := filepath.Join(a.OutputDir, "links-js.txt")
	if err := a.writeLines(linksFile, liveLinks); err != nil {
		return fmt.Errorf("failed to save links: %v", err)
	}

	green.Printf("✓ Found %d live domain links\n", len(liveLinks))
	green.Printf("✓ Results saved to: %s\n", linksFile)

	return nil
}

// downloadJS downloads JavaScript content from URL
func (a *Analyzer) downloadJS(url string) (string, error) {
	cmd := exec.Command("curl", "-s", "-L", "--max-time", "30", url)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// extractSecretsFromContent uses jsluice to extract secrets
func (a *Analyzer) extractSecretsFromContent(content, url string) []string {
	var secrets []string

	// Use jsluice to extract secrets
	cmd := exec.Command("jsluice", "secrets")
	cmd.Stdin = strings.NewReader(content)
	output, err := cmd.Output()
	if err != nil {
		return secrets
	}

	// Parse jsluice output
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			secrets = append(secrets, line)
		}
	}

	// Also extract common patterns with regex
	regexSecrets := a.extractSecretsWithRegex(content)
	secrets = append(secrets, regexSecrets...)

	return secrets
}

// extractSecretsWithRegex uses regex patterns to find common secrets
func (a *Analyzer) extractSecretsWithRegex(content string) []string {
	var secrets []string

	patterns := map[string]*regexp.Regexp{
		"API Key":           regexp.MustCompile(`(?i)(api[_-]?key|apikey|api[_-]?secret)[\s]*[=:]["']([a-zA-Z0-9_\-]{20,})["']`),
		"AWS Key":           regexp.MustCompile(`(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
		"Private Key":       regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
		"GitHub Token":      regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
		"Slack Token":       regexp.MustCompile(`xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,32}`),
		"Google API":        regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
		"JWT Token":         regexp.MustCompile(`eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*`),
		"Firebase":          regexp.MustCompile(`(?i)firebase[_-]?(url|api|key|token|secret)[\s]*[=:]["']([^"']{10,})["']`),
		"Database URL":      regexp.MustCompile(`(?i)(mongodb|mysql|postgres|redis)://[^\s"']+`),
		"Authorization":     regexp.MustCompile(`(?i)authorization[\s]*[=:][\s]*["']?(bearer|basic)[\s]+([a-zA-Z0-9_\-\.=]+)["']?`),
	}

	for secretType, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 0 {
				secrets = append(secrets, fmt.Sprintf("[%s] %s", secretType, match[0]))
			}
		}
	}

	return secrets
}

// scanWithTrufflehog uses trufflehog for deep secret scanning
func (a *Analyzer) scanWithTrufflehog(content, url string) []string {
	var secrets []string

	// Save content to temp file
	tempFile := filepath.Join(os.TempDir(), fmt.Sprintf("js_%d.txt", len(url)))
	if err := os.WriteFile(tempFile, []byte(content), 0644); err != nil {
		return secrets
	}
	defer os.Remove(tempFile)

	// Run trufflehog
	cmd := exec.Command("trufflehog", "filesystem", tempFile, "--json")
	output, err := cmd.Output()
	if err != nil {
		return secrets
	}

	// Parse trufflehog JSON output (simplified)
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Raw") || strings.Contains(line, "Secret") {
			secrets = append(secrets, fmt.Sprintf("[Trufflehog] %s", line))
		}
	}

	return secrets
}

// extractEndpointsFromContent uses jsluice to extract endpoints
func (a *Analyzer) extractEndpointsFromContent(content string) []string {
	var endpoints []string
	endpointMap := make(map[string]bool)

	// Use jsluice to extract URLs
	cmd := exec.Command("jsluice", "urls")
	cmd.Stdin = strings.NewReader(content)
	output, err := cmd.Output()
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(output))
		for scanner.Scan() {
			url := strings.TrimSpace(scanner.Text())
			// Extract path from URL
			path := a.extractPathFromURL(url)
			if path != "" && path != "/" {
				endpointMap[path] = true
			}
		}
	}

	// Also use regex patterns for path extraction
	pathPatterns := []*regexp.Regexp{
		regexp.MustCompile(`["'](/[a-zA-Z0-9_\-/{}:]+)["']`),
		regexp.MustCompile(`(api/[a-zA-Z0-9_\-/]+)`),
		regexp.MustCompile(`(/v[0-9]+/[a-zA-Z0-9_\-/]+)`),
	}

	for _, pattern := range pathPatterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 {
				path := a.cleanEndpoint(match[1])
				if path != "" && path != "/" {
					endpointMap[path] = true
				}
			}
		}
	}

	// Convert map to slice
	for endpoint := range endpointMap {
		endpoints = append(endpoints, endpoint)
	}

	return endpoints
}

// extractQuotedEndpoints extracts endpoints from quoted strings in JS content
// This matches patterns like "/api/endpoint" and extracts clean paths
func (a *Analyzer) extractQuotedEndpoints(content string) []string {
	endpointMap := make(map[string]bool)

	// Pattern to match quoted strings starting with / (like grep -oh "\"\/[a-zA-Z0-9_/?=&]*\"")
	// Matches: "/api/v1/users", "/endpoint?param=value", etc.
	quotedPathPattern := regexp.MustCompile(`"(\/[a-zA-Z0-9_\-/?=&]+)"`)

	matches := quotedPathPattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			endpoint := match[1] // Get the captured group (without quotes)

			// Remove leading / (like sed 's#^/##')
			endpoint = strings.TrimPrefix(endpoint, "/")

			// Clean the endpoint (remove query params, fragments)
			endpoint = a.cleanEndpoint(endpoint)

			// Only add non-empty, valid endpoints
			if endpoint != "" && endpoint != "/" {
				endpointMap[endpoint] = true
			}
		}
	}

	// Convert map to slice
	endpoints := make([]string, 0, len(endpointMap))
	for endpoint := range endpointMap {
		endpoints = append(endpoints, endpoint)
	}

	return endpoints
}

// extractURLsFromContent uses jsluice to extract all URLs
func (a *Analyzer) extractURLsFromContent(content string) []string {
	var urls []string

	// Use jsluice
	cmd := exec.Command("jsluice", "urls")
	cmd.Stdin = strings.NewReader(content)
	output, err := cmd.Output()
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(output))
		for scanner.Scan() {
			url := strings.TrimSpace(scanner.Text())
			if url != "" {
				urls = append(urls, url)
			}
		}
	}

	// Also extract URLs with regex
	urlPattern := regexp.MustCompile(`https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+`)
	matches := urlPattern.FindAllString(content, -1)
	urls = append(urls, matches...)

	return urls
}

// extractPathFromURL extracts the path component from a URL
func (a *Analyzer) extractPathFromURL(url string) string {
	// Remove protocol
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")

	// Find first slash
	slashIndex := strings.Index(url, "/")
	if slashIndex == -1 {
		return ""
	}

	// Extract path
	path := url[slashIndex:]

	// Remove query parameters
	if idx := strings.Index(path, "?"); idx != -1 {
		path = path[:idx]
	}

	// Remove fragments
	if idx := strings.Index(path, "#"); idx != -1 {
		path = path[:idx]
	}

	return a.cleanEndpoint(path)
}

// cleanEndpoint cleans and normalizes endpoint paths
func (a *Analyzer) cleanEndpoint(endpoint string) string {
	// Remove quotes
	endpoint = strings.Trim(endpoint, "\"'")

	// Remove trailing slash
	endpoint = strings.TrimSuffix(endpoint, "/")

	// Remove leading slash for output format
	endpoint = strings.TrimPrefix(endpoint, "/")

	// Skip if empty or just root
	if endpoint == "" || endpoint == "/" {
		return ""
	}

	// Skip common file extensions that aren't useful for fuzzing
	skipExtensions := []string{".js", ".css", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".eot", ".ico"}
	for _, ext := range skipExtensions {
		if strings.HasSuffix(strings.ToLower(endpoint), ext) {
			return ""
		}
	}

	return endpoint
}

// isDomainMatch checks if URL ends with target domain
func (a *Analyzer) isDomainMatch(url string) bool {
	// Remove protocol
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")

	// Extract domain part
	domain := url
	if idx := strings.Index(url, "/"); idx != -1 {
		domain = url[:idx]
	}

	// Remove port
	if idx := strings.Index(domain, ":"); idx != -1 {
		domain = domain[:idx]
	}

	// Check if domain ends with target domain
	return strings.HasSuffix(domain, a.Domain)
}

// verifyLinksWithHttpx verifies URLs with httpx
func (a *Analyzer) verifyLinksWithHttpx(urls []string) ([]string, error) {
	// Create temp file with URLs
	tempFile := filepath.Join(a.OutputDir, "temp-links-verify.txt")
	if err := a.writeLines(tempFile, urls); err != nil {
		return nil, err
	}
	defer os.Remove(tempFile)

	// Run httpx
	cmd := exec.Command("httpx", "-l", tempFile, "-silent", "-no-color")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("httpx verification failed: %v", err)
	}

	// Parse output
	var liveURLs []string
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url != "" {
			liveURLs = append(liveURLs, url)
		}
	}

	return liveURLs, nil
}

// deduplicateSecrets removes duplicate secrets
func (a *Analyzer) deduplicateSecrets(secrets []string) []string {
	seen := make(map[string]bool)
	var unique []string

	for _, secret := range secrets {
		if !seen[secret] {
			seen[secret] = true
			unique = append(unique, secret)
		}
	}

	return unique
}

// readLines reads lines from a file
func (a *Analyzer) readLines(filename string) ([]string, error) {
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
func (a *Analyzer) writeLines(filename string, lines []string) error {
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
