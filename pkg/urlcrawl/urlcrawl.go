package urlcrawl

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

type Scanner struct {
	OutputDir         string
	Domain            string // Target domain for filtering
	VirusTotalKey     string
	OTXKey            string
	EnableActive      bool
	GospiderThreads   int
	Verbose           bool

	// Global timeout for entire URL crawling phase
	PhaseTimeout int // timeout in minutes for entire phase

	// Individual tool timeouts
	WaybackurlsTimeout  int
	GauTimeout          int
	KatanaTimeout       int
	KatanaParamsTimeout int
	GospiderTimeout     int
	WebArchiveTimeout   int
}

// NewScanner creates a new URL crawler
func NewScanner(outputDir, domain string) *Scanner {
	return &Scanner{
		OutputDir:       outputDir,
		Domain:          domain,
		EnableActive:    true, // katana enabled by default
		GospiderThreads: 10,   // reasonable concurrency
		Verbose:         true,

		// Default timeouts (10 hours for phase, 5 hours per tool)
		PhaseTimeout:        600, // 10 hours
		WaybackurlsTimeout:  300, // 5 hours
		GauTimeout:          300, // 5 hours
		KatanaTimeout:       300, // 5 hours
		KatanaParamsTimeout: 300, // 5 hours
		GospiderTimeout:     300, // 5 hours
		WebArchiveTimeout:   300, // 5 hours
	}
}

// Run executes URL crawling on live subdomains
func (s *Scanner) Run(liveSubsFile string) error {
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)
	red := color.New(color.FgRed, color.Bold)

	yellow.Println("\n═══════════════════════════════════════════════════════")
	yellow.Println("[STEP 2] URL Crawling & Discovery")
	yellow.Println("═══════════════════════════════════════════════════════")

	// Check if live subdomains file exists
	if _, err := os.Stat(liveSubsFile); os.IsNotExist(err) {
		yellow.Printf("⚠ Live subdomains file not found: %s\n", liveSubsFile)
		return fmt.Errorf("live subdomains file not found")
	}

	// Load API keys from environment
	s.VirusTotalKey = os.Getenv("VT_API_KEY")
	s.OTXKey = os.Getenv("ALIEN_API_KEY")

	if s.VirusTotalKey != "" {
		cyan.Println("→ VirusTotal API key detected")
	}
	if s.OTXKey != "" {
		cyan.Println("→ AlienVault OTX API key detected")
	}

	// Check required tools (fail fast)
	cyan.Println("→ Checking required tools...")
	if err := s.checkTools(); err != nil {
		red.Printf("✗ Missing required tools: %v\n", err)
		return err
	}
	green.Println("✓ All required tools are available")

	// Load subdomains
	subdomains, err := s.readLines(liveSubsFile)
	if err != nil {
		return fmt.Errorf("failed to read subdomains: %v", err)
	}
	cyan.Printf("→ Loaded %d live subdomains for URL crawling\n", len(subdomains))

	// Create temporary directory for tool outputs
	tempDir := filepath.Join(s.OutputDir, "temp-urlcrawl")
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return fmt.Errorf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir) // Clean up temp files

	// Create context with global phase timeout
	var allURLs []string
	if s.PhaseTimeout > 0 {
		phaseTimeout := time.Duration(s.PhaseTimeout) * time.Minute
		ctx, cancel := context.WithTimeout(context.Background(), phaseTimeout)
		defer cancel()

		cyan.Printf("\n→ Running URL discovery tools (max %d minutes for entire phase)...\n", s.PhaseTimeout)

		// Run with timeout
		done := make(chan struct{})
		var toolErr error
		go func() {
			allURLs, toolErr = s.runAllTools(subdomains, tempDir)
			close(done)
		}()

		select {
		case <-done:
			// Completed normally
			if toolErr != nil {
				return toolErr
			}
		case <-ctx.Done():
			// Timeout occurred
			yellow.Printf("\n⚠ URL crawling phase timed out after %d minutes\n", s.PhaseTimeout)
			yellow.Println("  Continuing with partial results...")
			// Wait a bit for cleanup
			time.Sleep(2 * time.Second)
		}
	} else {
		// No timeout
		cyan.Println("\n→ Running URL discovery tools (this may take a while)...")
		var toolErr error
		allURLs, toolErr = s.runAllTools(subdomains, tempDir)
		if toolErr != nil {
			return toolErr
		}
	}

	if len(allURLs) == 0 {
		yellow.Println("⚠ No URLs discovered from any tools")
		return nil
	}

	cyan.Printf("→ Collected %d URLs from all tools\n", len(allURLs))

	// Deduplicate URLs
	cyan.Println("→ Deduplicating URLs with uro and sort...")
	uniqueURLs, err := s.deduplicateURLs(allURLs)
	if err != nil {
		yellow.Printf("⚠ Deduplication error: %v\n", err)
		uniqueURLs = s.simpleDedup(allURLs) // Fallback to simple dedup
	}

	cyan.Printf("→ Found %d unique URLs after deduplication\n", len(uniqueURLs))

	// Save all unique URLs
	uniqueURLsFile := filepath.Join(s.OutputDir, "unique-urls.txt")
	if err := s.writeLines(uniqueURLsFile, uniqueURLs); err != nil {
		return fmt.Errorf("failed to save unique URLs: %v", err)
	}
	green.Printf("✓ Saved unique URLs to: %s\n", uniqueURLsFile)

	// Filter and verify URLs
	cyan.Println("\n→ Filtering and verifying URLs...")

	// Extract and verify URLs with parameters
	cyan.Println("→ Extracting URLs with parameters...")
	paramURLs, err := s.filterParamURLs(uniqueURLs)
	if err != nil {
		yellow.Printf("⚠ Error filtering param URLs: %v\n", err)
	} else if len(paramURLs) > 0 {
		cyan.Printf("→ Found %d URLs with parameters, verifying with httpx...\n", len(paramURLs))
		liveParamURLs, err := s.verifyWithHttpx(paramURLs)
		if err != nil {
			yellow.Printf("⚠ Error verifying param URLs: %v\n", err)
		} else if len(liveParamURLs) > 0 {
			paramsFile := filepath.Join(s.OutputDir, "params.txt")
			if err := s.writeLines(paramsFile, liveParamURLs); err == nil {
				green.Printf("✓ Saved %d live parameter URLs to: %s\n", len(liveParamURLs), paramsFile)
			}
		}
	}

	// Extract and verify JavaScript files
	cyan.Println("→ Extracting JavaScript files...")
	jsURLs, err := s.filterJSURLs(uniqueURLs)
	if err != nil {
		yellow.Printf("⚠ Error filtering JS URLs: %v\n", err)
	} else if len(jsURLs) > 0 {
		cyan.Printf("→ Found %d JavaScript files, verifying with httpx...\n", len(jsURLs))
		liveJSURLs, err := s.verifyWithHttpxStatus(jsURLs, "200")
		if err != nil {
			yellow.Printf("⚠ Error verifying JS URLs: %v\n", err)
		} else if len(liveJSURLs) > 0 {
			jsFile := filepath.Join(s.OutputDir, "live-js.txt")
			if err := s.writeLines(jsFile, liveJSURLs); err == nil {
				green.Printf("✓ Saved %d live JavaScript files to: %s\n", len(liveJSURLs), jsFile)
			}
		}
	}

	// Extract and verify sensitive files
	cyan.Println("→ Extracting sensitive files...")
	sensitiveURLs, err := s.filterSensitiveURLs(uniqueURLs)
	if err != nil {
		yellow.Printf("⚠ Error filtering sensitive URLs: %v\n", err)
	} else if len(sensitiveURLs) > 0 {
		cyan.Printf("→ Found %d potential sensitive files, verifying with httpx...\n", len(sensitiveURLs))
		liveSensitiveURLs, err := s.verifyWithHttpx(sensitiveURLs)
		if err != nil {
			yellow.Printf("⚠ Error verifying sensitive URLs: %v\n", err)
		} else if len(liveSensitiveURLs) > 0 {
			sensitiveFile := filepath.Join(s.OutputDir, "sensitive-files.txt")
			if err := s.writeLines(sensitiveFile, liveSensitiveURLs); err == nil {
				green.Printf("✓ Saved %d live sensitive files to: %s\n", len(liveSensitiveURLs), sensitiveFile)
			}
		}
	}

	yellow.Println("\n═══════════════════════════════════════════════════════")
	green.Println("         URL CRAWLING COMPLETE")
	yellow.Println("═══════════════════════════════════════════════════════")

	return nil
}

// checkTools verifies all required tools are installed
func (s *Scanner) checkTools() error {
	requiredTools := []string{
		"waybackurls",
		"gau",
		"katana",
		"gospider",
		"httpx",
		"uro",
		"sort",
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

// runAllTools runs all URL discovery tools in parallel
func (s *Scanner) runAllTools(subdomains []string, tempDir string) ([]string, error) {
	cyan := color.New(color.FgCyan)
	yellow := color.New(color.FgYellow)
	green := color.New(color.FgGreen)

	var wg sync.WaitGroup
	var mu sync.Mutex
	allURLs := []string{}
	completedTools := 0
	totalTools := 6 // waybackurls, gau, katana, katana-params, gospider, webarchive-cdx

	// Tool runner helper
	runTool := func(name string, runner func() ([]string, error)) {
		defer wg.Done()
		cyan.Printf("  → Running %s...\n", name)
		urls, err := runner()

		mu.Lock()
		completedTools++
		progress := (completedTools * 100) / totalTools
		mu.Unlock()

		if err != nil {
			yellow.Printf("  ⚠ %s failed, skipping: %v\n", name, err)
			cyan.Printf("  → Overall progress: %d%% (%d/%d tools completed)\n", progress, completedTools, totalTools)
			return
		}

		mu.Lock()
		allURLs = append(allURLs, urls...)
		mu.Unlock()

		green.Printf("  ✓ %s: found %d URLs\n", name, len(urls))
		cyan.Printf("  → Overall progress: %d%% (%d/%d tools completed)\n", progress, completedTools, totalTools)
	}

	// Run waybackurls
	wg.Add(1)
	go runTool("waybackurls", func() ([]string, error) {
		return s.runWaybackurls(subdomains, tempDir)
	})

	// Run gau
	wg.Add(1)
	go runTool("gau", func() ([]string, error) {
		return s.runGau(subdomains, tempDir)
	})

	// Run katana (default crawling)
	if s.EnableActive {
		wg.Add(1)
		go runTool("katana", func() ([]string, error) {
			return s.runKatana(subdomains, tempDir)
		})

		// Run katana for parameters
		wg.Add(1)
		go runTool("katana-params", func() ([]string, error) {
			return s.runKatanaParams(subdomains, tempDir)
		})
	}

	// Run gospider
	if s.EnableActive {
		wg.Add(1)
		go runTool("gospider", func() ([]string, error) {
			return s.runGospider(subdomains, tempDir)
		})
	}

	// Run web archive CDX API
	wg.Add(1)
	go runTool("webarchive-cdx", func() ([]string, error) {
		return s.runWebArchiveCDX(subdomains, tempDir)
	})

	wg.Wait()

	return allURLs, nil
}

// runWaybackurls runs waybackurls on subdomains with timeout
func (s *Scanner) runWaybackurls(subdomains []string, tempDir string) ([]string, error) {
	outputFile := filepath.Join(tempDir, "waybackurls.txt")
	file, err := os.Create(outputFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Create context with timeout
	timeout := time.Duration(s.WaybackurlsTimeout) * time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Process domains with timeout
	done := make(chan struct{})
	go func() {
		for _, subdomain := range subdomains {
			// Check if context is cancelled
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Remove http/https prefix for waybackurls
			domain := strings.TrimPrefix(subdomain, "https://")
			domain = strings.TrimPrefix(domain, "http://")
			domain = strings.Split(domain, "/")[0]

			cmd := exec.CommandContext(ctx, "waybackurls", domain)
			output, err := cmd.Output()
			if err != nil {
				continue
			}
			file.Write(output)
		}
		close(done)
	}()

	select {
	case <-done:
		// Completed normally
	case <-ctx.Done():
		// Timeout occurred - return partial results
		yellow := color.New(color.FgYellow)
		yellow.Printf("  ⚠ waybackurls timed out after %d minutes\n", s.WaybackurlsTimeout)
	}

	file.Close()
	return s.readLines(outputFile)
}

// runGau runs gau on subdomains with API keys and timeout
func (s *Scanner) runGau(subdomains []string, tempDir string) ([]string, error) {
	outputFile := filepath.Join(tempDir, "gau.txt")
	inputFile := filepath.Join(tempDir, "gau-input.txt")

	// Clean domains (remove http/https)
	cleanDomains := []string{}
	for _, sub := range subdomains {
		domain := strings.TrimPrefix(sub, "https://")
		domain = strings.TrimPrefix(domain, "http://")
		domain = strings.Split(domain, "/")[0]
		cleanDomains = append(cleanDomains, domain)
	}

	if err := s.writeLines(inputFile, cleanDomains); err != nil {
		return nil, err
	}

	// Create context with timeout
	timeout := time.Duration(s.GauTimeout) * time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "gau",
		"--subs",
		"--providers", "wayback,otx,commoncrawl,urlscan",
		"--o", outputFile,
	)

	// Add API keys via environment
	env := os.Environ()
	if s.VirusTotalKey != "" {
		env = append(env, "VT_API_KEY="+s.VirusTotalKey)
	}
	if s.OTXKey != "" {
		env = append(env, "ALIEN_API_KEY="+s.OTXKey)
	}
	cmd.Env = env

	// Read domains from stdin
	cmd.Stdin = strings.NewReader(strings.Join(cleanDomains, "\n"))

	err := cmd.Run()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			yellow := color.New(color.FgYellow)
			yellow.Printf("  ⚠ gau timed out after %d minutes\n", s.GauTimeout)
			// Return partial results
			if _, statErr := os.Stat(outputFile); statErr == nil {
				return s.readLines(outputFile)
			}
			return []string{}, nil
		}
		return nil, err
	}

	return s.readLines(outputFile)
}

// runKatana runs katana for active crawling with timeout
func (s *Scanner) runKatana(subdomains []string, tempDir string) ([]string, error) {
	outputFile := filepath.Join(tempDir, "katana.txt")
	inputFile := filepath.Join(tempDir, "katana-input.txt")

	if err := s.writeLines(inputFile, subdomains); err != nil {
		return nil, err
	}

	// Create context with timeout
	timeout := time.Duration(s.KatanaTimeout) * time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "katana",
		"-list", inputFile,
		"-duc",    // disable update check
		"-silent",
		"-nc",     // no color
		"-jc",     // javascript crawling
		"-kf",     // known files
		"-fx",     // form extraction
		"-xhr",    // xhr requests
		"-ef", "woff,css,png,svg,jpg,woff2,jpeg,gif,svg",
		"-o", outputFile,
	)

	err := cmd.Run()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			yellow := color.New(color.FgYellow)
			yellow.Printf("  ⚠ katana timed out after %d minutes\n", s.KatanaTimeout)
			if _, statErr := os.Stat(outputFile); statErr == nil {
				return s.readLines(outputFile)
			}
			return []string{}, nil
		}
		return nil, err
	}

	return s.readLines(outputFile)
}

// runKatanaParams runs katana for parameter discovery with timeout
func (s *Scanner) runKatanaParams(subdomains []string, tempDir string) ([]string, error) {
	outputFile := filepath.Join(tempDir, "katana-params.txt")
	inputFile := filepath.Join(tempDir, "katana-params-input.txt")

	if err := s.writeLines(inputFile, subdomains); err != nil {
		return nil, err
	}

	// Create context with timeout
	timeout := time.Duration(s.KatanaParamsTimeout) * time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "katana",
		"-list", inputFile,
		"-fs", "fqdn",
		"-f", "qurl",
		"-jc",
		"-d", "6",
		"-o", outputFile,
	)

	err := cmd.Run()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			yellow := color.New(color.FgYellow)
			yellow.Printf("  ⚠ katana-params timed out after %d minutes\n", s.KatanaParamsTimeout)
			if _, statErr := os.Stat(outputFile); statErr == nil {
				return s.readLines(outputFile)
			}
			return []string{}, nil
		}
		return nil, err
	}

	return s.readLines(outputFile)
}

// runGospider runs gospider for spidering with timeout
func (s *Scanner) runGospider(subdomains []string, tempDir string) ([]string, error) {
	outputFile := filepath.Join(tempDir, "gospider.txt")
	file, err := os.Create(outputFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Create context with timeout
	timeout := time.Duration(s.GospiderTimeout) * time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Run gospider with limited concurrency
	semaphore := make(chan struct{}, s.GospiderThreads)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, subdomain := range subdomains {
		// Check if context is cancelled
		select {
		case <-ctx.Done():
			break
		default:
		}

		wg.Add(1)
		semaphore <- struct{}{}

		go func(sub string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			cmd := exec.CommandContext(ctx, "gospider",
				"-a",
				"-s", sub,
				"-d", "2",
				"-t", "10",
			)

			output, err := cmd.Output()
			if err != nil {
				return
			}

			// Extract URLs from gospider output
			scanner := bufio.NewScanner(strings.NewReader(string(output)))
			for scanner.Scan() {
				line := scanner.Text()
				if strings.Contains(line, "http") {
					parts := strings.Fields(line)
					for _, part := range parts {
						if strings.HasPrefix(part, "http") {
							mu.Lock()
							file.WriteString(part + "\n")
							mu.Unlock()
						}
					}
				}
			}
		}(subdomain)
	}

	// Wait with timeout awareness
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Completed normally
	case <-ctx.Done():
		// Timeout occurred
		yellow := color.New(color.FgYellow)
		yellow.Printf("  ⚠ gospider timed out after %d minutes\n", s.GospiderTimeout)
	}

	file.Close()
	return s.readLines(outputFile)
}

// runWebArchiveCDX runs direct Web Archive CDX API queries with timeout
func (s *Scanner) runWebArchiveCDX(subdomains []string, tempDir string) ([]string, error) {
	outputFile := filepath.Join(tempDir, "webarchive-cdx.txt")
	file, err := os.Create(outputFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Create context with timeout
	timeout := time.Duration(s.WebArchiveTimeout) * time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	done := make(chan struct{})
	go func() {
		for _, subdomain := range subdomains {
			// Check if context is cancelled
			select {
			case <-ctx.Done():
				return
			default:
			}

			domain := strings.TrimPrefix(subdomain, "https://")
			domain = strings.TrimPrefix(domain, "http://")
			domain = strings.Split(domain, "/")[0]

			url := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=text&fl=original&collapse=urlkey", domain)

			cmd := exec.CommandContext(ctx, "curl", "-s", url)
			output, err := cmd.Output()
			if err != nil {
				continue
			}

			file.Write(output)
		}
		close(done)
	}()

	select {
	case <-done:
		// Completed normally
	case <-ctx.Done():
		// Timeout occurred
		yellow := color.New(color.FgYellow)
		yellow.Printf("  ⚠ webarchive-cdx timed out after %d minutes\n", s.WebArchiveTimeout)
	}

	file.Close()
	return s.readLines(outputFile)
}

// deduplicateURLs uses uro and sort to deduplicate URLs
func (s *Scanner) deduplicateURLs(urls []string) ([]string, error) {
	// Write URLs to temp file
	tempFile := filepath.Join(s.OutputDir, "temp-urls-dedup.txt")
	if err := s.writeLines(tempFile, urls); err != nil {
		return nil, err
	}
	defer os.Remove(tempFile)

	// First pass: uro
	uroOutput := filepath.Join(s.OutputDir, "temp-uro-output.txt")
	defer os.Remove(uroOutput)

	cmd := exec.Command("uro")
	inFile, err := os.Open(tempFile)
	if err != nil {
		return nil, err
	}
	defer inFile.Close()

	outFile, err := os.Create(uroOutput)
	if err != nil {
		return nil, err
	}
	defer outFile.Close()

	cmd.Stdin = inFile
	cmd.Stdout = outFile

	if err := cmd.Run(); err != nil {
		return nil, err
	}

	// Second pass: sort -u
	sortedOutput := filepath.Join(s.OutputDir, "temp-sorted-output.txt")
	defer os.Remove(sortedOutput)

	sortCmd := exec.Command("sort", "-u", uroOutput)
	sortOut, err := os.Create(sortedOutput)
	if err != nil {
		return nil, err
	}
	defer sortOut.Close()

	sortCmd.Stdout = sortOut
	if err := sortCmd.Run(); err != nil {
		return nil, err
	}

	return s.readLines(sortedOutput)
}

// simpleDedup is a fallback deduplication method
func (s *Scanner) simpleDedup(urls []string) []string {
	urlMap := make(map[string]bool)
	var unique []string

	for _, url := range urls {
		url = strings.TrimSpace(url)
		if url != "" && !urlMap[url] {
			urlMap[url] = true
			unique = append(unique, url)
		}
	}

	return unique
}

// filterParamURLs filters URLs that contain parameters belonging to target domain only
func (s *Scanner) filterParamURLs(urls []string) ([]string, error) {
	var paramURLs []string
	staticExts := []string{".jpg", ".jpeg", ".gif", ".css", ".tif", ".tiff", ".png", ".ttf", ".woff", ".woff2", ".ico", ".pdf", ".svg", ".txt", ".js"}

	for _, url := range urls {
		url = strings.TrimSpace(url)
		if url == "" {
			continue
		}

		if !strings.Contains(url, "=") {
			continue // No parameters
		}

		// Check if URL ends with static extension
		isStatic := false
		urlLower := strings.ToLower(url)
		for _, ext := range staticExts {
			if strings.Contains(urlLower, ext) {
				isStatic = true
				break
			}
		}

		if isStatic {
			continue
		}

		// Extract domain from URL and check if it belongs to target
		// Remove protocol
		domainPart := url
		if strings.HasPrefix(urlLower, "http://") {
			domainPart = url[7:]
		} else if strings.HasPrefix(urlLower, "https://") {
			domainPart = url[8:]
		}

		// Extract hostname (everything before first /)
		slashIdx := strings.Index(domainPart, "/")
		if slashIdx > 0 {
			domainPart = domainPart[:slashIdx]
		}

		// Remove port if present
		colonIdx := strings.Index(domainPart, ":")
		if colonIdx > 0 {
			domainPart = domainPart[:colonIdx]
		}

		// Check if domain matches target domain or is a subdomain of target
		domainPartLower := strings.ToLower(domainPart)
		targetLower := strings.ToLower(s.Domain)

		if domainPartLower == targetLower || strings.HasSuffix(domainPartLower, "."+targetLower) {
			paramURLs = append(paramURLs, url)
		}
	}

	return paramURLs, nil
}

// filterJSURLs filters JavaScript files belonging to target domain only
func (s *Scanner) filterJSURLs(urls []string) ([]string, error) {
	var jsURLs []string

	for _, url := range urls {
		url = strings.TrimSpace(url)
		if url == "" {
			continue
		}

		// Match .js extension (but not .json)
		if !strings.Contains(url, ".js") || strings.Contains(url, ".json") {
			continue
		}

		// Extract domain from URL and check if it belongs to target
		// URL format: https://subdomain.example.com/path
		urlLower := strings.ToLower(url)

		// Remove protocol
		domainPart := url
		if strings.HasPrefix(urlLower, "http://") {
			domainPart = url[7:]
		} else if strings.HasPrefix(urlLower, "https://") {
			domainPart = url[8:]
		}

		// Extract hostname (everything before first /)
		slashIdx := strings.Index(domainPart, "/")
		if slashIdx > 0 {
			domainPart = domainPart[:slashIdx]
		}

		// Remove port if present
		colonIdx := strings.Index(domainPart, ":")
		if colonIdx > 0 {
			domainPart = domainPart[:colonIdx]
		}

		// Check if domain matches target domain or is a subdomain of target
		domainPartLower := strings.ToLower(domainPart)
		targetLower := strings.ToLower(s.Domain)

		if domainPartLower == targetLower || strings.HasSuffix(domainPartLower, "."+targetLower) {
			jsURLs = append(jsURLs, url)
		}
	}

	return jsURLs, nil
}

// filterSensitiveURLs filters URLs with sensitive file extensions belonging to target domain only
func (s *Scanner) filterSensitiveURLs(urls []string) ([]string, error) {
	sensitiveExts := []string{
		".txt", ".json", ".vscode", ".env", ".zip", ".firebase",
		".csv", ".log", ".cache", ".secret", ".db", ".backup",
		".yml", ".yaml", ".gz", ".rar", ".config", ".sql", ".cnf",
		".DS_Store", ".git", ".bak", ".old", ".swp",
	}

	var sensitiveURLs []string

	for _, url := range urls {
		url = strings.TrimSpace(url)
		if url == "" {
			continue
		}

		urlLower := strings.ToLower(url)

		// Check if URL has sensitive extension
		hasSensitiveExt := false
		for _, ext := range sensitiveExts {
			if strings.Contains(urlLower, ext) {
				hasSensitiveExt = true
				break
			}
		}

		if !hasSensitiveExt {
			continue
		}

		// Extract domain from URL and check if it belongs to target
		// Remove protocol
		domainPart := url
		if strings.HasPrefix(urlLower, "http://") {
			domainPart = url[7:]
		} else if strings.HasPrefix(urlLower, "https://") {
			domainPart = url[8:]
		}

		// Extract hostname (everything before first /)
		slashIdx := strings.Index(domainPart, "/")
		if slashIdx > 0 {
			domainPart = domainPart[:slashIdx]
		}

		// Remove port if present
		colonIdx := strings.Index(domainPart, ":")
		if colonIdx > 0 {
			domainPart = domainPart[:colonIdx]
		}

		// Check if domain matches target domain or is a subdomain of target
		domainPartLower := strings.ToLower(domainPart)
		targetLower := strings.ToLower(s.Domain)

		if domainPartLower == targetLower || strings.HasSuffix(domainPartLower, "."+targetLower) {
			sensitiveURLs = append(sensitiveURLs, url)
		}
	}

	return sensitiveURLs, nil
}

// verifyWithHttpx verifies URLs with httpx (any status code)
func (s *Scanner) verifyWithHttpx(urls []string) ([]string, error) {
	if len(urls) == 0 {
		return []string{}, nil
	}

	tempFile := filepath.Join(s.OutputDir, "temp-httpx-verify.txt")
	if err := s.writeLines(tempFile, urls); err != nil {
		return nil, err
	}
	defer os.Remove(tempFile)

	cmd := exec.Command("httpx", "-l", tempFile, "-silent")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var liveURLs []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			liveURLs = append(liveURLs, line)
		}
	}

	return liveURLs, nil
}

// verifyWithHttpxStatus verifies URLs with httpx (specific status code)
func (s *Scanner) verifyWithHttpxStatus(urls []string, statusCode string) ([]string, error) {
	if len(urls) == 0 {
		return []string{}, nil
	}

	tempFile := filepath.Join(s.OutputDir, "temp-httpx-verify-status.txt")
	if err := s.writeLines(tempFile, urls); err != nil {
		return nil, err
	}
	defer os.Remove(tempFile)

	cmd := exec.Command("httpx", "-l", tempFile, "-mc", statusCode, "-silent")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var liveURLs []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			liveURLs = append(liveURLs, line)
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
		fmt.Fprintln(writer, line)
	}

	return writer.Flush()
}
