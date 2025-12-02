package depconf

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

type Detector struct {
	OutputDir    string
	Domain       string
	Concurrency  int
	HTTPClient   *http.Client
	Verbose      bool
}

type PackageInfo struct {
	Name       string
	Source     string // Which JS file it was found in
	Pattern    string // What pattern matched
	ExistsOnNPM bool
	Checked    bool
}

// NewDetector creates a new dependency confusion detector
func NewDetector(outputDir, domain string) *Detector {
	return &Detector{
		OutputDir:   outputDir,
		Domain:      domain,
		Concurrency: 10,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		Verbose: true,
	}
}

// Run executes dependency confusion detection
func (d *Detector) Run(liveJSFile string) error {
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	magenta := color.New(color.FgMagenta, color.Bold)

	yellow.Println("\n═══════════════════════════════════════════════════════")
	yellow.Println("[STEP 2.4] Dependency Confusion Detection (NPM)")
	yellow.Println("═══════════════════════════════════════════════════════")

	cyan.Println("→ Detecting internal NPM packages for supply chain attacks...")

	// Check if live-js.txt exists
	if _, err := os.Stat(liveJSFile); os.IsNotExist(err) {
		yellow.Printf("⚠ No JavaScript files found: %s\n", liveJSFile)
		yellow.Println("→ Skipping dependency confusion detection")
		return nil
	}

	// Load JS URLs
	jsURLs, err := d.readLines(liveJSFile)
	if err != nil {
		return fmt.Errorf("failed to read JS file: %v", err)
	}

	if len(jsURLs) == 0 {
		yellow.Println("⚠ No JavaScript URLs to analyze")
		return nil
	}

	cyan.Printf("→ Analyzing %d JavaScript files for NPM packages...\n", len(jsURLs))

	// Phase 1: Extract package names from JS files
	packageMap := make(map[string]*PackageInfo)
	var mu sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, d.Concurrency)

	totalProcessed := 0

	for _, jsURL := range jsURLs {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(url string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			// Download JS content
			content, err := d.downloadJS(url)
			if err != nil {
				return
			}

			// Extract package names
			packages := d.extractPackageNames(content, url)

			// Also check for source map
			if mapURL := d.findSourceMapURL(content, url); mapURL != "" {
				mapPackages := d.analyzeSourceMap(mapURL)
				packages = append(packages, mapPackages...)
			}

			mu.Lock()
			totalProcessed++
			for _, pkg := range packages {
				if _, exists := packageMap[pkg.Name]; !exists {
					packageMap[pkg.Name] = pkg
				}
			}
			cyan.Printf("\r→ Progress: %d/%d JS files analyzed, %d unique packages found", totalProcessed, len(jsURLs), len(packageMap))
			mu.Unlock()
		}(jsURL)
	}

	wg.Wait()
	fmt.Println() // New line after progress

	if len(packageMap) == 0 {
		yellow.Println("⚠ No NPM packages found in JavaScript files")
		return nil
	}

	cyan.Printf("→ Found %d unique NPM package names\n", len(packageMap))

	// Phase 2: Check which packages exist on public npm registry
	cyan.Println("→ Checking npm registry for unclaimed packages...")

	packages := make([]*PackageInfo, 0, len(packageMap))
	for _, pkg := range packageMap {
		packages = append(packages, pkg)
	}

	d.checkNPMRegistry(packages)

	// Phase 3: Filter and save results
	var unclaimedPackages []*PackageInfo
	for _, pkg := range packages {
		if pkg.Checked && !pkg.ExistsOnNPM {
			unclaimedPackages = append(unclaimedPackages, pkg)
		}
	}

	if len(unclaimedPackages) == 0 {
		cyan.Println("→ All found packages exist on npm registry (no unclaimed packages)")
		return nil
	}

	// Save results
	outputFile := filepath.Join(d.OutputDir, "dependency-confusion.txt")
	if err := d.saveResults(outputFile, unclaimedPackages); err != nil {
		return fmt.Errorf("failed to save results: %v", err)
	}

	magenta.Println("\n⚠ CRITICAL: Potential Dependency Confusion Vulnerability!")
	magenta.Printf("→ Found %d UNCLAIMED packages on npm registry\n", len(unclaimedPackages))
	red.Println("→ These packages could be claimed by attackers for supply chain attacks")
	green.Printf("✓ Results saved to: %s\n", outputFile)

	// Print summary
	cyan.Println("\n→ Top findings:")
	count := 0
	for _, pkg := range unclaimedPackages {
		if count >= 5 {
			break
		}
		magenta.Printf("  • %s (from %s)\n", pkg.Name, pkg.Source)
		count++
	}

	if len(unclaimedPackages) > 5 {
		cyan.Printf("  ... and %d more (see %s)\n", len(unclaimedPackages)-5, outputFile)
	}

	yellow.Println("\n═══════════════════════════════════════════════════════")
	green.Println("     DEPENDENCY CONFUSION DETECTION COMPLETE")
	yellow.Println("═══════════════════════════════════════════════════════")

	return nil
}

// extractPackageNames extracts NPM package names from JS content
func (d *Detector) extractPackageNames(content, sourceURL string) []*PackageInfo {
	var packages []*PackageInfo
	seen := make(map[string]bool)

	// Pattern 1: node_modules paths
	// Example: node_modules/package-name/lib/file.js
	nodeModulesPattern := regexp.MustCompile(`node_modules/([a-zA-Z0-9@_\-\.]+(?:/[a-zA-Z0-9_\-\.]+)?)/`)
	matches := nodeModulesPattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			pkgName := d.cleanPackageName(match[1])
			if pkgName != "" && !seen[pkgName] && d.isValidPackageName(pkgName) {
				seen[pkgName] = true
				packages = append(packages, &PackageInfo{
					Name:    pkgName,
					Source:  sourceURL,
					Pattern: "node_modules path",
				})
			}
		}
	}

	// Pattern 2: require("package-name")
	requirePattern := regexp.MustCompile(`require\s*\(\s*["']([a-zA-Z0-9@_\-\.\/]+)["']\s*\)`)
	matches = requirePattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			pkgName := d.extractPackageFromPath(match[1])
			if pkgName != "" && !seen[pkgName] && d.isValidPackageName(pkgName) {
				seen[pkgName] = true
				packages = append(packages, &PackageInfo{
					Name:    pkgName,
					Source:  sourceURL,
					Pattern: "require() statement",
				})
			}
		}
	}

	// Pattern 3: import from "package-name"
	importPattern := regexp.MustCompile(`import\s+.*\s+from\s+["']([a-zA-Z0-9@_\-\.\/]+)["']`)
	matches = importPattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			pkgName := d.extractPackageFromPath(match[1])
			if pkgName != "" && !seen[pkgName] && d.isValidPackageName(pkgName) {
				seen[pkgName] = true
				packages = append(packages, &PackageInfo{
					Name:    pkgName,
					Source:  sourceURL,
					Pattern: "import statement",
				})
			}
		}
	}

	// Pattern 4: Embedded package.json
	packageJsonPattern := regexp.MustCompile(`["']name["']\s*:\s*["']([a-zA-Z0-9@_\-\.\/]+)["']`)
	matches = packageJsonPattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			pkgName := d.cleanPackageName(match[1])
			if pkgName != "" && !seen[pkgName] && d.isValidPackageName(pkgName) {
				seen[pkgName] = true
				packages = append(packages, &PackageInfo{
					Name:    pkgName,
					Source:  sourceURL,
					Pattern: "embedded package.json",
				})
			}
		}
	}

	// Pattern 5: Webpack module IDs (often contain package names)
	webpackPattern := regexp.MustCompile(`"(@?[a-zA-Z0-9_\-\.]+(?:/[a-zA-Z0-9_\-\.]+)?)":\s*function`)
	matches = webpackPattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			pkgName := d.cleanPackageName(match[1])
			if pkgName != "" && !seen[pkgName] && d.isValidPackageName(pkgName) && !d.isCommonWord(pkgName) {
				seen[pkgName] = true
				packages = append(packages, &PackageInfo{
					Name:    pkgName,
					Source:  sourceURL,
					Pattern: "webpack module",
				})
			}
		}
	}

	return packages
}

// findSourceMapURL finds source map URL in JS content
func (d *Detector) findSourceMapURL(content, jsURL string) string {
	// Look for sourceMappingURL comment
	pattern := regexp.MustCompile(`//# sourceMappingURL=(.+)`)
	matches := pattern.FindStringSubmatch(content)

	if len(matches) > 1 {
		mapFile := strings.TrimSpace(matches[1])

		// If relative path, construct full URL
		if !strings.HasPrefix(mapFile, "http") {
			// Get base URL
			baseURL := jsURL
			if idx := strings.LastIndex(baseURL, "/"); idx != -1 {
				baseURL = baseURL[:idx+1]
			}
			return baseURL + mapFile
		}
		return mapFile
	}

	// Try appending .map to JS URL
	mapURL := jsURL + ".map"
	return mapURL
}

// analyzeSourceMap downloads and analyzes source map file
func (d *Detector) analyzeSourceMap(mapURL string) []*PackageInfo {
	var packages []*PackageInfo
	seen := make(map[string]bool)

	// Download source map
	content, err := d.downloadJS(mapURL)
	if err != nil {
		return packages
	}

	// Parse source map JSON
	var sourceMap struct {
		Sources []string `json:"sources"`
	}

	if err := json.Unmarshal([]byte(content), &sourceMap); err != nil {
		// If not valid JSON, try regex extraction
		nodeModulesPattern := regexp.MustCompile(`node_modules/([a-zA-Z0-9@_\-\.]+(?:/[a-zA-Z0-9_\-\.]+)?)/`)
		matches := nodeModulesPattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 {
				pkgName := d.cleanPackageName(match[1])
				if pkgName != "" && !seen[pkgName] && d.isValidPackageName(pkgName) {
					seen[pkgName] = true
					packages = append(packages, &PackageInfo{
						Name:    pkgName,
						Source:  mapURL,
						Pattern: "source map (regex)",
					})
				}
			}
		}
		return packages
	}

	// Extract package names from source paths
	for _, source := range sourceMap.Sources {
		// Look for node_modules in path
		if strings.Contains(source, "node_modules/") {
			parts := strings.Split(source, "node_modules/")
			if len(parts) > 1 {
				pkgPath := parts[1]
				pkgName := d.extractPackageFromPath(pkgPath)
				if pkgName != "" && !seen[pkgName] && d.isValidPackageName(pkgName) {
					seen[pkgName] = true
					packages = append(packages, &PackageInfo{
						Name:    pkgName,
						Source:  mapURL,
						Pattern: "source map path",
					})
				}
			}
		}
	}

	return packages
}

// extractPackageFromPath extracts package name from a path
func (d *Detector) extractPackageFromPath(path string) string {
	// Handle scoped packages: @scope/package
	if strings.HasPrefix(path, "@") {
		parts := strings.Split(path, "/")
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
	}

	// Handle regular packages
	parts := strings.Split(path, "/")
	if len(parts) > 0 {
		return parts[0]
	}

	return ""
}

// cleanPackageName cleans and normalizes package name
func (d *Detector) cleanPackageName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.Trim(name, "\"'")

	// Remove trailing slashes
	name = strings.TrimSuffix(name, "/")

	return name
}

// isValidPackageName checks if a string is a valid npm package name
// This is VERY strict to avoid false positives from webpack module IDs, variables, constants, etc.
func (d *Detector) isValidPackageName(name string) bool {
	if name == "" || len(name) > 214 {
		return false
	}

	// Skip relative paths
	if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "/") {
		return false
	}

	// Skip numeric-only strings (webpack module IDs, timestamps, etc.)
	// Example: 5898623200788480
	isNumeric := true
	for _, c := range name {
		if c < '0' || c > '9' {
			isNumeric = false
			break
		}
	}
	if isNumeric {
		return false
	}

	// Skip short random-looking strings (webpack module IDs)
	// Examples: 0XgM, 2W6z, 9W6o, 4Mzw, 5bA4, 0Owb, WU/Z
	if len(name) <= 6 {
		// Check if it looks like a random webpack ID (mixed case, numbers, short)
		hasUpper := false
		hasLower := false
		for _, c := range name {
			if c >= 'A' && c <= 'Z' {
				hasUpper = true
			}
			if c >= 'a' && c <= 'z' {
				hasLower = true
			}
		}
		// If it has mixed case or starts with a number, it's likely a webpack ID
		if (hasUpper && hasLower) || (name[0] >= '0' && name[0] <= '9') {
			return false
		}
	}

	// Skip ALL_CAPS constants (YAML, CHILD, PSEUDO, STYLE_SEPARATOR, etc.)
	isAllCaps := true
	for _, c := range name {
		if c >= 'a' && c <= 'z' {
			isAllCaps = false
			break
		}
	}
	if isAllCaps && !strings.HasPrefix(name, "@") {
		return false
	}

	// Skip camelCase variable names (recoveryToken, siteKey, errorId, clientURI, isDef)
	// Real npm packages use lowercase or kebab-case, not camelCase
	if !strings.HasPrefix(name, "@") {
		hasUpperInMiddle := false
		for i, c := range name {
			if i > 0 && c >= 'A' && c <= 'Z' {
				hasUpperInMiddle = true
				break
			}
		}
		if hasUpperInMiddle {
			return false
		}
	}

	// Skip PascalCase words (Opera, TitleAndAccessibilities)
	if len(name) > 0 && name[0] >= 'A' && name[0] <= 'Z' && !strings.HasPrefix(name, "@") {
		return false
	}

	// Skip built-in Node.js modules
	builtins := []string{
		"fs", "path", "http", "https", "crypto", "util", "os", "events",
		"stream", "buffer", "child_process", "cluster", "dns", "net",
		"tls", "url", "querystring", "zlib", "assert", "console",
		"module", "process", "global", "require",
	}
	for _, builtin := range builtins {
		if name == builtin {
			return false
		}
	}

	// Must not start with . or _
	if strings.HasPrefix(name, "_") {
		return false
	}

	// Scoped packages must have format @scope/package
	if strings.HasPrefix(name, "@") {
		parts := strings.Split(name, "/")
		if len(parts) != 2 || parts[1] == "" {
			return false
		}
		// The package name part must still be lowercase
		if parts[1] != strings.ToLower(parts[1]) {
			return false
		}
	}

	// Real npm packages should be lowercase or contain hyphens
	// Examples: lodash, react-router-dom, @babel/core
	if !strings.HasPrefix(name, "@") && name != strings.ToLower(name) {
		return false
	}

	return true
}

// isCommonWord filters out common English words and code artifacts that might appear
func (d *Detector) isCommonWord(name string) bool {
	commonWords := []string{
		"index", "main", "app", "common", "utils", "helpers", "config",
		"test", "tests", "lib", "src", "dist", "build", "public",
		"static", "assets", "components", "services", "models", "views",
		"controllers", "routes", "middleware", "plugins", "modules",
		// Common variable/function names
		"data", "props", "state", "value", "key", "id", "name", "type",
		"options", "settings", "params", "args", "result", "response",
		"request", "error", "callback", "handler", "context", "scope",
		// Code artifacts
		"default", "export", "import", "module", "exports", "webpack",
		"undefined", "null", "true", "false", "function", "class",
		"const", "let", "var", "return", "this", "self", "window",
		"document", "global", "process", "console", "object", "array",
		"string", "number", "boolean", "symbol", "map", "set",
	}

	nameLower := strings.ToLower(name)
	for _, word := range commonWords {
		if nameLower == word {
			return true
		}
	}

	return false
}

// checkNPMRegistry checks if packages exist on npm registry
func (d *Detector) checkNPMRegistry(packages []*PackageInfo) {
	cyan := color.New(color.FgCyan)

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, d.Concurrency)
	checked := 0
	var mu sync.Mutex

	for _, pkg := range packages {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(p *PackageInfo) {
			defer wg.Done()
			defer func() { <-semaphore }()

			exists := d.checkPackageExists(p.Name)

			mu.Lock()
			p.Checked = true
			p.ExistsOnNPM = exists
			checked++
			cyan.Printf("\r→ Checked %d/%d packages on npm registry", checked, len(packages))
			mu.Unlock()

			// Small delay to avoid rate limiting
			time.Sleep(100 * time.Millisecond)
		}(pkg)
	}

	wg.Wait()
	fmt.Println() // New line
}

// checkPackageExists checks if a package exists on npm registry
func (d *Detector) checkPackageExists(packageName string) bool {
	// npm registry API endpoint
	url := fmt.Sprintf("https://registry.npmjs.org/%s", packageName)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}

	// Set user agent
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")

	resp, err := d.HTTPClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// If 404, package doesn't exist
	if resp.StatusCode == 404 {
		return false
	}

	// If 200, package exists
	if resp.StatusCode == 200 {
		return true
	}

	// For other status codes, assume it might exist (be conservative)
	return true
}

// saveResults saves unclaimed packages to file
func (d *Detector) saveResults(filename string, packages []*PackageInfo) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	// Write header
	writer.WriteString("═══════════════════════════════════════════════════════════════════════════════\n")
	writer.WriteString("              DEPENDENCY CONFUSION VULNERABILITY DETECTION REPORT\n")
	writer.WriteString("═══════════════════════════════════════════════════════════════════════════════\n\n")
	writer.WriteString("⚠ CRITICAL: The following NPM packages are referenced in JavaScript files but\n")
	writer.WriteString("   DO NOT EXIST on the public npm registry (registry.npmjs.org)\n\n")
	writer.WriteString("   These packages may be INTERNAL/PRIVATE dependencies. An attacker could:\n")
	writer.WriteString("   1. Register these package names on public npm\n")
	writer.WriteString("   2. Publish malicious code with a high version number (e.g., 99.99.99)\n")
	writer.WriteString("   3. Achieve Remote Code Execution (RCE) when the package is installed\n\n")
	writer.WriteString("   NEXT STEPS:\n")
	writer.WriteString("   - Verify if these are genuinely internal packages\n")
	writer.WriteString("   - Reserve the names on npm registry immediately\n")
	writer.WriteString("   - Use scoped packages (@company/package) for internal code\n")
	writer.WriteString("   - Configure package manager to use private registry first\n\n")
	writer.WriteString("═══════════════════════════════════════════════════════════════════════════════\n\n")

	writer.WriteString(fmt.Sprintf("Total Unclaimed Packages Found: %d\n", len(packages)))
	writer.WriteString(fmt.Sprintf("Scan Date: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	writer.WriteString(fmt.Sprintf("Target Domain: %s\n\n", d.Domain))

	writer.WriteString("═══════════════════════════════════════════════════════════════════════════════\n\n")

	// Write packages
	for i, pkg := range packages {
		writer.WriteString(fmt.Sprintf("[%d] Package: %s\n", i+1, pkg.Name))
		writer.WriteString(fmt.Sprintf("    Source: %s\n", pkg.Source))
		writer.WriteString(fmt.Sprintf("    Found via: %s\n", pkg.Pattern))
		writer.WriteString(fmt.Sprintf("    NPM Registry: NOT FOUND (404)\n"))
		writer.WriteString(fmt.Sprintf("    Verify: https://www.npmjs.com/package/%s\n", pkg.Name))
		writer.WriteString("\n")
	}

	writer.WriteString("═══════════════════════════════════════════════════════════════════════════════\n")
	writer.WriteString("                              END OF REPORT\n")
	writer.WriteString("═══════════════════════════════════════════════════════════════════════════════\n")

	return nil
}

// downloadJS downloads JavaScript content from URL
func (d *Detector) downloadJS(url string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")

	resp, err := d.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// readLines reads lines from a file
func (d *Detector) readLines(filename string) ([]string, error) {
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
