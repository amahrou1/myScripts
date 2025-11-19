package dirfuzz

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/fatih/color"
)

type Scanner struct {
	OutputDir       string
	Wordlist        string
	Threads         int
	FilterThreshold int // If >N results have same word length, filter them
	StatusCodes     []int
	Verbose         bool
}

type FfufResult struct {
	Input            string `json:"input"`
	Position         int    `json:"position"`
	StatusCode       int    `json:"status"`
	ContentLength    int    `json:"length"`
	ContentWords     int    `json:"words"`
	ContentLines     int    `json:"lines"`
	RedirectLocation string `json:"redirectlocation"`
	ResultFile       string `json:"resultfile"`
	URL              string `json:"url"`
	Host             string `json:"host"`
}

type FfufOutput struct {
	Results []FfufResult `json:"results"`
}

// NewScanner creates a new directory fuzzer
func NewScanner(outputDir string) *Scanner {
	return &Scanner{
		OutputDir:       outputDir,
		Wordlist:        "/root/myLists/myList.txt",
		Threads:         40,
		FilterThreshold: 5,
		StatusCodes:     []int{200, 301, 302, 307, 403},
		Verbose:         true,
	}
}

// Run executes directory fuzzing on targets
func (s *Scanner) Run(liveSubsFile, shodanIPsFile string) error {
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)
	red := color.New(color.FgRed, color.Bold)

	yellow.Println("\n═══════════════════════════════════════════════════════")
	yellow.Println("[STEP 4] Directory Fuzzing")
	yellow.Println("═══════════════════════════════════════════════════════")

	// Check if ffuf is installed
	if _, err := exec.LookPath("ffuf"); err != nil {
		red.Println("✗ ffuf not found in PATH")
		yellow.Println("→ Please install ffuf: go install github.com/ffuf/ffuf/v2@latest")
		return fmt.Errorf("ffuf not installed")
	}

	// Check if wordlist exists
	if _, err := os.Stat(s.Wordlist); os.IsNotExist(err) {
		red.Printf("✗ Wordlist not found: %s\n", s.Wordlist)
		return fmt.Errorf("wordlist not found")
	}

	// Count wordlist entries
	wordlistCount, _ := s.countLines(s.Wordlist)
	cyan.Printf("→ Wordlist: %s (%d entries)\n", s.Wordlist, wordlistCount)
	cyan.Printf("→ Status codes: %v\n", s.StatusCodes)
	cyan.Printf("→ Threads: %d\n", s.Threads)

	// Prepare targets
	var targets []string

	// Load Shodan IPs first
	if _, err := os.Stat(shodanIPsFile); err == nil {
		ips, err := s.readLines(shodanIPsFile)
		if err == nil && len(ips) > 0 {
			targets = append(targets, ips...)
			cyan.Printf("→ Loaded %d Shodan IPs for fuzzing\n", len(ips))
		}
	}

	// Then load live subdomains
	if _, err := os.Stat(liveSubsFile); err == nil {
		subs, err := s.readLines(liveSubsFile)
		if err == nil && len(subs) > 0 {
			targets = append(targets, subs...)
			cyan.Printf("→ Loaded %d live subdomains for fuzzing\n", len(subs))
		}
	}

	if len(targets) == 0 {
		red.Println("✗ No targets found for directory fuzzing")
		yellow.Printf("→ Live subdomains file: %s (not found or empty)\n", liveSubsFile)
		yellow.Printf("→ Shodan IPs file: %s (not found or empty)\n", shodanIPsFile)
		return fmt.Errorf("no targets found for directory fuzzing")
	}

	cyan.Printf("→ Total targets: %d\n", len(targets))
	cyan.Printf("→ Estimated time: ~%d minutes\n", (len(targets)*wordlistCount/1000)/60)

	// Run fuzzing on all targets
	cyan.Println("\n→ Starting directory fuzzing (this may take a while)...")
	allResults, err := s.fuzzAllTargets(targets)
	if err != nil {
		red.Printf("✗ Fuzzing error: %v\n", err)
		return err
	}

	if len(allResults) == 0 {
		cyan.Println("→ No directories/files discovered")
		return nil
	}

	cyan.Printf("→ Total results before filtering: %d\n", len(allResults))

	// Apply smart filtering
	cyan.Println("→ Applying smart filtering...")
	filteredResults := s.applySmartFilter(allResults)

	cyan.Printf("→ Results after filtering: %d\n", len(filteredResults))

	// Save results
	outputFile := filepath.Join(s.OutputDir, "fuzz.txt")
	if err := s.saveResults(outputFile, filteredResults); err != nil {
		return fmt.Errorf("failed to save results: %v", err)
	}

	green.Printf("✓ Discovered %d directories/files\n", len(filteredResults))
	green.Printf("✓ Results saved to: %s\n", outputFile)

	yellow.Println("═══════════════════════════════════════════════════════")
	green.Println("         DIRECTORY FUZZING COMPLETE")
	yellow.Println("═══════════════════════════════════════════════════════")

	return nil
}

// fuzzAllTargets fuzzes all targets concurrently
func (s *Scanner) fuzzAllTargets(targets []string) ([]FfufResult, error) {
	var allResults []FfufResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	cyan := color.New(color.FgCyan)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)

	// Limit concurrent fuzzing to 3 targets at a time
	semaphore := make(chan struct{}, 3)

	for idx, target := range targets {
		wg.Add(1)
		go func(url string, index int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			cyan.Printf("  [%d/%d] Fuzzing %s\n", index+1, len(targets), url)

			results, err := s.fuzzTarget(url)
			if err != nil {
				red.Printf("    ✗ Error fuzzing %s: %v\n", url, err)
				return
			}

			if len(results) > 0 {
				mu.Lock()
				allResults = append(allResults, results...)
				green.Printf("    ✓ Found %d results\n", len(results))
				mu.Unlock()
			}
		}(target, idx)
	}

	wg.Wait()
	return allResults, nil
}

// fuzzTarget fuzzes a single target
func (s *Scanner) fuzzTarget(target string) ([]FfufResult, error) {
	// Ensure target has trailing slash for directory fuzzing
	if !strings.HasSuffix(target, "/") {
		target = target + "/"
	}

	// Create temp output file for JSON results
	tempFile := filepath.Join(s.OutputDir, fmt.Sprintf("ffuf-temp-%d.json", os.Getpid()))
	defer os.Remove(tempFile)

	// Build status code filter
	statusFilter := ""
	for i, code := range s.StatusCodes {
		if i > 0 {
			statusFilter += ","
		}
		statusFilter += fmt.Sprintf("%d", code)
	}

	// Build ffuf command
	args := []string{
		"-u", target + "FUZZ",
		"-w", s.Wordlist,
		"-mc", statusFilter,
		"-t", fmt.Sprintf("%d", s.Threads),
		"-ac", // Auto-calibrate
		"-json",
		"-o", tempFile,
		"-s", // Silent mode
	}

	cmd := exec.Command("ffuf", args...)

	// Run ffuf
	if err := cmd.Run(); err != nil {
		// ffuf returns exit code 1 if no results found, which is not an error
		if _, statErr := os.Stat(tempFile); os.IsNotExist(statErr) {
			return []FfufResult{}, nil
		}
	}

	// Parse JSON output
	results, err := s.parseFfufOutput(tempFile)
	if err != nil {
		return nil, err
	}

	return results, nil
}

// parseFfufOutput parses ffuf JSON output
func (s *Scanner) parseFfufOutput(outputFile string) ([]FfufResult, error) {
	file, err := os.Open(outputFile)
	if err != nil {
		if os.IsNotExist(err) {
			return []FfufResult{}, nil
		}
		return nil, err
	}
	defer file.Close()

	var output FfufOutput
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&output); err != nil {
		return nil, fmt.Errorf("failed to parse ffuf output: %v", err)
	}

	return output.Results, nil
}

// applySmartFilter filters out results with common word lengths (>threshold)
func (s *Scanner) applySmartFilter(results []FfufResult) []FfufResult {
	cyan := color.New(color.FgCyan)
	yellow := color.New(color.FgYellow)

	// Group results by word length
	wordLengthGroups := make(map[int][]FfufResult)
	for _, result := range results {
		wordLengthGroups[result.ContentWords] = append(wordLengthGroups[result.ContentWords], result)
	}

	// Find word lengths that appear more than threshold times
	suspiciousWordLengths := make(map[int]bool)
	for wordLength, group := range wordLengthGroups {
		if len(group) > s.FilterThreshold {
			suspiciousWordLengths[wordLength] = true
			yellow.Printf("  → Filtering %d results with word length %d (likely false positive)\n", len(group), wordLength)
		}
	}

	// Filter out suspicious results
	var filtered []FfufResult
	for _, result := range results {
		if !suspiciousWordLengths[result.ContentWords] {
			filtered = append(filtered, result)
		}
	}

	if len(suspiciousWordLengths) > 0 {
		cyan.Printf("  → Filtered out %d suspicious results\n", len(results)-len(filtered))
	}

	return filtered
}

// saveResults saves fuzzing results to file
func (s *Scanner) saveResults(outputFile string, results []FfufResult) error {
	file, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, result := range results {
		// Format: [STATUS] [SIZE bytes] [WORDS words] URL
		line := fmt.Sprintf("[%d] [%d bytes] [%d words] %s\n",
			result.StatusCode,
			result.ContentLength,
			result.ContentWords,
			result.URL)
		writer.WriteString(line)
	}

	return writer.Flush()
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

// countLines counts lines in a file
func (s *Scanner) countLines(filename string) (int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		count++
	}

	return count, scanner.Err()
}
