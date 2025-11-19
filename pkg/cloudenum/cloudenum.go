package cloudenum

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
	OutputDir      string
	SlurpPath      string
	CloudEnumPath  string
	Verbose        bool
}

// NewScanner creates a new cloud enumeration scanner
func NewScanner(outputDir string) *Scanner {
	return &Scanner{
		OutputDir:     outputDir,
		SlurpPath:     "/root/tools/slurp",
		CloudEnumPath: "/root/Tools/cloud_enum",
		Verbose:       true,
	}
}

// Run executes cloud enumeration on the main domain
func (s *Scanner) Run(domain string) error {
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)

	yellow.Println("\n═══════════════════════════════════════════════════════")
	yellow.Println("[BONUS] Cloud Resource Enumeration")
	yellow.Println("═══════════════════════════════════════════════════════")

	cyan.Printf("→ Target domain: %s\n", domain)

	var allResults []string

	// Run slurp for S3 bucket enumeration
	cyan.Println("\n→ Running slurp for S3 bucket discovery...")
	slurpResults, err := s.runSlurp(domain)
	if err != nil {
		yellow.Printf("⚠ Slurp error: %v (continuing)\n", err)
	} else if len(slurpResults) > 0 {
		green.Printf("✓ Found %d S3 buckets with slurp\n", len(slurpResults))
		allResults = append(allResults, slurpResults...)
	} else {
		cyan.Println("→ No S3 buckets found with slurp")
	}

	// Run cloud_enum for multi-cloud enumeration
	cyan.Println("\n→ Running cloud_enum for AWS/Azure/GCP enumeration...")
	cloudResults, err := s.runCloudEnum(domain)
	if err != nil {
		yellow.Printf("⚠ cloud_enum error: %v (continuing)\n", err)
	} else if len(cloudResults) > 0 {
		green.Printf("✓ Found %d cloud resources with cloud_enum\n", len(cloudResults))
		allResults = append(allResults, cloudResults...)
	} else {
		cyan.Println("→ No cloud resources found with cloud_enum")
	}

	// Save all results
	if len(allResults) > 0 {
		outputFile := filepath.Join(s.OutputDir, "cloud-resources.txt")
		if err := s.writeLines(outputFile, allResults); err != nil {
			return fmt.Errorf("failed to save results: %v", err)
		}

		green.Printf("\n✓ Total cloud resources discovered: %d\n", len(allResults))
		green.Printf("✓ Results saved to: %s\n", outputFile)
	} else {
		cyan.Println("\n→ No cloud resources discovered")
	}

	yellow.Println("═══════════════════════════════════════════════════════")
	green.Println("      CLOUD ENUMERATION COMPLETE")
	yellow.Println("═══════════════════════════════════════════════════════")

	return nil
}

// runSlurp executes slurp for S3 bucket discovery
func (s *Scanner) runSlurp(domain string) ([]string, error) {
	cyan := color.New(color.FgCyan)
	yellow := color.New(color.FgYellow)

	// Check if slurp exists
	slurpBinary := filepath.Join(s.SlurpPath, "slurp")
	if _, err := os.Stat(slurpBinary); os.IsNotExist(err) {
		yellow.Printf("⚠ slurp not found at: %s\n", slurpBinary)
		return []string{}, fmt.Errorf("slurp not found")
	}

	// Check if permutations.json exists
	permutationsFile := filepath.Join(s.SlurpPath, "permutations.json")
	if _, err := os.Stat(permutationsFile); os.IsNotExist(err) {
		yellow.Printf("⚠ permutations.json not found at: %s\n", permutationsFile)
		return []string{}, fmt.Errorf("permutations.json not found")
	}

	// Prepare target URL
	targetURL := fmt.Sprintf("https://%s", domain)

	// Build slurp command
	args := []string{
		"domain",
		"-p", permutationsFile,
		"-t", targetURL,
		"-c", "25",
	}

	cyan.Printf("→ Command: cd %s && ./slurp %s\n", s.SlurpPath, strings.Join(args, " "))

	// Create output file
	outputFile := filepath.Join(s.OutputDir, "slurp-output.txt")

	cmd := exec.Command(slurpBinary, args...)
	cmd.Dir = s.SlurpPath

	// Capture output
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Slurp might return error even if it found results, check output
		if len(output) > 0 {
			// Save output anyway
			os.WriteFile(outputFile, output, 0644)
		}
		// Don't return error if we got some output
		if len(output) == 0 {
			return []string{}, fmt.Errorf("slurp failed: %v", err)
		}
	}

	// Save raw output
	if err := os.WriteFile(outputFile, output, 0644); err != nil {
		yellow.Printf("⚠ Failed to save slurp output: %v\n", err)
	}

	// Parse results
	results := s.parseSlurpOutput(string(output))
	return results, nil
}

// runCloudEnum executes cloud_enum for multi-cloud enumeration
func (s *Scanner) runCloudEnum(domain string) ([]string, error) {
	cyan := color.New(color.FgCyan)
	yellow := color.New(color.FgYellow)

	// Check if cloud_enum.py exists
	cloudEnumScript := filepath.Join(s.CloudEnumPath, "cloud_enum.py")
	if _, err := os.Stat(cloudEnumScript); os.IsNotExist(err) {
		yellow.Printf("⚠ cloud_enum.py not found at: %s\n", cloudEnumScript)
		return []string{}, fmt.Errorf("cloud_enum.py not found")
	}

	// Build cloud_enum command
	args := []string{
		cloudEnumScript,
		"-k", domain,
	}

	cyan.Printf("→ Command: cd %s && python3 %s\n", s.CloudEnumPath, strings.Join(args, " "))

	cmd := exec.Command("python3", args...)
	cmd.Dir = s.CloudEnumPath

	// Capture output
	output, err := cmd.CombinedOutput()
	if err != nil {
		// cloud_enum might return error code, but still produce results
		if len(output) > 0 {
			// Continue processing
		} else {
			return []string{}, fmt.Errorf("cloud_enum failed: %v", err)
		}
	}

	// Save raw output
	outputFile := filepath.Join(s.OutputDir, "cloud_enum-output.txt")
	if err := os.WriteFile(outputFile, output, 0644); err != nil {
		yellow.Printf("⚠ Failed to save cloud_enum output: %v\n", err)
	}

	// Print output in real-time (cloud_enum has nice formatting)
	if len(output) > 0 {
		fmt.Println(string(output))
	}

	// Parse results
	results := s.parseCloudEnumOutput(string(output))
	return results, nil
}

// parseSlurpOutput parses slurp output for S3 buckets
func (s *Scanner) parseSlurpOutput(output string) []string {
	var results []string
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Look for S3 URLs or bucket names
		if strings.Contains(line, "s3.amazonaws.com") ||
			strings.Contains(line, ".s3.") ||
			strings.Contains(line, "amazonaws.com") {

			// Extract bucket name or URL
			if !seen[line] && line != "" {
				results = append(results, fmt.Sprintf("[S3] %s", line))
				seen[line] = true
			}
		}
	}

	return results
}

// parseCloudEnumOutput parses cloud_enum output for cloud resources
func (s *Scanner) parseCloudEnumOutput(output string) []string {
	var results []string
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Look for found resources (cloud_enum marks them with specific patterns)
		if strings.Contains(line, "FOUND:") ||
			strings.Contains(line, "s3://") ||
			strings.Contains(line, "blob.core.windows.net") ||
			strings.Contains(line, "storage.googleapis.com") ||
			strings.Contains(line, "appspot.com") {

			if !seen[line] && line != "" && !strings.HasPrefix(line, "#") {
				// Determine cloud provider
				provider := ""
				if strings.Contains(line, "s3://") || strings.Contains(line, "amazonaws") {
					provider = "[AWS]"
				} else if strings.Contains(line, "blob.core.windows.net") || strings.Contains(line, "azure") {
					provider = "[Azure]"
				} else if strings.Contains(line, "googleapis.com") || strings.Contains(line, "appspot.com") {
					provider = "[GCP]"
				}

				results = append(results, fmt.Sprintf("%s %s", provider, line))
				seen[line] = true
			}
		}
	}

	return results
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
