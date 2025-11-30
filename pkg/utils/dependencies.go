package utils

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/fatih/color"
)

// Dependency represents a required tool
type Dependency struct {
	Name        string
	Command     string
	Required    bool
	Description string
}

// CheckDependencies checks if all required tools are installed
func CheckDependencies(verbose bool) error {
	dependencies := []Dependency{
		// Core tools (required)
		{Name: "httpx", Command: "httpx", Required: true, Description: "HTTP probing tool"},
		{Name: "subfinder", Command: "subfinder", Required: true, Description: "Subdomain discovery"},
		{Name: "amass", Command: "amass", Required: true, Description: "Subdomain enumeration"},
		{Name: "assetfinder", Command: "assetfinder", Required: true, Description: "Subdomain finding"},
		{Name: "findomain", Command: "findomain", Required: true, Description: "Subdomain discovery"},
		{Name: "massdns", Command: "massdns", Required: true, Description: "DNS brute forcing"},
		{Name: "dig", Command: "dig", Required: true, Description: "DNS lookup"},

		// Port scanning
		{Name: "nmap", Command: "nmap", Required: true, Description: "Port scanning"},

		// URL crawling
		{Name: "waybackurls", Command: "waybackurls", Required: false, Description: "Wayback Machine URLs"},
		{Name: "gau", Command: "gau", Required: false, Description: "Get All URLs"},
		{Name: "katana", Command: "katana", Required: false, Description: "Web crawling"},
		{Name: "waymore", Command: "waymore", Required: false, Description: "Archive crawling"},
		{Name: "gospider", Command: "gospider", Required: false, Description: "Web spidering"},
		{Name: "uro", Command: "uro", Required: false, Description: "URL deduplication"},

		// Vulnerability scanning
		{Name: "nuclei", Command: "nuclei", Required: false, Description: "Vulnerability scanner"},
		{Name: "gf", Command: "gf", Required: false, Description: "Pattern matching"},
		{Name: "kxss", Command: "kxss", Required: false, Description: "XSS detection"},
		{Name: "dalfox", Command: "dalfox", Required: false, Description: "XSS scanner"},
		{Name: "ghauri", Command: "ghauri", Required: false, Description: "SQLi scanner"},
		{Name: "sqlmap", Command: "sqlmap", Required: false, Description: "SQL injection"},

		// Cloud enumeration
		{Name: "slurp", Command: "slurp", Required: false, Description: "S3 bucket finder"},
		{Name: "cloud_enum", Command: "cloud_enum", Required: false, Description: "Cloud enumeration"},

		// Directory fuzzing
		{Name: "ffuf", Command: "ffuf", Required: false, Description: "Web fuzzing"},

		// Shodan
		{Name: "shodan", Command: "shodan", Required: false, Description: "Shodan CLI"},
	}

	cyan := color.New(color.FgCyan)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)
	yellow := color.New(color.FgYellow)

	if verbose {
		cyan.Println("\n→ Checking dependencies...")
	}

	var missingRequired []string
	var missingOptional []string

	for _, dep := range dependencies {
		_, err := exec.LookPath(dep.Command)
		if err != nil {
			if dep.Required {
				missingRequired = append(missingRequired, dep.Name)
				if verbose {
					red.Printf("  ✗ %s: NOT FOUND (required)\n", dep.Name)
				}
			} else {
				missingOptional = append(missingOptional, dep.Name)
				if verbose {
					yellow.Printf("  ⚠ %s: NOT FOUND (optional)\n", dep.Name)
				}
			}
		} else if verbose {
			green.Printf("  ✓ %s\n", dep.Name)
		}
	}

	// Report results
	if len(missingRequired) > 0 {
		red.Println("\n✗ Missing required tools:")
		for _, tool := range missingRequired {
			red.Printf("  - %s\n", tool)
		}
		red.Println("\nPlease install the missing tools before continuing.")
		red.Println("See README.md for installation instructions.")
		return fmt.Errorf("missing required dependencies: %s", strings.Join(missingRequired, ", "))
	}

	if len(missingOptional) > 0 && verbose {
		yellow.Println("\n⚠ Missing optional tools (some features will be disabled):")
		for _, tool := range missingOptional {
			yellow.Printf("  - %s\n", tool)
		}
	}

	if verbose {
		green.Println("\n✓ All required dependencies are installed")
	}

	return nil
}

// CheckTool checks if a specific tool is available
func CheckTool(tool string) bool {
	_, err := exec.LookPath(tool)
	return err == nil
}
