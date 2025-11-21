package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/amahrou1/myScripts/pkg/cloudenum"
	"github.com/amahrou1/myScripts/pkg/nuclei"
	"github.com/amahrou1/myScripts/pkg/portscan"
	"github.com/amahrou1/myScripts/pkg/subdomains"
	"github.com/amahrou1/myScripts/pkg/urlcrawl"
	"github.com/amahrou1/myScripts/pkg/vulnscan"
	"github.com/fatih/color"
)

const banner = `
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║    ██████╗ ██╗   ██╗ ██████╗     ██████╗ ███████╗ ██████╗    ║
║    ██╔══██╗██║   ██║██╔════╝     ██╔══██╗██╔════╝██╔════╝    ║
║    ██████╔╝██║   ██║██║  ███╗    ██████╔╝█████╗  ██║         ║
║    ██╔══██╗██║   ██║██║   ██║    ██╔══██╗██╔══╝  ██║         ║
║    ██████╔╝╚██████╔╝╚██████╔╝    ██║  ██║███████╗╚██████╗    ║
║    ╚═════╝  ╚═════╝  ╚═════╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝    ║
║                                                               ║
║           Bug Bounty Reconnaissance Framework                ║
║                    v1.0.0 - Step 1                           ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
`

func main() {
	// Command line flags
	domain := flag.String("d", "", "Target domain (required)")
	output := flag.String("o", "", "Output directory (required)")
	skipVhost := flag.Bool("skip-vhost", false, "Skip VHost fuzzing (faster)")
	skipUrlcrawl := flag.Bool("skip-urlcrawl", false, "Skip URL crawling")
	skipVulnscan := flag.Bool("skip-vulnscan", false, "Skip vulnerability scanning (XSS & SQLi)")
	skipCloudenum := flag.Bool("skip-cloudenum", false, "Skip cloud enumeration")
	skipPortscan := flag.Bool("skip-portscan", false, "Skip port scanning")
	skipNuclei := flag.Bool("skip-nuclei", false, "Skip Nuclei vulnerability scanning")
	help := flag.Bool("h", false, "Show help")

	flag.Parse()

	// Show banner
	cyan := color.New(color.FgCyan, color.Bold)
	cyan.Println(banner)

	// Show help
	if *help || *domain == "" || *output == "" {
		showHelp()
		os.Exit(0)
	}

	// Validate domain
	if *domain == "" {
		color.Red("Error: Domain is required\n")
		showHelp()
		os.Exit(1)
	}

	// Validate output directory
	if *output == "" {
		color.Red("Error: Output directory is required\n")
		showHelp()
		os.Exit(1)
	}

	// Create absolute path for output directory
	outputDir, err := filepath.Abs(*output)
	if err != nil {
		color.Red("Error: Invalid output directory: %v\n", err)
		os.Exit(1)
	}

	// Print scan information
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow)

	green.Println("╔═══════════════════════════════════════════════════════════════╗")
	green.Println("║                      SCAN INFORMATION                        ║")
	green.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Printf("  Target Domain    : %s\n", *domain)
	fmt.Printf("  Output Directory : %s\n", outputDir)
	fmt.Printf("  Start Time       : %s\n", time.Now().Format("2006-01-02 15:04:05"))
	green.Println("╚═══════════════════════════════════════════════════════════════╝")

	// Start subdomain enumeration
	startTime := time.Now()

	enumerator := subdomains.NewEnumerator(*domain, outputDir)
	enumerator.SkipVHost = *skipVhost
	if err := enumerator.Run(); err != nil {
		color.Red("\n✗ Error: %v\n", err)
		os.Exit(1)
	}

	// Run URL Crawling if not skipped
	if !*skipUrlcrawl {
		urlscanner := urlcrawl.NewScanner(outputDir)
		liveSubsFile := filepath.Join(outputDir, "live-subdomains.txt")

		if err := urlscanner.Run(liveSubsFile); err != nil {
			color.Red("\n✗ URL crawling error: %v\n", err)
			// Don't exit - URL crawling errors are not critical
		}
	} else {
		yellow := color.New(color.FgYellow, color.Bold)
		yellow.Println("\n[STEP 2] URL Crawling - SKIPPED (use without -skip-urlcrawl to enable)")
	}

	// Run Vulnerability Scanning if not skipped
	if !*skipVulnscan && !*skipUrlcrawl {
		vulnscanner := vulnscan.NewScanner(outputDir)
		paramsFile := filepath.Join(outputDir, "params.txt")
		jsFile := filepath.Join(outputDir, "live-js.txt")

		if err := vulnscanner.Run(paramsFile, jsFile); err != nil {
			color.Red("\n✗ Vulnerability scanning error: %v\n", err)
			// Don't exit - vulnerability scanning errors are not critical
		}
	} else if *skipVulnscan {
		yellow := color.New(color.FgYellow, color.Bold)
		yellow.Println("\n[STEP 2.5] Vulnerability Scanning - SKIPPED (use without -skip-vulnscan to enable)")
	}

	// Run Cloud Enumeration if not skipped
	if !*skipCloudenum {
		cloudscanner := cloudenum.NewScanner(outputDir)
		if err := cloudscanner.Run(*domain); err != nil {
			color.Red("\n✗ Cloud enumeration error: %v\n", err)
			// Don't exit - cloud enum errors are not critical
		}
	} else {
		yellow := color.New(color.FgYellow, color.Bold)
		yellow.Println("\n[BONUS] Cloud Enumeration - SKIPPED (use without -skip-cloudenum to enable)")
	}

	// Run Port Scanning if not skipped
	if !*skipPortscan {
		portscanner := portscan.NewScanner(outputDir)
		liveSubsFile := filepath.Join(outputDir, "live-subdomains.txt")
		shodanIPsFile := filepath.Join(outputDir, "shodan-ips.txt")

		if err := portscanner.Run(liveSubsFile, shodanIPsFile); err != nil {
			color.Red("\n✗ Port scan error: %v\n", err)
			// Don't exit - port scan errors are not critical
		}
	} else {
		yellow := color.New(color.FgYellow, color.Bold)
		yellow.Println("\n[STEP 3] Port Scanning - SKIPPED (use without -skip-portscan to enable)")
	}

	// Run Nuclei scanning if not skipped
	if !*skipNuclei {
		// Scan subdomains with default templates
		scanner := nuclei.NewScanner(outputDir)
		liveSubsFile := filepath.Join(outputDir, "live-subdomains.txt")
		shodanIPsFile := filepath.Join(outputDir, "shodan-ips.txt")

		if err := scanner.Run(liveSubsFile, shodanIPsFile); err != nil {
			color.Red("\n✗ Nuclei error: %v\n", err)
			// Don't exit - Nuclei errors are not critical
		}

		// Run Nuclei on URL crawling results if they exist
		if !*skipUrlcrawl {
			runURLNucleiScans(outputDir)
		}
	} else {
		yellow := color.New(color.FgYellow, color.Bold)
		yellow.Println("\n[STEP 2] Nuclei Scanning - SKIPPED (use without -skip-nuclei to enable)")
	}

	// Print completion
	duration := time.Since(startTime)
	green.Println("\n╔═══════════════════════════════════════════════════════════════╗")
	green.Println("║                    SCAN COMPLETED                            ║")
	green.Println("╚═══════════════════════════════════════════════════════════════╝")
	yellow.Printf("  Total Duration: %s\n", formatDuration(duration))
	green.Printf("\n✓ Results saved in: %s\n\n", outputDir)
}

// runURLNucleiScans runs Nuclei scans on URL crawling results
func runURLNucleiScans(outputDir string) {
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)
	red := color.New(color.FgRed, color.Bold)

	yellow.Println("\n═══════════════════════════════════════════════════════════════")
	yellow.Println("[STEP 5] Nuclei Scanning - URL Crawling Results")
	yellow.Println("═══════════════════════════════════════════════════════════════")

	// Scan params.txt with fuzzing templates
	paramsFile := filepath.Join(outputDir, "params.txt")
	if _, err := os.Stat(paramsFile); err == nil {
		cyan.Println("\n→ Scanning parameter URLs with fuzzing templates...")
		fuzzResultsFile := filepath.Join(outputDir, "fuzzing-nuclei-result.txt")

		cmd := exec.Command("nuclei",
			"-l", paramsFile,
			"-t", "/root/fuzz/",
			"-o", fuzzResultsFile,
		)

		if err := cmd.Run(); err != nil {
			red.Printf("✗ Nuclei fuzzing scan error: %v\n", err)
		} else {
			green.Printf("✓ Fuzzing scan complete, results saved to: %s\n", fuzzResultsFile)
		}
	} else {
		cyan.Println("→ No parameter URLs found, skipping fuzzing scan")
	}

	// Scan live-js.txt with exposure templates
	jsFile := filepath.Join(outputDir, "live-js.txt")
	if _, err := os.Stat(jsFile); err == nil {
		cyan.Println("\n→ Scanning JavaScript files with exposure templates...")
		jsResultsFile := filepath.Join(outputDir, "js-nuclei-result.txt")

		cmd := exec.Command("nuclei",
			"-l", jsFile,
			"-t", "/root/nuclei-templates/http/exposures/",
			"-o", jsResultsFile,
		)

		if err := cmd.Run(); err != nil {
			red.Printf("✗ Nuclei JS scan error: %v\n", err)
		} else {
			green.Printf("✓ JS exposure scan complete, results saved to: %s\n", jsResultsFile)
		}
	} else {
		cyan.Println("→ No JavaScript files found, skipping JS exposure scan")
	}

	yellow.Println("═══════════════════════════════════════════════════════════════")
}

func showHelp() {
	yellow := color.New(color.FgYellow, color.Bold)
	white := color.New(color.FgWhite)

	yellow.Println("\nUSAGE:")
	white.Println("  recon -d <domain> -o <output_directory>")

	yellow.Println("\nFLAGS:")
	white.Println("  -d string")
	white.Println("      Target domain (e.g., example.com)")
	white.Println("  -o string")
	white.Println("      Output directory for results")
	white.Println("  -skip-vhost")
	white.Println("      Skip VHost fuzzing (faster, recommended for large scans)")
	white.Println("  -skip-urlcrawl")
	white.Println("      Skip URL crawling and discovery")
	white.Println("  -skip-vulnscan")
	white.Println("      Skip vulnerability scanning (XSS & SQLi)")
	white.Println("  -skip-cloudenum")
	white.Println("      Skip cloud enumeration (S3, Azure, GCP)")
	white.Println("  -skip-portscan")
	white.Println("      Skip port scanning (top 1000 ports)")
	white.Println("  -skip-nuclei")
	white.Println("      Skip Nuclei vulnerability scanning")
	white.Println("  -h")
	white.Println("      Show this help message")

	yellow.Println("\nEXAMPLES:")
	white.Println("  # Basic scan (full)")
	white.Println("  ./recon -d example.com -o results")
	white.Println()
	white.Println("  # Scan with custom output directory")
	white.Println("  ./recon -d avantgardportal.com -o /root/scans/avantgard")
	white.Println()
	white.Println("  # Skip VHost fuzzing for faster results")
	white.Println("  ./recon -d example.com -o results -skip-vhost")
	white.Println()
	white.Println("  # Skip port scanning")
	white.Println("  ./recon -d example.com -o results -skip-vhost -skip-portscan")
	white.Println()
	white.Println("  # Subdomain enum only (fastest)")
	white.Println("  ./recon -d example.com -o results -skip-vhost -skip-portscan -skip-nuclei")

	yellow.Println("\nOUTPUT FILES:")
	white.Println("  all-subdomains.txt          - All discovered subdomains (unique)")
	white.Println("  live-subdomains.txt         - Subdomains with live HTTP/HTTPS services")
	white.Println("  shodan-ips.txt              - All IPs from Shodan SSL certificates")
	white.Println("  shodan-live-ips.txt         - Live Shodan IPs with HTTP/HTTPS")
	white.Println("  unique-urls.txt             - All unique URLs from crawling")
	white.Println("  params.txt                  - Live URLs with parameters")
	white.Println("  live-js.txt                 - Live JavaScript files")
	white.Println("  sensitive-files.txt         - Sensitive files (.env, .json, etc.)")
	white.Println("  params-filtered-xss.txt     - XSS candidate URLs (filtered with gf)")
	white.Println("  params-filtered-sqli.txt    - SQLi candidate URLs (filtered with gf)")
	white.Println("  kxss-results.txt            - kxss scan results (potential XSS)")
	white.Println("  xss-vulnerable.txt          - Confirmed XSS vulnerabilities (dalfox)")
	white.Println("  ghauri-results.txt          - Ghauri SQLi scan results")
	white.Println("  ghauri-vulnerable-urls.txt  - Confirmed SQLi vulnerabilities (ghauri)")
	white.Println("  sqlmap-results.txt          - SQLmap confirmation results")
	white.Println("  open-ports.txt              - Open ports (verified with httpx)")
	white.Println("  cloud-resources.txt         - Discovered cloud resources")
	white.Println("  nuclei-results.txt          - Nuclei vulnerability scan results")
	white.Println("  fuzzing-nuclei-result.txt   - Nuclei fuzzing results (params)")
	white.Println("  js-nuclei-result.txt        - Nuclei JS exposure results")

	yellow.Println("\nTOOLS USED:")
	white.Println("  • Subdomain Discovery: subfinder, amass, assetfinder, findomain, massdns")
	white.Println("  • URL Crawling: waybackurls, gau, katana, waymore, gospider")
	white.Println("  • Vulnerability Scanning: gf, kxss, dalfox, ghauri, sqlmap")
	white.Println("  • Cloud Enumeration: slurp, cloud_enum")
	white.Println("  • Port Scanning: nmap")
	white.Println("  • Verification: httpx")
	white.Println("  • Template Scanning: nuclei")

	fmt.Println()
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	} else if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}
