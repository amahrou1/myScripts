package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/amahrou1/myScripts/pkg/cloudenum"
	"github.com/amahrou1/myScripts/pkg/config"
	"github.com/amahrou1/myScripts/pkg/depconf"
	"github.com/amahrou1/myScripts/pkg/jsanalysis"
	"github.com/amahrou1/myScripts/pkg/logger"
	"github.com/amahrou1/myScripts/pkg/nuclei"
	"github.com/amahrou1/myScripts/pkg/portscan"
	"github.com/amahrou1/myScripts/pkg/subdomains"
	"github.com/amahrou1/myScripts/pkg/urlcrawl"
	"github.com/amahrou1/myScripts/pkg/utils"
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
	skipJSAnalysis := flag.Bool("skip-jsanalysis", false, "Skip JavaScript file analysis")
	skipDepConf := flag.Bool("skip-depconf", false, "Skip dependency confusion detection")
	skipVulnscan := flag.Bool("skip-vulnscan", false, "Skip vulnerability scanning (XSS & SQLi)")
	skipCloudenum := flag.Bool("skip-cloudenum", false, "Skip cloud enumeration")
	skipPortscan := flag.Bool("skip-portscan", false, "Skip port scanning")
	skipNuclei := flag.Bool("skip-nuclei", false, "Skip Nuclei vulnerability scanning")
	checkDeps := flag.Bool("check-deps", false, "Check dependencies and exit")
	help := flag.Bool("h", false, "Show help")

	flag.Parse()

	// Show banner
	cyan := color.New(color.FgCyan, color.Bold)
	cyan.Println(banner)

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		color.Red("Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// Check dependencies if requested
	if *checkDeps {
		if err := utils.CheckDependencies(true); err != nil {
			os.Exit(1)
		}
		color.Green("\n✓ All dependencies are satisfied\n")
		os.Exit(0)
	}

	// Show help
	if *help || *domain == "" || *output == "" {
		showHelp()
		os.Exit(0)
	}

	// Validate and sanitize domain
	validatedDomain, err := utils.ValidateDomain(*domain)
	if err != nil {
		color.Red("Error: Invalid domain: %v\n", err)
		color.Yellow("Please provide a valid domain (e.g., example.com)\n")
		os.Exit(1)
	}
	*domain = validatedDomain

	// Validate output directory
	if *output == "" {
		color.Red("Error: Output directory is required\n")
		showHelp()
		os.Exit(1)
	}

	// Sanitize and create absolute path for output directory
	outputDir, err := filepath.Abs(*output)
	if err != nil {
		color.Red("Error: Invalid output directory: %v\n", err)
		os.Exit(1)
	}

	if _, err := utils.SanitizeFilePath(outputDir); err != nil {
		color.Red("Error: Invalid output path: %v\n", err)
		os.Exit(1)
	}

	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		color.Red("Error: Failed to create output directory: %v\n", err)
		os.Exit(1)
	}

	// Initialize logging
	if err := logger.Init(outputDir, true); err != nil {
		color.Yellow("Warning: Failed to initialize logging: %v\n", err)
	} else {
		defer logger.Close()
	}

	logger.Info("Starting scan for domain: %s", *domain)
	logger.Info("Output directory: %s", outputDir)

	// Check dependencies (non-verbose, just log warnings)
	if err := utils.CheckDependencies(false); err != nil {
		logger.Error("Dependency check failed: %v", err)
		color.Red("\n✗ Missing required dependencies. Run with -check-deps to see details.\n")
		os.Exit(1)
	}

	// Show configuration warnings
	warnings := cfg.Validate()
	if len(warnings) > 0 {
		yellow := color.New(color.FgYellow)
		yellow.Println("\n⚠ Configuration warnings:")
		for _, warning := range warnings {
			yellow.Printf("  - %s\n", warning)
			logger.Error("Config warning: %s", warning)
		}
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

	// Apply config settings
	if cfg.ShodanAPIKey != "" {
		enumerator.ShodanAPIKey = cfg.ShodanAPIKey
	}
	if cfg.SubdomainWordlist != "" {
		enumerator.Wordlist = cfg.SubdomainWordlist
	}
	if cfg.VHostWordlist != "" {
		enumerator.VHostWordlist = cfg.VHostWordlist
	}
	if cfg.DNSResolvers != "" {
		enumerator.Resolvers = cfg.DNSResolvers
	}
	if cfg.PythonScript != "" {
		enumerator.PythonScript = cfg.PythonScript
	}

	if err := enumerator.Run(); err != nil {
		logger.Error("Subdomain enumeration failed: %v", err)
		color.Red("\n✗ Error: %v\n", err)
		os.Exit(1)
	}
	logger.Info("Subdomain enumeration completed successfully")

	// Run URL Crawling if not skipped
	if !*skipUrlcrawl {
		urlscanner := urlcrawl.NewScanner(outputDir, *domain)
		liveSubsFile := filepath.Join(outputDir, "live-subdomains.txt")

		// Apply config settings - global phase timeout
		urlscanner.PhaseTimeout = cfg.URLCrawlingTimeout

		// Apply individual tool timeouts
		urlscanner.WaybackurlsTimeout = cfg.WaybackurlsTimeout
		urlscanner.GauTimeout = cfg.GauTimeout
		urlscanner.KatanaTimeout = cfg.KatanaTimeout
		urlscanner.KatanaParamsTimeout = cfg.KatanaParamsTimeout
		urlscanner.GospiderTimeout = cfg.GospiderTimeout
		urlscanner.WebArchiveTimeout = cfg.WebArchiveTimeout

		// Apply API keys
		urlscanner.VirusTotalKey = cfg.VirusTotalKey
		urlscanner.OTXKey = cfg.AlienVaultKey

		if err := urlscanner.Run(liveSubsFile); err != nil {
			logger.Error("URL crawling failed: %v", err)
			color.Red("\n✗ URL crawling error: %v\n", err)
			// Don't exit - URL crawling errors are not critical
		} else {
			logger.Info("URL crawling completed successfully")
		}
	} else {
		yellow := color.New(color.FgYellow, color.Bold)
		yellow.Println("\n[STEP 2] URL Crawling - SKIPPED (use without -skip-urlcrawl to enable)")
		logger.Info("URL crawling skipped by user")
	}

	// Run JavaScript Analysis if not skipped
	if !*skipJSAnalysis && !*skipUrlcrawl {
		jsanalyzer := jsanalysis.NewAnalyzer(outputDir, *domain)
		liveJSFile := filepath.Join(outputDir, "live-js.txt")

		if err := jsanalyzer.Run(liveJSFile); err != nil {
			logger.Error("JavaScript analysis failed: %v", err)
			color.Red("\n✗ JavaScript analysis error: %v\n", err)
			// Don't exit - JS analysis errors are not critical
		} else {
			logger.Info("JavaScript analysis completed successfully")
		}
	} else if *skipJSAnalysis {
		yellow := color.New(color.FgYellow, color.Bold)
		yellow.Println("\n[STEP 2.3] JavaScript Analysis - SKIPPED (use without -skip-jsanalysis to enable)")
		logger.Info("JavaScript analysis skipped by user")
	}

	// Run Dependency Confusion Detection if not skipped
	if !*skipDepConf && !*skipUrlcrawl {
		depconfDetector := depconf.NewDetector(outputDir, *domain)
		liveJSFile := filepath.Join(outputDir, "live-js.txt")

		if err := depconfDetector.Run(liveJSFile); err != nil {
			logger.Error("Dependency confusion detection failed: %v", err)
			color.Red("\n✗ Dependency confusion detection error: %v\n", err)
			// Don't exit - depconf errors are not critical
		} else {
			logger.Info("Dependency confusion detection completed successfully")
		}
	} else if *skipDepConf {
		yellow := color.New(color.FgYellow, color.Bold)
		yellow.Println("\n[STEP 2.4] Dependency Confusion Detection - SKIPPED (use without -skip-depconf to enable)")
		logger.Info("Dependency confusion detection skipped by user")
	}

	// Run Vulnerability Scanning if not skipped
	if !*skipVulnscan && !*skipUrlcrawl {
		vulnscanner := vulnscan.NewScanner(outputDir)
		paramsFile := filepath.Join(outputDir, "params.txt")
		jsFile := filepath.Join(outputDir, "live-js.txt")

		if err := vulnscanner.Run(paramsFile, jsFile); err != nil {
			logger.Error("Vulnerability scanning failed: %v", err)
			color.Red("\n✗ Vulnerability scanning error: %v\n", err)
			// Don't exit - vulnerability scanning errors are not critical
		} else {
			logger.Info("Vulnerability scanning completed successfully")
		}
	} else if *skipVulnscan {
		yellow := color.New(color.FgYellow, color.Bold)
		yellow.Println("\n[STEP 2.5] Vulnerability Scanning - SKIPPED (use without -skip-vulnscan to enable)")
		logger.Info("Vulnerability scanning skipped by user")
	}

	// Run Cloud Enumeration if not skipped
	if !*skipCloudenum {
		cloudscanner := cloudenum.NewScanner(outputDir)
		if err := cloudscanner.Run(*domain); err != nil {
			logger.Error("Cloud enumeration failed: %v", err)
			color.Red("\n✗ Cloud enumeration error: %v\n", err)
			// Don't exit - cloud enum errors are not critical
		} else {
			logger.Info("Cloud enumeration completed successfully")
		}
	} else {
		yellow := color.New(color.FgYellow, color.Bold)
		yellow.Println("\n[BONUS] Cloud Enumeration - SKIPPED (use without -skip-cloudenum to enable)")
		logger.Info("Cloud enumeration skipped by user")
	}

	// Run Port Scanning if not skipped
	if !*skipPortscan {
		portscanner := portscan.NewScanner(outputDir)
		portscanner.TopPorts = cfg.NmapTopPorts // Use configured port count
		liveSubsFile := filepath.Join(outputDir, "live-subdomains.txt")
		shodanIPsFile := filepath.Join(outputDir, "shodan-ips.txt")

		if err := portscanner.Run(liveSubsFile, shodanIPsFile); err != nil {
			logger.Error("Port scanning failed: %v", err)
			color.Red("\n✗ Port scan error: %v\n", err)
			// Don't exit - port scan errors are not critical
		} else {
			logger.Info("Port scanning completed successfully")
		}
	} else {
		yellow := color.New(color.FgYellow, color.Bold)
		yellow.Println("\n[STEP 3] Port Scanning - SKIPPED (use without -skip-portscan to enable)")
		logger.Info("Port scanning skipped by user")
	}

	// Run Nuclei scanning if not skipped
	if !*skipNuclei {
		// Scan subdomains with default templates
		scanner := nuclei.NewScanner(outputDir)
		liveSubsFile := filepath.Join(outputDir, "live-subdomains.txt")
		shodanIPsFile := filepath.Join(outputDir, "shodan-ips.txt")

		if err := scanner.Run(liveSubsFile, shodanIPsFile); err != nil {
			logger.Error("Nuclei scanning failed: %v", err)
			color.Red("\n✗ Nuclei error: %v\n", err)
			// Don't exit - Nuclei errors are not critical
		} else {
			logger.Info("Nuclei scanning completed successfully")
		}

		// Run Nuclei on URL crawling results if they exist
		if !*skipUrlcrawl {
			runURLNucleiScans(outputDir)
		}
	} else {
		yellow := color.New(color.FgYellow, color.Bold)
		yellow.Println("\n[STEP 2] Nuclei Scanning - SKIPPED (use without -skip-nuclei to enable)")
		logger.Info("Nuclei scanning skipped by user")
	}

	// Print completion
	duration := time.Since(startTime)

	green.Println("\n╔═══════════════════════════════════════════════════════════════╗")
	green.Println("║                    SCAN COMPLETED                            ║")
	green.Println("╚═══════════════════════════════════════════════════════════════╝")
	yellow.Printf("  Total Duration: %s\n", formatDuration(duration))
	green.Printf("\n✓ Results saved in: %s\n", outputDir)
	green.Printf("✓ Logs saved in: %s/logs/\n\n", outputDir)

	logger.Info("Scan completed successfully in %s", formatDuration(duration))
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
	white.Println("  -skip-jsanalysis")
	white.Println("      Skip JavaScript file analysis (secrets, endpoints, domain links)")
	white.Println("  -skip-depconf")
	white.Println("      Skip dependency confusion detection (supply chain attack detection)")
	white.Println("  -skip-vulnscan")
	white.Println("      Skip vulnerability scanning (XSS)")
	white.Println("  -skip-cloudenum")
	white.Println("      Skip cloud enumeration (S3, Azure, GCP)")
	white.Println("  -skip-portscan")
	white.Println("      Skip port scanning (top 5000 ports)")
	white.Println("  -skip-nuclei")
	white.Println("      Skip Nuclei vulnerability scanning")
	white.Println("  -check-deps")
	white.Println("      Check if all dependencies are installed and exit")
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
	white.Println("  js-secrets.txt              - Secrets/API keys from JS files")
	white.Println("  endpoints-fuzzing.txt       - API endpoints extracted from JS for fuzzing")
	white.Println("  links-js.txt                - Live domain-specific links from JS files")
	white.Println("  dependency-confusion.txt    - ⚠ CRITICAL: Unclaimed NPM packages")
	white.Println("  params-filtered-xss.txt     - XSS candidate URLs (filtered with gf)")
	white.Println("  kxss-results.txt            - kxss scan results (potential XSS)")
	white.Println("  xss-vulnerable.txt          - Confirmed XSS vulnerabilities (dalfox)")
	white.Println("  open-ports.txt              - Open ports (verified with httpx)")
	white.Println("  cloud-resources.txt         - Discovered cloud resources")
	white.Println("  nuclei-results.txt          - Nuclei vulnerability scan results")
	white.Println("  fuzzing-nuclei-result.txt   - Nuclei fuzzing results (params)")
	white.Println("  js-nuclei-result.txt        - Nuclei JS exposure results")

	yellow.Println("\nTOOLS USED:")
	white.Println("  • Subdomain Discovery: subfinder, amass, assetfinder, findomain, massdns")
	white.Println("  • URL Crawling: waybackurls, gau, katana, gospider")
	white.Println("  • JavaScript Analysis: jsluice, trufflehog (secrets, endpoints, domain links)")
	white.Println("  • Dependency Confusion: NPM registry verification (supply chain attacks)")
	white.Println("  • Vulnerability Scanning: gf, kxss, dalfox (XSS only)")
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
