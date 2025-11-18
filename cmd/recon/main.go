package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/amahrou1/myScripts/pkg/subdomains"
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

	// Print completion
	duration := time.Since(startTime)
	green.Println("\n╔═══════════════════════════════════════════════════════════════╗")
	green.Println("║                    SCAN COMPLETED                            ║")
	green.Println("╚═══════════════════════════════════════════════════════════════╝")
	yellow.Printf("  Total Duration: %s\n", formatDuration(duration))
	green.Printf("\n✓ Results saved in: %s\n\n", outputDir)
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
	white.Println("  -h")
	white.Println("      Show this help message")

	yellow.Println("\nEXAMPLES:")
	white.Println("  # Basic scan")
	white.Println("  ./recon -d example.com -o results")
	white.Println()
	white.Println("  # Scan with custom output directory")
	white.Println("  ./recon -d avantgardportal.com -o /root/scans/avantgard")
	white.Println()
	white.Println("  # Skip VHost fuzzing for faster results")
	white.Println("  ./recon -d example.com -o results -skip-vhost")

	yellow.Println("\nOUTPUT FILES:")
	white.Println("  all-subdomains.txt   - All discovered subdomains (unique)")
	white.Println("  live-subdomains.txt  - Subdomains with live HTTP/HTTPS services")

	yellow.Println("\nTOOLS USED:")
	white.Println("  • Passive: subfinder, amass, assetfinder, findomain")
	white.Println("  • Active: massdns (if no wildcard)")
	white.Println("  • Verification: httpx")

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
