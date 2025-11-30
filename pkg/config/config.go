package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/fatih/color"
)

// Config holds all configuration values
type Config struct {
	// API Keys
	ShodanAPIKey    string
	VirusTotalKey   string
	AlienVaultKey   string

	// Paths
	PythonScript      string
	SubdomainWordlist string
	VHostWordlist     string
	DNSResolvers      string

	// Settings
	MaxVHostIPs        int
	WaymoreTimeout     int // in minutes
	WaymoreMaxDomains  int
}

// Load loads configuration from .env file and environment variables
// Priority: Environment Variables > .env file > defaults
func Load() (*Config, error) {
	cfg := &Config{
		// Default values
		PythonScript:      "/root/tools/subdomain-enum/subdomain-Enum.py",
		SubdomainWordlist: "/root/myLists/subdomains.txt",
		VHostWordlist:     "/root/myLists/vhost-wordlist.txt",
		DNSResolvers:      "/root/myLists/resolvers.txt",
		MaxVHostIPs:       50,
		WaymoreTimeout:    10,  // 10 minutes
		WaymoreMaxDomains: 100, // Process max 100 domains
	}

	// Try to find .env file
	envPaths := []string{
		".env",
		filepath.Join(".", ".env"),
		filepath.Join("..", ".env"),
		"/root/myScripts/.env",
	}

	var envFile string
	for _, path := range envPaths {
		if _, err := os.Stat(path); err == nil {
			envFile = path
			break
		}
	}

	// Load .env file if found
	if envFile != "" {
		if err := loadEnvFile(envFile); err != nil {
			yellow := color.New(color.FgYellow)
			yellow.Printf("⚠ Warning: Error loading %s: %v\n", envFile, err)
		}
	}

	// Load values (environment variables take precedence)
	cfg.ShodanAPIKey = getEnv("SHODAN_API_KEY", "")
	cfg.VirusTotalKey = getEnv("VT_API_KEY", "")
	cfg.AlienVaultKey = getEnv("ALIEN_API_KEY", "")
	cfg.PythonScript = getEnv("PYTHON_SCRIPT", cfg.PythonScript)
	cfg.SubdomainWordlist = getEnv("SUBDOMAIN_WORDLIST", cfg.SubdomainWordlist)
	cfg.VHostWordlist = getEnv("VHOST_WORDLIST", cfg.VHostWordlist)
	cfg.DNSResolvers = getEnv("DNS_RESOLVERS", cfg.DNSResolvers)
	cfg.MaxVHostIPs = getEnvInt("MAX_VHOST_IPS", cfg.MaxVHostIPs)
	cfg.WaymoreTimeout = getEnvInt("WAYMORE_TIMEOUT", cfg.WaymoreTimeout)
	cfg.WaymoreMaxDomains = getEnvInt("WAYMORE_MAX_DOMAINS", cfg.WaymoreMaxDomains)

	// Validate critical settings
	if cfg.ShodanAPIKey == "" {
		yellow := color.New(color.FgYellow, color.Bold)
		yellow.Println("⚠ Warning: SHODAN_API_KEY not set. Shodan features will be disabled.")
		yellow.Println("   Set it in .env file or export SHODAN_API_KEY=your_key")
	}

	return cfg, nil
}

// loadEnvFile loads environment variables from a file
func loadEnvFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse KEY=VALUE
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid format at line %d: %s", lineNum, line)
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Remove quotes if present
		value = strings.Trim(value, `"'`)

		// Only set if not already in environment
		if os.Getenv(key) == "" {
			os.Setenv(key, value)
		}
	}

	return scanner.Err()
}

// getEnv gets an environment variable or returns default
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvInt gets an integer environment variable or returns default
func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

// Validate checks if critical files and API keys exist
func (c *Config) Validate() []string {
	var warnings []string

	// Check wordlists
	if _, err := os.Stat(c.SubdomainWordlist); os.IsNotExist(err) {
		warnings = append(warnings, fmt.Sprintf("Subdomain wordlist not found: %s", c.SubdomainWordlist))
	}

	if _, err := os.Stat(c.VHostWordlist); os.IsNotExist(err) {
		warnings = append(warnings, fmt.Sprintf("VHost wordlist not found: %s", c.VHostWordlist))
	}

	if _, err := os.Stat(c.DNSResolvers); os.IsNotExist(err) {
		warnings = append(warnings, fmt.Sprintf("DNS resolvers not found: %s", c.DNSResolvers))
	}

	// Check Python script
	if _, err := os.Stat(c.PythonScript); os.IsNotExist(err) {
		warnings = append(warnings, fmt.Sprintf("Python script not found: %s", c.PythonScript))
	}

	return warnings
}
