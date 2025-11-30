package utils

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// ValidateDomain validates and sanitizes a domain name
func ValidateDomain(domain string) (string, error) {
	// Remove any protocol if present
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimSpace(domain)
	domain = strings.ToLower(domain)

	// Remove trailing slash and path
	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[:idx]
	}

	// Basic domain validation regex
	// Allows: letters, numbers, hyphens, dots
	domainRegex := regexp.MustCompile(`^([a-z0-9]([-a-z0-9]*[a-z0-9])?\.)+[a-z]{2,}$`)

	if !domainRegex.MatchString(domain) {
		return "", fmt.Errorf("invalid domain format: %s", domain)
	}

	// Additional validation: no spaces, no special chars
	if strings.ContainsAny(domain, " \t\n\r;|&$`<>") {
		return "", fmt.Errorf("domain contains invalid characters: %s", domain)
	}

	// Max length check (253 chars for domain)
	if len(domain) > 253 {
		return "", fmt.Errorf("domain too long: %s", domain)
	}

	return domain, nil
}

// SanitizeFilePath sanitizes a file path to prevent directory traversal
func SanitizeFilePath(path string) (string, error) {
	// Check for directory traversal attempts
	if strings.Contains(path, "..") {
		return "", fmt.Errorf("invalid path: directory traversal detected")
	}

	// Check for null bytes
	if strings.Contains(path, "\x00") {
		return "", fmt.Errorf("invalid path: null byte detected")
	}

	return path, nil
}

// ValidateURL validates a URL
func ValidateURL(rawURL string) (string, error) {
	rawURL = strings.TrimSpace(rawURL)

	if rawURL == "" {
		return "", fmt.Errorf("empty URL")
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %v", err)
	}

	// Ensure scheme is http or https
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return "", fmt.Errorf("invalid URL scheme: %s", parsedURL.Scheme)
	}

	// Ensure host is present
	if parsedURL.Host == "" {
		return "", fmt.Errorf("URL missing host")
	}

	return rawURL, nil
}

// SanitizeCommand sanitizes command arguments to prevent injection
func SanitizeCommand(arg string) (string, error) {
	// Check for dangerous characters
	dangerous := []string{";", "|", "&", "$", "`", "\n", "\r", "$(", "${"}

	for _, char := range dangerous {
		if strings.Contains(arg, char) {
			return "", fmt.Errorf("potentially dangerous character in argument: %s", char)
		}
	}

	return arg, nil
}
