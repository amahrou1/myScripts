# Bug Bounty Reconnaissance Framework

A fast, efficient, and scalable reconnaissance framework for bug bounty hunting, written in Go.

## 🚀 Features

### ✅ Step 1: Subdomain Enumeration

- **Wildcard DNS Detection** - Automatically detects wildcard DNS configurations
- **Concurrent Passive Enumeration** - Runs 8 tools simultaneously:
  - subfinder, amass, assetfinder, findomain
  - Web Archive (Wayback Machine), crt.sh, subshodan
  - Python subdomain-Enum.py (custom script)
- **Brute Force with massdns** - Fast DNS brute forcing (skipped if wildcard detected)
- **Live Host Detection** - Uses httpx to verify live services
- **Smart VHost Fuzzing** - Discovers hidden subdomains via virtual host fuzzing
  - Filters out CDN/Cloud IPs (Cloudflare, AWS, Azure, GCP, Fastly, Akamai)
  - Limits to top 50 most common IPs
  - Optional `-skip-vhost` flag for faster scans
- **Deduplication** - Automatically removes duplicates and sorts results
- **Live Progress Tracking** - Real-time colored output
- **Configurable Timeout** - 10-hour max (configurable via `.env`)

### ✅ Step 2: URL Crawling & Discovery

- **7 Parallel URL Discovery Tools** with individual timeouts:
  - waybackurls (30 min timeout)
  - gau (30 min timeout, 200 domain limit)
  - katana (60 min timeout, 150 domain limit)
  - katana-params (60 min timeout, 150 domain limit)
  - waymore (10 min timeout, 100 domain limit)
  - gospider (60 min timeout, 100 domain limit)
  - webarchive-cdx (30 min timeout)
- **Smart Domain Limiting** - Prevents processing too many targets
- **Graceful Timeout Handling** - Saves partial results on timeout
- **Global Phase Timeout** - 10-hour max for entire URL crawling (configurable)
- **Deduplication with uro** - Removes duplicate URLs
- **Intelligent Filtering**:
  - Parameter URLs (for vulnerability testing)
  - JavaScript files (for analysis)
  - Sensitive files (.env, .json, config files, etc.)
- **Live Verification with httpx** - Confirms URLs are accessible

### ✅ Step 2.5: Vulnerability Scanning (XSS & SQLi)

- **XSS Detection Pipeline**:
  - gf pattern filtering for XSS candidates
  - kxss for quick XSS detection
  - dalfox for confirmed XSS vulnerabilities
- **SQLi Detection Pipeline**:
  - gf pattern filtering for SQLi candidates
  - ghauri for fast SQLi scanning
  - sqlmap for confirmed SQLi (limited targets)
- **Automated gf Pattern Installation**
- **Configurable Timeout** - 10-hour max (configurable via `.env`)

### ✅ Step 3: Port Scanning

- **Smart Port Discovery** - Scans top 1000 ports with nmap
- **Multi-Target Scanning** - Scans both live subdomains AND Shodan IPs
- **Intelligent Filtering** - Excludes default ports (80, 443)
- **Live Service Verification** - Uses httpx to verify discovered ports
- **URL Format Output** - Saves results as full URLs (e.g., https://test.com:8443)
- **Optional `-skip-portscan` flag**
- **Configurable Timeout** - 10-hour max (configurable via `.env`)

### ✅ Step 4: Directory Fuzzing

- **ffuf Integration** - Fast directory/file discovery
- **Smart Filtering** - Reduces false positives
- **Concurrent Fuzzing** - Multiple targets in parallel
- **Auto-calibration** - Accurate results
- **Timeout Management** - Prevents hanging

### ✅ Bonus: Cloud Enumeration

- **S3 Bucket Discovery** - Uses slurp for bucket permutations
- **Multi-Cloud Support** - AWS, Azure, GCP with cloud_enum
- **Targeted Scanning** - Main domain only (not subdomains)
- **Optional `-skip-cloudenum` flag**
- **Configurable Timeout** - 1-hour max (configurable via `.env`)

### ✅ Step 5: Nuclei Vulnerability Scanning

- **Automated Vulnerability Scanning** - Scans all discovered targets
- **Multi-Source Scanning** - Scans subdomains, IPs, and crawled URLs
- **Dual Template Support**:
  - Default: `/root/nuclei-templates` (Project Discovery)
  - Custom: `/root/test123` (your templates)
- **Severity Filtering** - Medium, high, and critical only
- **Fuzzing Templates** - Scans parameter URLs with fuzzing templates
- **JS Exposure Templates** - Scans JavaScript files for exposures
- **Optional `-skip-nuclei` flag**
- **Configurable Timeout** - 10-hour max (configurable via `.env`)

### 🔒 Security Features

- **Environment-Based Configuration** - API keys in `.env` (never in code)
- **Input Validation** - Domain, path, and URL sanitization
- **Comprehensive Logging** - Detailed logs in `{output}/logs/` directory
- **Dependency Checking** - Verify all tools are installed with `-check-deps`
- **Git History Cleanup Script** - Remove exposed secrets from history

### ⚡ Performance Features

- **Comprehensive Timeout Management** - No scan phase can hang indefinitely
- **Global Phase Timeouts** - Each major phase has max execution time (default: 10 hours)
- **Individual Tool Timeouts** - Each tool has its own timeout limit
- **Domain Limits** - Prevent processing too many targets
- **Graceful Degradation** - Saves partial results on timeout
- **Parallel Execution** - Multiple tools run simultaneously
- **Smart Filtering** - CDN/cloud IP exclusion, deduplication

---

## 📋 Prerequisites

### Required Tools

```bash
# Core tools (required)
httpx subfinder amass assetfinder findomain massdns dig nmap

# URL crawling tools (required for -skip-urlcrawl=false)
waybackurls gau katana waymore gospider uro

# Vulnerability scanning (required for -skip-vulnscan=false)
gf kxss dalfox ghauri sqlmap

# Cloud enumeration (required for -skip-cloudenum=false)
slurp cloud_enum

# Directory fuzzing (required for -skip-dirfuzz=false)
ffuf

# Nuclei (required for -skip-nuclei=false)
nuclei

# Shodan CLI (optional, enhances results)
shodan
```

**Quick Dependency Check:**
```bash
./bin/recon -check-deps
```

### Installation Guide

See [SETUP.md](SETUP.md) for detailed installation instructions for all tools.

---

## 🔧 Installation

```bash
# Clone the repository
cd /root/myScripts

# Create .env file from template
cp .env.example .env

# Edit .env and add your API keys
nano .env

# Build the binary
make build

# Or install system-wide
make install
```

This will create a binary at `bin/recon` (or install to `/usr/local/bin/recon`).

---

## ⚙️ Configuration

### Quick Setup

1. **Copy the example configuration:**
   ```bash
   cp .env.example .env
   ```

2. **Edit `.env` and add your API keys:**
   ```bash
   # Required for Shodan features
   SHODAN_API_KEY=your_shodan_api_key_here

   # Optional (enhances URL discovery)
   VT_API_KEY=your_virustotal_key_here
   ALIEN_API_KEY=your_alienvault_key_here
   ```

3. **Customize timeout settings (optional):**
   ```bash
   # Global phase timeouts (in minutes)
   SUBDOMAIN_ENUM_TIMEOUT=600      # 10 hours
   URL_CRAWLING_TIMEOUT=600        # 10 hours
   PORT_SCAN_TIMEOUT=600           # 10 hours
   VULN_SCAN_TIMEOUT=600           # 10 hours
   NUCLEI_SCAN_TIMEOUT=600         # 10 hours
   CLOUD_ENUM_TIMEOUT=60           # 1 hour

   # Individual tool timeouts (in minutes)
   WAYMORE_TIMEOUT=10              # 10 minutes
   GAU_TIMEOUT=30                  # 30 minutes
   KATANA_TIMEOUT=60               # 1 hour
   GOSPIDER_TIMEOUT=60             # 1 hour

   # Domain limits (prevents processing too many targets)
   WAYMORE_MAX_DOMAINS=100
   GAU_MAX_DOMAINS=200
   KATANA_MAX_DOMAINS=150
   GOSPIDER_MAX_DOMAINS=100
   ```

**See [SETUP.md](SETUP.md) for complete configuration guide.**

---

## 📖 Usage

### Basic Usage

```bash
./bin/recon -d example.com -o results
```

### Command Line Options

```
-d string
    Target domain (required)
    Example: example.com

-o string
    Output directory (required)
    Example: results or /root/scans/target-name

-skip-vhost
    Skip VHost fuzzing (faster, recommended for large scans)

-skip-urlcrawl
    Skip URL crawling and discovery

-skip-vulnscan
    Skip vulnerability scanning (XSS & SQLi)

-skip-cloudenum
    Skip cloud enumeration (S3, Azure, GCP)

-skip-portscan
    Skip port scanning

-skip-nuclei
    Skip Nuclei vulnerability scanning

-check-deps
    Check if all dependencies are installed and exit

-h
    Show help message
```

### Examples

```bash
# Full scan (all features)
./bin/recon -d example.com -o results

# Check dependencies first
./bin/recon -check-deps

# Fast scan (skip VHost and port scanning)
./bin/recon -d example.com -o results -skip-vhost -skip-portscan

# Subdomain enumeration only
./bin/recon -d example.com -o results -skip-vhost -skip-urlcrawl -skip-portscan -skip-nuclei

# Skip active crawling (faster URL discovery)
./bin/recon -d example.com -o results -skip-vhost
```

---

## 📁 Output Structure

After running a scan, the output directory will contain:

```
results/
├── logs/
│   └── recon_2025-01-15_10-30-45.log   # Detailed execution log
├── all-subdomains.txt                  # All discovered subdomains
├── live-subdomains.txt                 # Live HTTP/HTTPS subdomains
├── vhost-subdomains.txt                # VHost-discovered subdomains
├── shodan-ips.txt                      # Shodan SSL certificate IPs
├── unique-urls.txt                     # All unique URLs
├── params.txt                          # Live URLs with parameters
├── live-js.txt                         # Live JavaScript files
├── sensitive-files.txt                 # Sensitive files (.env, .json, etc.)
├── params-filtered-xss.txt             # XSS candidate URLs (gf filtered)
├── params-filtered-sqli.txt            # SQLi candidate URLs (gf filtered)
├── kxss-results.txt                    # kxss scan results
├── xss-vulnerable.txt                  # Confirmed XSS vulnerabilities
├── ghauri-results.txt                  # Ghauri SQLi scan results
├── ghauri-vulnerable-urls.txt          # Confirmed SQLi vulnerabilities
├── sqlmap-results.txt                  # SQLmap confirmation results
├── open-ports.txt                      # Live services on non-standard ports
├── cloud-resources.txt                 # Discovered cloud resources
├── fuzz.txt                            # Directory fuzzing results
├── nuclei-results.txt                  # Nuclei scan results
├── fuzzing-nuclei-result.txt           # Nuclei fuzzing scan results
└── js-nuclei-result.txt                # Nuclei JS exposure results
```

---

## 🎯 Workflow

The tool executes the following workflow:

1. **Wildcard Detection** → Tests for wildcard DNS
2. **Passive Enumeration** → 8 tools in parallel
3. **DNS Brute Forcing** → massdns (if no wildcard)
4. **Live Host Detection** → httpx verification
5. **Shodan IP Collection** → SSL certificate search
6. **VHost Fuzzing** → Discover hidden subdomains (optional)
7. **URL Crawling** → 7 tools in parallel with timeouts
8. **Vulnerability Scanning** → XSS & SQLi detection (optional)
9. **Cloud Enumeration** → S3/Azure/GCP discovery (optional)
10. **Port Scanning** → Top 1000 ports with nmap (optional)
11. **Directory Fuzzing** → ffuf-based discovery (optional)
12. **Nuclei Scanning** → Template-based vuln scanning (optional)

**Each phase has configurable timeouts to prevent indefinite hanging.**

---

## ⏱️ Timeout Management

**Global Phase Timeouts (default: 10 hours each):**
- Subdomain Enumeration: 600 minutes
- URL Crawling: 600 minutes
- Port Scanning: 600 minutes
- Vulnerability Scanning: 600 minutes
- Nuclei Scanning: 600 minutes
- Cloud Enumeration: 60 minutes

**Individual Tool Timeouts:**
- waymore: 10 minutes (100 domain limit)
- gau: 30 minutes (200 domain limit)
- katana: 60 minutes (150 domain limit)
- gospider: 60 minutes (100 domain limit)
- waybackurls: 30 minutes
- webarchive-cdx: 30 minutes

**All timeouts are configurable via `.env` file.**

---

## 🚀 Current Feature Status

- ✅ Step 1: Subdomain Enumeration
- ✅ Step 2: URL Crawling & Discovery
- ✅ Step 2.5: Vulnerability Scanning (XSS & SQLi)
- ✅ Step 3: Port Scanning
- ✅ Step 4: Directory Fuzzing
- ✅ Step 5: Nuclei Vulnerability Scanning
- ✅ Bonus: Cloud Enumeration (S3, Azure, GCP)
- ✅ Security: Environment-based configuration
- ✅ Performance: Comprehensive timeout management
- ✅ Logging: Detailed execution logs
- ✅ Validation: Input sanitization & dependency checking

---

## 🔐 Security Best Practices

1. **Never commit `.env` file** - It's in `.gitignore`
2. **Rotate API keys regularly** - See [SETUP.md](SETUP.md)
3. **Use strong permissions** - `chmod 600 .env`
4. **Clean git history** - Use `scripts/remove-api-key-from-history.sh` if needed
5. **Validate domains** - Built-in input validation prevents injection

---

## 📚 Documentation

- **[SETUP.md](SETUP.md)** - Complete setup guide with credential management
- **[.env.example](.env.example)** - Configuration template
- **README.md** - This file

---

## 🤝 Contributing

This is a private repository for personal bug bounty work.

---

## 📝 License

Private - Not for distribution

---

## ⚠️ Disclaimer

**This tool is for authorized security testing only.** Always ensure you have explicit permission before scanning any target. Unauthorized scanning may be illegal in your jurisdiction.

---

## 🆘 Troubleshooting

### URL Crawling Hanging?
✅ **Fixed!** All tools have individual timeouts + global 10-hour phase timeout.

### Missing Dependencies?
```bash
./bin/recon -check-deps
```

### API Keys Not Working?
Check your `.env` file is in the correct location and properly formatted.

### Logs?
```bash
cat results/logs/recon_*.log
```

For detailed troubleshooting, see [SETUP.md](SETUP.md).
