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

- **6 Parallel URL Discovery Tools** with individual timeouts:
  - waybackurls (5 hour timeout)
  - gau (5 hour timeout)
  - katana (5 hour timeout)
  - katana-params (5 hour timeout)
  - gospider (5 hour timeout)
  - webarchive-cdx (5 hour timeout)
- **No Domain Limits** - All tools process all discovered subdomains
- **Graceful Timeout Handling** - Saves partial results on timeout
- **Global Phase Timeout** - 10-hour max for entire URL crawling (configurable)
- **Deduplication with uro** - Removes duplicate URLs
- **Intelligent Filtering**:
  - Parameter URLs (for vulnerability testing)
  - JavaScript files (for analysis)
  - Sensitive files (.env, .json, config files, etc.)
- **Live Verification with httpx** - Confirms URLs are accessible

### ✅ Step 2.3: JavaScript File Analysis 🔥

**The goldmine for bug bounty hunters!** Modern web apps heavily rely on JavaScript, which often exposes:
- **Hardcoded API keys and tokens**
- **Hidden API endpoints**
- **Authentication secrets**
- **Database credentials**
- **Undisclosed subdomains**

**Three-Phase Analysis:**

1. **Secret Detection**:
   - **[jsluice](https://github.com/BishopFox/jsluice)** - Modern AST-based extraction (not just regex!)
   - **[trufflehog](https://github.com/trufflesecurity/trufflehog)** - Deep secret scanning (optional)
   - **Custom regex patterns** - API keys, AWS keys, JWT tokens, Firebase URLs, etc.
   - **Output format**: Shows URL followed by all secrets found (easy to investigate!)

2. **Endpoint Extraction**:
   - Extracts all API paths and endpoints from JS files
   - Understands string concatenation and dynamic URLs
   - **Output**: Clean paths ready for fuzzing (`api/admin`, `v1/users`, etc.)
   - Filters out static assets (.js, .css, images)
   - **Saved to**: `endpoints-fuzzing.txt`

3. **Domain-Specific Link Discovery**:
   - Finds all URLs ending with your target domain
   - Discovers hidden subdomains from JS references
   - **Verifies with httpx** - Only saves live links
   - **Saved to**: `links-js.txt`

**Why jsluice?** Unlike regex-based tools, jsluice uses **go-tree-sitter** to parse JavaScript AST, understanding how URLs are actually used in code (assigned to `document.location`, passed to `fetch()`, etc.)

**Concurrent Processing**: Processes 10 JS files simultaneously for maximum speed

**Optional**: Use `-skip-jsanalysis` to skip this step

### ✅ Step 2.4: Dependency Confusion Detection 🚨

**CRITICAL**: Supply chain attack detection! Finds internal NPM packages that could be hijacked by attackers.

**What is Dependency Confusion?**
A supply chain attack where attackers exploit how package managers resolve dependencies. If your build system uses an internal package like `company-auth` that isn't published on npm, an attacker can:
1. Publish a malicious package with the same name on public npm
2. Assign it a higher version number (e.g., 99.99.99)
3. Your build system installs the malicious package → **Remote Code Execution (RCE)**

**Real-World Impact:**
- ✅ **Alex Birsan** earned $130K+ from Apple, Microsoft, PayPal, Netflix, Shopify, Tesla, Yelp, Uber using this technique
- ✅ Companies lost internal secrets, API keys, AWS credentials
- ✅ Attackers gained RCE in CI/CD pipelines

**How It Works:**

1. **Extraction from JavaScript Files**:
   - `node_modules/package-name/lib/file.js` patterns
   - `require("package-name")` statements
   - `import from "package-name"` statements
   - Embedded package.json content
   - Webpack module IDs

2. **Source Map Analysis** (.map files):
   - Downloads and parses .js.map files
   - Extracts full internal paths like: `../node_modules/@company/internal-api/lib/auth.js`
   - **Why source maps?** They reveal original, unminified code structure

3. **NPM Registry Verification**:
   - Checks each package against `https://registry.npmjs.org/package-name`
   - If returns 404 → Package doesn't exist publicly → **CRITICAL FINDING**
   - Concurrent checking (10 packages at a time)

**Output:** `dependency-confusion.txt`
- Lists ALL unclaimed packages found
- Shows which JS file referenced each package
- Includes npm verification links
- **You manually verify and reserve these names ASAP**

**Why This Matters:**
- Internal packages in production JS = Attack surface
- Most companies don't realize their internal names are exposed
- Easy to exploit, hard to defend against
- Can lead to complete infrastructure compromise

**Optional**: Use `-skip-depconf` to skip this step

**Learn More:**
- [Alex Birsan's Original Research](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)
- [What is NPM Dependency Confusion (2025 Guide)](https://blogs.jsmon.sh/npm-dependency-confusion-organization-namespaces-2025/)
- [Snyk: Detect and Prevent Dependency Confusion](https://snyk.io/blog/detect-prevent-dependency-confusion-attacks-npm-supply-chain-security/)

### ✅ Step 2.5: Vulnerability Scanning (XSS)

- **XSS Detection Pipeline**:
  - gf pattern filtering for XSS candidates
  - kxss for quick XSS detection
  - dalfox for confirmed XSS vulnerabilities
- **Automated gf Pattern Installation**
- **Configurable Timeout** - 10-hour max (configurable via `.env`)

### ✅ Step 3: Port Scanning

- **Smart Port Discovery** - Scans top 5000 ports with nmap
- **Multi-Target Scanning** - Scans both live subdomains AND Shodan IPs
- **Intelligent Filtering** - Excludes default ports (80, 443)
- **Live Service Verification** - Uses httpx to verify discovered ports
- **URL Format Output** - Saves results as full URLs (e.g., https://test.com:8443)
- **Optional `-skip-portscan` flag**
- **Configurable Timeout** - 10-hour max (configurable via `.env`)

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
- **Individual Tool Timeouts** - Each URL crawl tool has 5-hour timeout
- **No Domain Limits** - All tools process all discovered subdomains
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
waybackurls gau katana gospider uro curl

# JavaScript analysis (required for -skip-jsanalysis=false)
jsluice trufflehog

# Vulnerability scanning (required for -skip-vulnscan=false)
gf kxss dalfox

# Cloud enumeration (required for -skip-cloudenum=false)
slurp cloud_enum

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
   WAYBACKURLS_TIMEOUT=300         # 5 hours
   GAU_TIMEOUT=300                 # 5 hours
   KATANA_TIMEOUT=300              # 5 hours
   KATANA_PARAMS_TIMEOUT=300       # 5 hours
   GOSPIDER_TIMEOUT=300            # 5 hours
   WEBARCHIVE_TIMEOUT=300          # 5 hours
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
├── js-secrets.txt                      # Secrets/API keys from JS files
├── endpoints-fuzzing.txt               # API endpoints for fuzzing
├── links-js.txt                        # Live domain-specific links from JS
├── dependency-confusion.txt            # ⚠ CRITICAL: Unclaimed NPM packages (supply chain risk!)
├── params-filtered-xss.txt             # XSS candidate URLs (gf filtered)
├── kxss-results.txt                    # kxss scan results
├── xss-vulnerable.txt                  # Confirmed XSS vulnerabilities
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
7. **URL Crawling** → 6 tools in parallel with 5-hour timeouts
8. **JavaScript Analysis** → Secrets, endpoints, domain links (optional)
9. **Dependency Confusion** → Detect unclaimed NPM packages (optional but recommended!)
10. **Vulnerability Scanning** → XSS detection (optional)
11. **Cloud Enumeration** → S3/Azure/GCP discovery (optional)
12. **Port Scanning** → Top 5000 ports with nmap (optional)
13. **Directory Fuzzing** → ffuf-based discovery (optional)
14. **Nuclei Scanning** → Template-based vuln scanning (optional)

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
- waybackurls: 5 hours (300 minutes)
- gau: 5 hours (300 minutes)
- katana: 5 hours (300 minutes)
- katana-params: 5 hours (300 minutes)
- gospider: 5 hours (300 minutes)
- webarchive-cdx: 5 hours (300 minutes)

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
