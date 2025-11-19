# Bug Bounty Reconnaissance Framework

A fast, efficient, and scalable reconnaissance framework for bug bounty hunting, written in Go.

## 🚀 Features

### Step 1: Subdomain Enumeration

- ✅ **Wildcard DNS Detection** - Automatically detects wildcard DNS configurations
- ✅ **Concurrent Passive Enumeration** - Runs 8 tools simultaneously:
  - subfinder
  - amass
  - assetfinder
  - findomain
  - **Web Archive (Wayback Machine)** - Historical subdomain data
  - **crt.sh** - Certificate Transparency logs
  - **subshodan** - Shodan API subdomain discovery
  - **Python subdomain-Enum.py** - Custom Python enumeration script
- ✅ **Brute Force with massdns** - Fast DNS brute forcing (skipped if wildcard detected)
- ✅ **Live Host Detection** - Uses httpx to verify live services
- ✅ **Smart VHost Fuzzing** - Discovers hidden subdomains via virtual host fuzzing
  - Extracts IPs from discovered subdomains
  - Queries Shodan for IPs via SSL certificates
  - **Filters out CDN/Cloud IPs** (Cloudflare, AWS, Azure, GCP, Fastly, Akamai)
  - **Limits to top 50 most common IPs** (faster, more relevant)
  - **Uses dedicated VHost wordlist** (120 entries, focused on common vhosts)
  - **Live progress tracking** (shows current IP being tested)
  - **Optional -skip-vhost flag** for faster scans
  - Uses ffuf for concurrent VHost fuzzing
  - Filters results to find truly new subdomains
- ✅ **Deduplication** - Automatically removes duplicates and sorts results
- ✅ **Live Progress Tracking** - Real-time colored output showing progress
- ✅ **Organized Output** - Structured results in custom output directories

### Step 2: Nuclei Vulnerability Scanning

- ✅ **Automated Vulnerability Scanning** - Scans all discovered targets with Nuclei
- ✅ **Multi-Source Scanning** - Scans both live subdomains and Shodan IPs
- ✅ **Dual Template Support** - Uses both default and custom templates
  - Default: `/root/nuclei-templates` (Project Discovery templates)
  - Custom: `/root/test123` (Your custom templates)
- ✅ **Severity Filtering** - Scans for low, medium, high, and critical vulnerabilities
- ✅ **Real-time Output** - Shows scan progress and findings as they happen
- ✅ **Optional -skip-nuclei flag** - Skip Nuclei scanning for faster runs
- ✅ **Organized Results** - Saves findings to `nuclei.txt`

### Step 3: Port Scanning

- ✅ **Smart Port Discovery** - Scans top 5000 ports on all targets
- ✅ **Multi-Target Scanning** - Scans both live subdomains AND Shodan IPs
- ✅ **Intelligent Filtering** - Excludes default ports (80, 443) to focus on interesting services
- ✅ **Live Service Verification** - Uses httpx to verify discovered ports are actually live
- ✅ **URL Format Output** - Saves results as full URLs (e.g., https://test.com:8443)
- ✅ **Fast Scanning with naabu** - Uses Project Discovery's naabu for speed
- ✅ **Optional -skip-portscan flag** - Skip port scanning for faster runs
- ✅ **Organized Results** - Saves live services to `open-ports.txt`

## 📋 Prerequisites

### Required Tools

Make sure these tools are installed and available in your PATH:

```bash
# Check if tools are installed
which subfinder amass assetfinder findomain massdns httpx dig ffuf shodan nuclei naabu
```

**Installation on Ubuntu/Debian:**

```bash
# Go (if not already installed)
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Amass
go install -v github.com/owasp-amass/amass/v4/...@master

# Assetfinder
go install -v github.com/tomnomnom/assetfinder@latest

# Findomain
wget https://github.com/findomain/findomain/releases/latest/download/findomain-linux
chmod +x findomain-linux
sudo mv findomain-linux /usr/local/bin/findomain

# Httpx
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Massdns
git clone https://github.com/blechschmidt/massdns.git
cd massdns
make
sudo make install

# ffuf (for VHost fuzzing)
go install github.com/ffuf/ffuf@latest

# Shodan CLI (for IP collection)
pip install shodan
# Configure with your API key:
shodan init YOUR_API_KEY

# Nuclei (for vulnerability scanning)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# Update nuclei templates
nuclei -update-templates

# Naabu (for port scanning)
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
```

### Required Wordlists

- Subdomain wordlist: `/root/myLists/subdomains.txt`
- VHost wordlist: `/root/myLists/vhost-wordlist.txt` (auto-created from config/)
- DNS resolvers: `/root/myLists/resolvers.txt`

### Configuration

Edit `config/config.env` to customize:
- Shodan API key
- Python script path
- Wordlist locations
- VHost fuzzing settings (max IPs to test)

## 🔧 Installation

```bash
# Clone the repository
cd /root/myScripts

# Build the binary
make build

# Or install system-wide
make install
```

This will create a binary at `bin/recon` (or install to `/usr/local/bin/recon`).

## 📖 Usage

### Basic Usage

```bash
./bin/recon -d example.com -o results
```

### Command Line Options

```
-d string
    Target domain (required)
    Example: example.com or avantgardportal.com

-o string
    Output directory (required)
    Example: results or /root/scans/target-name

-skip-vhost
    Skip VHost fuzzing (faster, recommended for large scans)
    VHost fuzzing can be slow on large IP sets

-skip-portscan
    Skip port scanning (top 5000 ports)

-skip-nuclei
    Skip Nuclei vulnerability scanning

-h
    Show help message
```

### Examples

```bash
# Scan example.com and save to 'results' directory
./bin/recon -d example.com -o results

# Scan with absolute path
./bin/recon -d avantgardportal.com -o /root/scans/avantgard

# Skip VHost fuzzing for faster results
./bin/recon -d example.com -o results -skip-vhost

# Skip port scanning
./bin/recon -d example.com -o results -skip-vhost -skip-portscan

# Subdomain enum only (fastest)
./bin/recon -d example.com -o results -skip-vhost -skip-portscan -skip-nuclei

# After installation (system-wide)
recon -d target.com -o /root/recon/target
```

## 📁 Output Structure

After running a scan, the output directory will contain:

```
results/
├── all-subdomains.txt      # All unique subdomains found (includes vhost results)
├── live-subdomains.txt     # Subdomains with live HTTP/HTTPS services
├── vhost-subdomains.txt    # Subdomains discovered via VHost fuzzing (if any)
├── shodan-ips.txt          # IPs collected from Shodan
├── open-ports.txt          # Live services on non-standard ports
└── nuclei.txt              # Nuclei vulnerability scan results
```

### Output Files

- **all-subdomains.txt**: Complete list of unique subdomains from all sources (passive + brute force + vhost)
- **live-subdomains.txt**: Subdomains verified to have active web services (HTTP/HTTPS)
- **vhost-subdomains.txt**: Subdomains discovered specifically via VHost fuzzing (created only if VHost finds new results)
- **shodan-ips.txt**: IPs collected from Shodan via SSL certificate search
- **open-ports.txt**: Live services on non-standard ports (e.g., https://example.com:8443)
- **nuclei.txt**: Vulnerability findings from Nuclei scans (low, medium, high, critical severities)

## 🎯 Workflow

The tool executes the following workflow:

1. **Wildcard Detection**
   - Tests for wildcard DNS using random subdomains
   - If detected, brute force is skipped

2. **Passive Enumeration** (Concurrent)
   - Runs 8 sources simultaneously (subfinder, amass, assetfinder, findomain, wayback, crt.sh, subshodan, python-enum)
   - Collects subdomains from multiple sources
   - Shows progress for each tool

3. **Brute Force** (Conditional)
   - Uses massdns with custom wordlist
   - Only runs if no wildcard detected
   - Fast DNS resolution

4. **Deduplication**
   - Combines all results
   - Removes duplicates
   - Sorts alphabetically

5. **Live Host Detection**
   - Verifies which subdomains are live
   - Uses httpx for HTTP/HTTPS probing
   - Saves live hosts separately

6. **VHost Fuzzing** (Advanced - Optional with -skip-vhost)
   - Extracts IPs from discovered subdomains
   - Collects IPs from Shodan via SSL certificate search
   - Filters out CDN/Cloud provider IPs (Cloudflare, AWS, Azure, GCP, etc.)
   - Selects top 50 most common IPs for targeted fuzzing
   - Uses dedicated small VHost wordlist (120 entries)
   - Shows live progress for each IP being tested
   - Runs ffuf for virtual host fuzzing on selected IPs
   - Discovers hidden subdomains without DNS records
   - Filters out already known subdomains
   - Verifies if vhost-discovered subdomains are live

## 🎨 Output Example

```
╔═══════════════════════════════════════════════════════════════╗
║                      SCAN INFORMATION                        ║
╚═══════════════════════════════════════════════════════════════╝
  Target Domain    : example.com
  Output Directory : /root/results
  Start Time       : 2025-01-15 10:30:45

[*] Starting Subdomain Enumeration for: example.com

═══════════════════════════════════════════════════════════════
[Step 1/5] Wildcard DNS Detection
═══════════════════════════════════════════════════════════════
✓ No wildcard detected. Brute force will be performed.

═══════════════════════════════════════════════════════════════
[Step 2/5] Passive Subdomain Enumeration
═══════════════════════════════════════════════════════════════
✓ subfinder: 45 subdomains (3.21s)
✓ assetfinder: 32 subdomains (2.87s)
✓ findomain: 38 subdomains (4.12s)
✓ amass: 67 subdomains (15.43s)
✓ Found 182 subdomains from passive sources
```

## 🛠️ Configuration

The tool is pre-configured with sensible defaults. To customize:

**Quick Config (Recommended):**
Edit `config/config.env` to change:
- Shodan API key
- Python script path
- Wordlist locations

**Advanced Config:**
Edit `pkg/subdomains/subdomains.go` to modify:
- Tool timeouts
- HTTP client settings
- Additional enumeration sources

## 🚀 Current Steps

- ✅ Step 1: Subdomain Enumeration (Complete)
- ✅ Step 2: Nuclei Vulnerability Scanning (Complete)
- ✅ Step 3: Port Scanning (Complete)
- ⏳ Step 4: Directory Fuzzing
- ⏳ Step 5: URL Crawling
- ⏳ Step 6: JavaScript File Collection
- ⏳ Step 7: Secret Extraction
- ⏳ Step 8: Endpoint Extraction
- ⏳ Step 9: Vulnerability Scanning

## 🤝 Contributing

This is a private repository for personal bug bounty work.

## 📝 License

Private - Not for distribution

## ⚠️ Disclaimer

This tool is for authorized security testing only. Always ensure you have permission before scanning any target.