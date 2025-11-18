# Bug Bounty Reconnaissance Framework

A fast, efficient, and scalable reconnaissance framework for bug bounty hunting, written in Go.

## 🚀 Features

### Step 1: Subdomain Enumeration (Current)

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
- ✅ **VHost Fuzzing** - Discovers hidden subdomains via virtual host fuzzing
  - Extracts IPs from discovered subdomains
  - Queries Shodan for IPs via SSL certificates (status codes: 200, 403, 401, 404, 503, 301, 302, 307)
  - Uses ffuf for concurrent VHost fuzzing
  - Filters results to find truly new subdomains
- ✅ **Deduplication** - Automatically removes duplicates and sorts results
- ✅ **Live Progress Tracking** - Real-time colored output showing progress
- ✅ **Organized Output** - Structured results in custom output directories

## 📋 Prerequisites

### Required Tools

Make sure these tools are installed and available in your PATH:

```bash
# Check if tools are installed
which subfinder amass assetfinder findomain massdns httpx dig ffuf shodan
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
```

### Required Wordlists

- Subdomain wordlist: `/root/myLists/subdomains.txt`
- DNS resolvers: `/root/myLists/resolvers.txt`

### Configuration

Edit `config/config.env` to customize:
- Shodan API key
- Python script path
- Wordlist locations

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

-h
    Show help message
```

### Examples

```bash
# Scan example.com and save to 'results' directory
./bin/recon -d example.com -o results

# Scan with absolute path
./bin/recon -d avantgardportal.com -o /root/scans/avantgard

# After installation (system-wide)
recon -d target.com -o /root/recon/target
```

## 📁 Output Structure

After running a scan, the output directory will contain:

```
results/
├── all-subdomains.txt      # All unique subdomains found (includes vhost results)
├── live-subdomains.txt     # Subdomains with live HTTP/HTTPS services
└── vhost-subdomains.txt    # Subdomains discovered via VHost fuzzing (if any)
```

### Output Files

- **all-subdomains.txt**: Complete list of unique subdomains from all sources (passive + brute force + vhost)
- **live-subdomains.txt**: Subdomains verified to have active web services (HTTP/HTTPS)
- **vhost-subdomains.txt**: Subdomains discovered specifically via VHost fuzzing (created only if VHost finds new results)

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

6. **VHost Fuzzing** (Advanced)
   - Extracts IPs from discovered subdomains
   - Collects IPs from Shodan via SSL certificate search
   - Runs ffuf for virtual host fuzzing on each IP
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

## 🚀 Coming Soon (Future Steps)

- ✅ Step 1: Subdomain Enumeration (Complete)
- ⏳ Step 2: Nuclei Scanning
- ⏳ Step 3: Port Scanning & Shodan Integration
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