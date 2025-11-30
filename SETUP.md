# Setup Instructions

## 🔐 Credential and API Key Configuration

This guide will help you securely configure your API keys and credentials for the Bug Bounty Reconnaissance Framework.

---

## Step 1: Create Your .env File

1. **Copy the example configuration:**
   ```bash
   cd /root/myScripts
   cp .env.example .env
   ```

2. **Edit the .env file:**
   ```bash
   nano .env
   # or use your preferred editor:
   vim .env
   ```

3. **Add your API keys:**
   ```bash
   # Shodan API Key (REQUIRED for Shodan features)
   SHODAN_API_KEY=your_actual_shodan_api_key_here

   # VirusTotal API Key (OPTIONAL - enhances gau results)
   VT_API_KEY=your_virustotal_key_here

   # AlienVault OTX API Key (OPTIONAL - enhances gau results)
   ALIEN_API_KEY=your_alienvault_key_here
   ```

---

## Step 2: Get Your API Keys

### Shodan API Key (Highly Recommended)
1. Visit: https://account.shodan.io/
2. Sign up or log in
3. Copy your API key from the dashboard
4. Paste it in your `.env` file

**Note:** The Shodan API key is essential for:
- IP collection via SSL certificates
- Enhanced subdomain discovery
- Better reconnaissance coverage

### VirusTotal API Key (Optional)
1. Visit: https://www.virustotal.com/
2. Sign up for a free account
3. Go to your profile → API Key
4. Copy and add to `.env`

### AlienVault OTX API Key (Optional)
1. Visit: https://otx.alienvault.com/
2. Create an account
3. Go to Settings → API Integration
4. Copy your OTX Key
5. Add to `.env`

---

## Step 3: Verify Your Configuration

Run the dependency checker to ensure everything is set up correctly:

```bash
./bin/recon -check-deps
```

This will:
- ✓ Check all required tools are installed
- ✓ Verify optional tools availability
- ✓ Show which features will be available

---

## Step 4: Secure Your Credentials

### ✅ DO's:
1. **Never commit `.env` to git** - It's already in `.gitignore`
2. **Use environment variables in production**
3. **Restrict file permissions:**
   ```bash
   chmod 600 .env
   ```
4. **Keep backups of your `.env` file in a secure location**

### ❌ DON'Ts:
1. Don't share your `.env` file
2. Don't commit API keys to git
3. Don't use the same keys across multiple projects
4. Don't store keys in plain text in documentation

---

## Step 5: CRITICAL - Rotate Exposed API Keys

**If you had the old hardcoded API key in your repository:**

### 1. Rotate Your Shodan API Key IMMEDIATELY:
```bash
# Go to https://account.shodan.io/
# Click "Regenerate" next to your API key
# Copy the new key
# Update your .env file with the new key
```

### 2. Remove Old API Key from Git History:

**Option A: Using BFG Repo-Cleaner (Recommended)**
```bash
# Download BFG
wget https://repo1.maven.org/maven2/com/madgag/bfg/1.14.0/bfg-1.14.0.jar

# Backup your repo first!
cd /root/myScripts
git clone --mirror git@github.com:amahrou1/myScripts.git myScripts-backup.git

# Remove the API key
java -jar bfg-1.14.0.jar --replace-text passwords.txt myScripts-backup.git

# Create passwords.txt with:
# j8PrRv5fW2Ox7Vt8PBJIdNokQv5lsBD1  # Old Shodan key

# Clean up
cd myScripts-backup.git
git reflog expire --expire=now --all && git gc --prune=now --aggressive
git push --force
```

**Option B: Using git filter-branch**
```bash
cd /root/myScripts

# Backup first!
git clone . ../myScripts-backup

# Remove the sensitive data
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch pkg/subdomains/subdomains.go config/config.env" \
  --prune-empty --tag-name-filter cat -- --all

# Force push (WARNING: This rewrites history)
git push origin --force --all
git push origin --force --tags
```

### 3. Notify Team Members (if applicable):
If this is a shared repository, inform all collaborators that they need to:
```bash
git pull --rebase
# Or fresh clone:
rm -rf myScripts
git clone git@github.com:amahrou1/myScripts.git
```

---

## Step 6: Environment-Based Configuration

For production environments, you can also use system environment variables:

```bash
# Add to ~/.bashrc or ~/.zshrc
export SHODAN_API_KEY="your_key_here"
export VT_API_KEY="your_vt_key_here"
export ALIEN_API_KEY="your_alien_key_here"

# Reload shell
source ~/.bashrc
```

**Priority Order:**
1. System environment variables (highest priority)
2. `.env` file
3. Default values (lowest priority)

---

## Step 7: Customize Tool Configuration

Edit your `.env` file to customize timeout and limits:

```bash
# Timeout for waymore (in minutes) - prevents hanging
WAYMORE_TIMEOUT=10

# Maximum domains to process with waymore - prevents overload
WAYMORE_MAX_DOMAINS=100

# VHost fuzzing - maximum IPs to test
MAX_VHOST_IPS=50
```

---

## Step 8: Test Your Setup

Run a small test scan to verify everything works:

```bash
# Build the project
make build

# Run a test scan on a small domain
./bin/recon -d example.com -o test-scan -skip-vhost -skip-cloudenum

# Check the logs
cat test-scan/logs/*.log
```

---

## Troubleshooting

### API Key Not Found
```
⚠ Warning: SHODAN_API_KEY not set. Shodan features will be disabled.
```

**Solution:**
1. Check your `.env` file exists: `ls -la .env`
2. Verify the key is set: `cat .env | grep SHODAN`
3. Ensure no extra spaces: `SHODAN_API_KEY=key` not `SHODAN_API_KEY = key`
4. Try exporting manually: `export SHODAN_API_KEY="your_key"`

### Waymore Still Hanging
```
waymore timeout occurred
```

**Solution:**
1. Reduce timeout in `.env`: `WAYMORE_TIMEOUT=5`
2. Reduce max domains: `WAYMORE_MAX_DOMAINS=50`
3. Or skip waymore entirely by modifying the code

### Missing Dependencies
```
✗ Missing required tools
```

**Solution:**
```bash
# Check what's missing
./bin/recon -check-deps

# Install missing tools (see README.md for instructions)
```

---

## Best Practices

### 1. Use Separate API Keys for Different Environments
```bash
# Development
SHODAN_API_KEY=dev_key_here

# Production
SHODAN_API_KEY=prod_key_here
```

### 2. Monitor API Usage
- Check Shodan usage: https://account.shodan.io/
- Most free tiers have rate limits
- Consider upgrading for heavy use

### 3. Regular Key Rotation
- Rotate keys every 3-6 months
- Immediately rotate if exposed
- Keep track of key expiration dates

### 4. Secure Storage
Consider using a secrets manager for production:
- HashiCorp Vault
- AWS Secrets Manager
- Azure Key Vault
- 1Password CLI

---

## Summary of Files

```
/root/myScripts/
├── .env                    # YOUR API KEYS (never commit!)
├── .env.example            # Template (safe to commit)
├── .gitignore              # Updated to exclude .env
├── config/
│   └── config.env          # OLD FILE - now deprecated, ignored by git
├── pkg/
│   └── config/
│       └── config.go       # NEW: Configuration loader
└── SETUP.md                # This file
```

---

## Quick Reference Commands

```bash
# Check dependencies
./bin/recon -check-deps

# Run with custom .env location
ENV_FILE=/path/to/custom/.env ./bin/recon -d domain.com -o results

# Test configuration
grep -v "^#" .env | grep -v "^$"  # Show active config

# Verify API keys are loaded
./bin/recon -d test.com -o test 2>&1 | grep "API key"
```

---

## Need Help?

1. Check logs: `/path/to/output/logs/recon_*.log`
2. Run with -check-deps to verify setup
3. Review this guide
4. Open an issue on GitHub (without sharing your keys!)

---

**Remember:** Your API keys are like passwords. Treat them with the same level of security!
