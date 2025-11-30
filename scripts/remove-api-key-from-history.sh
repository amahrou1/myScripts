#!/bin/bash

# Script to remove exposed Shodan API key from git history
# WARNING: This will rewrite git history!

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║  WARNING: GIT HISTORY CLEANUP - READ CAREFULLY!              ║${NC}"
echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
echo ""
echo -e "${YELLOW}This script will:${NC}"
echo "  1. Rewrite your entire git history"
echo "  2. Remove the exposed Shodan API key from all commits"
echo "  3. Force push to remote (if confirmed)"
echo ""
echo -e "${RED}BEFORE RUNNING:${NC}"
echo "  ✓ Make sure you have rotated your Shodan API key at https://account.shodan.io/"
echo "  ✓ Backup your repository first"
echo "  ✓ Notify all team members about history rewrite"
echo "  ✓ Ensure no one is working on the repo"
echo ""
echo -e "${YELLOW}Files that will be cleaned:${NC}"
echo "  - pkg/subdomains/subdomains.go"
echo "  - config/config.env"
echo ""

# Confirm API key rotation
read -p "Have you rotated your Shodan API key? (yes/no): " ROTATED
if [ "$ROTATED" != "yes" ]; then
    echo -e "${RED}Please rotate your API key first!${NC}"
    echo "Go to: https://account.shodan.io/"
    exit 1
fi

# Confirm backup
read -p "Have you backed up your repository? (yes/no): " BACKED_UP
if [ "$BACKED_UP" != "yes" ]; then
    echo -e "${YELLOW}Creating backup now...${NC}"
    BACKUP_DIR="../myScripts-backup-$(date +%Y%m%d-%H%M%S)"
    git clone . "$BACKUP_DIR"
    echo -e "${GREEN}Backup created at: $BACKUP_DIR${NC}"
fi

# Final confirmation
echo ""
echo -e "${RED}FINAL WARNING: This will rewrite git history!${NC}"
read -p "Type 'REWRITE HISTORY' to continue: " CONFIRM

if [ "$CONFIRM" != "REWRITE HISTORY" ]; then
    echo -e "${YELLOW}Aborted.${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}Starting cleanup...${NC}"

# Method 1: Using git filter-branch
echo -e "${YELLOW}[1/4] Removing sensitive files from history...${NC}"

# Create a temporary file with the old API key pattern
cat > /tmp/api-key-patterns.txt << 'EOF'
j8PrRv5fW2Ox7Vt8PBJIdNokQv5lsBD1
SHODAN_API_KEY=j8PrRv5fW2Ox7Vt8PBJIdNokQv5lsBD1
ShodanAPIKey:  "j8PrRv5fW2Ox7Vt8PBJIdNokQv5lsBD1"
EOF

# Use git filter-branch to remove the API key
git filter-branch --force --index-filter \
  'git rm --cached --ignore-unmatch config/config.env || true' \
  --prune-empty --tag-name-filter cat -- --all

echo -e "${YELLOW}[2/4] Replacing API key occurrences in all commits...${NC}"

# Replace the API key with a placeholder in all files
git filter-branch --force --tree-filter '
  find . -type f -name "*.go" -o -name "*.env" | while read file; do
    if [ -f "$file" ]; then
      sed -i "s/j8PrRv5fW2Ox7Vt8PBJIdNokQv5lsBD1/REMOVED_FOR_SECURITY/g" "$file" 2>/dev/null || true
      sed -i "s/ShodanAPIKey:  \"REMOVED_FOR_SECURITY\"/ShodanAPIKey:  os.Getenv(\"SHODAN_API_KEY\")/g" "$file" 2>/dev/null || true
    fi
  done
' --prune-empty --tag-name-filter cat -- --all

echo -e "${YELLOW}[3/4] Cleaning up refs and garbage collection...${NC}"

# Clean up refs
rm -rf .git/refs/original/

# Expire all old refs
git reflog expire --expire=now --all

# Garbage collect
git gc --prune=now --aggressive

echo -e "${GREEN}[4/4] Cleanup complete!${NC}"
echo ""

# Show the changes
echo -e "${YELLOW}Verifying cleanup...${NC}"
if git log --all --full-history --source --extra=all -S "j8PrRv5fW2Ox7Vt8PBJIdNokQv5lsBD1" | grep -q "j8PrRv5fW2Ox7Vt8PBJIdNokQv5lsBD1"; then
    echo -e "${RED}WARNING: API key still found in history!${NC}"
    echo "You may need to use BFG Repo-Cleaner for more thorough cleaning."
    exit 1
else
    echo -e "${GREEN}✓ API key successfully removed from history${NC}"
fi

echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "  1. Review changes: git log --oneline --graph"
echo "  2. Test the repository: make build && ./bin/recon -check-deps"
echo "  3. Force push to remote (WARNING: destructive!)"
echo ""
echo -e "${RED}To force push (ONLY if you're sure):${NC}"
echo "  git push origin --force --all"
echo "  git push origin --force --tags"
echo ""
echo -e "${YELLOW}All team members will need to:${NC}"
echo "  rm -rf myScripts"
echo "  git clone <repository-url>"
echo ""

# Ask if user wants to force push now
read -p "Do you want to force push NOW? (yes/no): " PUSH_NOW
if [ "$PUSH_NOW" = "yes" ]; then
    echo -e "${YELLOW}Force pushing to remote...${NC}"
    git push origin --force --all
    git push origin --force --tags
    echo -e "${GREEN}✓ Force push complete!${NC}"
    echo -e "${RED}⚠ Notify all team members immediately!${NC}"
else
    echo -e "${YELLOW}Skipped force push. Remember to push when ready.${NC}"
fi

# Cleanup temp file
rm -f /tmp/api-key-patterns.txt

echo ""
echo -e "${GREEN}═══════════════════════════════════════${NC}"
echo -e "${GREEN}   Git History Cleanup Complete!${NC}"
echo -e "${GREEN}═══════════════════════════════════════${NC}"
