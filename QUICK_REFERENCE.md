# HSOCIETY Quick Reference Card

## 📦 Installation

```bash
# Ubuntu/Debian
sudo apt install whois dnsutils curl jq openssl

# macOS
brew install whois bind curl jq openssl

# Fedora/RHEL
sudo dnf install whois bind-utils curl jq openssl

# Make executable
chmod +x hsociety_recon.sh
```

## 🚀 Basic Usage

```bash
# Simple scan (console output only)
./hsociety_recon.sh example.com

# Save output to file
./hsociety_recon.sh -s example.com

# Verbose mode (detailed output)
./hsociety_recon.sh -v example.com

# Custom timeout (30 seconds)
./hsociety_recon.sh -t 30 example.com

# Custom output directory
./hsociety_recon.sh -o ./my_scans example.com

# All options combined
./hsociety_recon.sh -s -v -t 20 -o ./reports example.com
```

## ⚙️ Command-Line Options

| Option | Short | Description | Default | Example |
|--------|-------|-------------|---------|---------|
| `--save` | `-s` | Save output to timestamped file | false | `-s` |
| `--verbose` | `-v` | Show detailed output | false | `-v` |
| `--timeout N` | `-t N` | Set timeout in seconds | 10 | `-t 30` |
| `--output DIR` | `-o DIR` | Custom output directory | `./hsociety_recon` | `-o ./scans` |
| `--help` | `-h` | Show help message and exit | - | `-h` |

## 🔍 Reconnaissance Modules

### Module 1: WHOIS Information
**What it does:**
- Registrar details
- Domain registration dates (created, expires, updated)
- Name servers
- Registrant contact info (verbose mode only)

### Module 2: DNS Records
**What it does:**
- **A Records** - IPv4 addresses
- **AAAA Records** - IPv6 addresses
- **NS Records** - Name servers
- **MX Records** - Mail servers with priority
- **TXT Records** - SPF, DKIM, verification
- **CNAME Records** - Canonical names

### Module 3: Subdomain Discovery
**What it does:**
- Queries Certificate Transparency logs (crt.sh)
- Finds subdomains from SSL certificates
- Removes wildcards and duplicates
- Returns unique subdomain list

### Module 4: Subdomain Resolution
**What it does:**
- Resolves discovered subdomains to IPs
- Maps subdomain → IP relationships
- Shows failed resolutions in verbose mode
- Saves IPs for next module

### Module 5: IP WHOIS Lookup
**What it does:**
- Organization/owner information
- Geographic location (country)
- IP ranges and CIDR blocks
- Network details (verbose mode)

### Module 6: Technology Detection
**What it does:**
- Web server identification (nginx, Apache, IIS)
- Programming language/framework detection
- CMS identification (WordPress, Joomla, Drupal)
- JavaScript frameworks (React, Angular, Vue)
- Security header analysis

### Module 7: SSL/TLS Certificate Analysis
**What it does:**
- Certificate subject and issuer
- Validity dates (not before/after)
- Subject Alternative Names (SANs)
- Additional domains covered by cert

## 📁 Output Structure

```
hsociety_recon/
├── example.com_20260128_143022.txt
├── testsite.com_20260128_150315.txt
└── mysite.org_20260129_091245.txt
```

**Filename format:** `{domain}_{YYYYMMDD}_{HHMMSS}.txt`

## 💡 Common Use Cases

### Single Domain Scan
```bash
# Quick recon with saved output
./hsociety_recon.sh -s target.com
```

### Batch Scanning Multiple Domains
```bash
# From a file
for domain in $(cat domains.txt); do
    ./hsociety_recon.sh -s "$domain"
    sleep 5  # Be respectful
done

# From an array
domains=("example.com" "test.com" "site.org")
for domain in "${domains[@]}"; do
    ./hsociety_recon.sh -s -v "$domain"
done
```

### Quick Visual Scan
```bash
# Show only successful findings
./hsociety_recon.sh target.com | grep -E "✓|→"

# Show only errors/warnings
./hsociety_recon.sh target.com | grep -E "!|⚠"
```

### Detailed Analysis
```bash
# Maximum verbosity with extended timeout
./hsociety_recon.sh -s -v -t 30 target.com
```

### Extract Specific Data
```bash
# Get all discovered subdomains
./hsociety_recon.sh example.com | grep "→" | grep -oP '[a-z0-9.-]+\.example\.com'

# Get all IP addresses
./hsociety_recon.sh example.com | grep -oP '\d+\.\d+\.\d+\.\d+' | sort -u

# Get only A records
./hsociety_recon.sh example.com | sed -n '/A Records/,/^$/p'
```

## 🔗 Integration with Other Tools

### With httpx (HTTP probing)
```bash
# Extract and probe subdomains
./hsociety_recon.sh example.com | \
  grep -oP '[a-z0-9.-]+\.example\.com' | \
  sort -u | \
  httpx -title -tech-detect -status-code
```

### With subfinder (Enhanced enumeration)
```bash
# Combine multiple sources
subfinder -d example.com -silent > subs.txt
./hsociety_recon.sh example.com | grep -oP '[a-z0-9.-]+\.example\.com' >> subs.txt
sort -u subs.txt -o all_subs.txt
```

### With nuclei (Vulnerability scanning)
```bash
# Extract subdomains and scan for CVEs
./hsociety_recon.sh -s example.com
grep -oP '[a-z0-9.-]+\.example\.com' hsociety_recon/example.com_*.txt | \
  sort -u | \
  nuclei -t cves/ -severity high,critical
```

### With nmap (Port scanning)
```bash
# Get IPs and scan them
./hsociety_recon.sh example.com | \
  grep -oP '\d+\.\d+\.\d+\.\d+' | \
  sort -u | \
  nmap -iL - -p 80,443,8080,8443 --open
```

### With waybackurls (URL discovery)
```bash
# Get subdomains and find historical URLs
./hsociety_recon.sh example.com | \
  grep -oP '[a-z0-9.-]+\.example\.com' | \
  waybackurls | \
  sort -u > urls.txt
```

## ⚠️ Troubleshooting

### Problem: Missing Dependencies
```bash
# Check which tools are installed
which whois dig curl jq openssl

# Check versions
whois --version
dig -v
curl --version
jq --version
openssl version

# Install missing tools
sudo apt install <missing-tool>
```

### Problem: Slow Scans
**Solutions:**
```bash
# Reduce timeout
./hsociety_recon.sh -t 5 example.com

# Skip verbose mode
./hsociety_recon.sh example.com  # Don't use -v

# Use faster DNS servers
# Add to /etc/resolv.conf:
nameserver 1.1.1.1
nameserver 8.8.8.8
```

### Problem: No Output File Created
**Check:**
```bash
# Did you use the -s flag?
./hsociety_recon.sh -s example.com  # Correct

# Check if directory was created
ls -la hsociety_recon/

# Check for permission errors
ls -ld hsociety_recon/
# Should show: drwxr-xr-x
```

### Problem: Domain Not Resolving
**Debugging:**
```bash
# Test DNS resolution manually
dig +short A example.com
nslookup example.com

# Check domain exists
whois example.com | head -20

# Try different DNS server
dig @8.8.8.8 +short A example.com
```

### Problem: SSL Certificate Errors
**Explanation:**
- Not all domains have HTTPS configured
- Some use self-signed certificates
- Certificate may be expired

**The script will:**
- Show a warning
- Continue with other modules
- Not crash the entire scan

### Problem: No Subdomains Found
**Reasons:**
- Brand new domains (no SSL certificates yet)
- Domains without SSL certificates
- Private/internal domains
- No data in Certificate Transparency logs

**Alternative methods:**
```bash
# Use dedicated subdomain tools
subfinder -d example.com
amass enum -passive -d example.com
assetfinder --subs-only example.com
```

### Problem: Timeout Errors
**Solutions:**
```bash
# Increase timeout globally
./hsociety_recon.sh -t 30 example.com

# Or edit script default (line 15)
TIMEOUT=30

# For slow networks
./hsociety_recon.sh -t 60 example.com
```

## 📊 Performance Reference

### Typical Scan Times
| Domain Size | Subdomains | Avg. Time | Use Case |
|------------|------------|-----------|----------|
| Small | < 10 | 15-30s | Personal sites, blogs |
| Medium | 10-50 | 30-90s | Small businesses |
| Large | 50-200 | 2-5min | Large companies |
| Enterprise | 200+ | 5-15min | Fortune 500 |

### Speed Optimization Tips
1. **Lower timeout** for faster scans: `-t 5`
2. **Skip verbose mode** unless needed
3. **Run during off-peak hours** (less network congestion)
4. **Use faster DNS servers** (1.1.1.1, 8.8.8.8)
5. **Scan from VPS** near target's location
6. **Disable IPv6** if not needed (edit script)

## 🔐 Security & Legal

### ⚠️ CRITICAL RULES

```
❌ NEVER scan domains you don't own without written permission
❌ NEVER use for malicious purposes
❌ NEVER overwhelm target systems
❌ NEVER ignore rate limits or robots.txt
❌ NEVER share discovered sensitive information

✅ ALWAYS get written authorization first
✅ ALWAYS stay within authorized scope
✅ ALWAYS report findings responsibly
✅ ALWAYS document your testing
✅ ALWAYS follow bug bounty program rules
```

### Legal Considerations

**United States:**
- Computer Fraud and Abuse Act (CFAA)
- Unauthorized access is a federal crime

**United Kingdom:**
- Computer Misuse Act 1990
- Unauthorized access carries penalties

**European Union:**
- GDPR for data handling
- Cybersecurity Act

**Always check your local laws!**

## 📝 Best Practices

### Before Scanning
- [ ] Get written authorization
- [ ] Understand the scope
- [ ] Read bug bounty rules
- [ ] Check legal requirements
- [ ] Plan your methodology

### During Scanning
- [ ] Use `-s` to save outputs
- [ ] Monitor for errors
- [ ] Respect rate limits
- [ ] Stay within scope
- [ ] Document findings

### After Scanning
- [ ] Review all outputs
- [ ] Validate findings
- [ ] Report responsibly
- [ ] Archive evidence
- [ ] Follow disclosure timeline

## 🎯 Quick Tips

### Tip 1: Color Output Issues
If colors don't display properly:
```bash
# Force color output
export TERM=xterm-256color

# Or disable colors by redirecting to file
./hsociety_recon.sh example.com > output.txt
```

### Tip 2: Timeout Settings
For different scenarios:
```bash
# Fast local network
./hsociety_recon.sh -t 5 example.com

# Normal internet connection
./hsociety_recon.sh -t 10 example.com  # Default

# Slow/unreliable connection
./hsociety_recon.sh -t 30 example.com

# Very slow or international target
./hsociety_recon.sh -t 60 example.com
```

### Tip 3: More Subdomain Sources
Combine multiple tools:
```bash
# Use all available tools
subfinder -d example.com -silent > subs1.txt
amass enum -passive -d example.com -o subs2.txt
./hsociety_recon.sh example.com | grep -oP '[a-z0-9.-]+\.example\.com' > subs3.txt

# Combine and deduplicate
cat subs1.txt subs2.txt subs3.txt | sort -u > all_subs.txt
```

### Tip 4: Automated Daily Scans
Set up monitoring:
```bash
# Add to crontab
crontab -e

# Run daily at 2 AM
0 2 * * * /path/to/hsociety_recon.sh -s example.com

# Run weekly on Sunday at 3 AM
0 3 * * 0 /path/to/hsociety_recon.sh -s -v example.com
```

### Tip 5: JSON Output for Parsing
While the tool doesn't output JSON directly, you can parse it:
```bash
# Extract to JSON format
./hsociety_recon.sh example.com | \
  grep "→" | \
  awk '{print "\"" $2 "\""}' | \
  jq -Rs 'split("\n") | map(select(length > 0))'
```

## 🐛 Common Error Messages

| Error Message | Meaning | Solution |
|--------------|---------|----------|
| `Missing dependencies: whois` | whois not installed | `sudo apt install whois` |
| `Invalid domain format` | Domain syntax incorrect | Check spelling and format |
| `Domain may not resolve` | DNS lookup failed | Verify domain exists |
| `WHOIS lookup failed` | No WHOIS data available | Domain may be private/new |
| `No subdomains found` | No cert transparency data | Try subfinder/amass |
| `Could not retrieve SSL certificate` | No HTTPS or SSL error | Check if site uses HTTPS |
| `timeout: command not found` | timeout utility missing | `sudo apt install coreutils` |
| `jq: command not found` | jq JSON processor missing | `sudo apt install jq` |
| `Failed to fetch certificate data` | Network or API issue | Check internet, try again |

## 🔄 Exit Codes

| Code | Meaning | Description |
|------|---------|-------------|
| `0` | Success | Scan completed without errors |
| `1` | Error | Missing dependencies, invalid input, or failure |
| `130` | Interrupted | User pressed Ctrl+C |

## 📂 Files & Directories

### Created by Script
```
./hsociety_recon/               # Default output directory
├── example.com_20260128_143022.txt
├── test.com_20260128_150000.txt
└── ...
```

### Temporary Files
```
/tmp/tmp.XXXXXX.subs            # Subdomain list
/tmp/tmp.XXXXXX.subs.ips        # Resolved IPs
```
*Automatically cleaned up on exit*

## 💻 System Requirements

### Operating Systems
- ✅ Ubuntu 20.04+
- ✅ Debian 10+
- ✅ Kali Linux 2023+
- ✅ macOS 12+
- ✅ Fedora 35+
- ✅ RHEL/CentOS 8+

### Dependencies
- Bash 4.0 or higher
- Internet connection
- Standard Unix tools (grep, awk, sed)
- Required packages: whois, dig, curl, jq, openssl

### Resources
- Minimal CPU usage
- < 50MB RAM typically
- Network bandwidth varies by target size

## 📚 Additional Resources

### Learn More About
- **DNS:** `man dig`
- **WHOIS:** `man whois`
- **SSL/TLS:** `man openssl`
- **Certificate Transparency:** https://crt.sh

### Related Tools
- **subfinder:** https://github.com/projectdiscovery/subfinder
- **amass:** https://github.com/owasp-amass/amass
- **httpx:** https://github.com/projectdiscovery/httpx
- **nuclei:** https://github.com/projectdiscovery/nuclei

### Bug Bounty Platforms
- HackerOne: https://hackerone.com
- Bugcrowd: https://bugcrowd.com
- Intigriti: https://intigriti.com
- YesWeHack: https://yeswehack.com

## 🆘 Getting Help

### In Order of Priority:
1. **Read the full README.md** - Comprehensive documentation
2. **Check this Quick Reference** - Common issues covered
3. **Test dependencies** - Ensure all tools installed
4. **Test with known domain** - Verify script works
5. **Review error messages** - Often self-explanatory
6. **Check permissions** - File/directory access rights
7. **Verify network** - Internet connectivity

### Debugging Commands
```bash
# Check script syntax
bash -n hsociety_recon.sh

# Run with debug mode
bash -x hsociety_recon.sh example.com

# Check dependencies systematically
for cmd in whois dig curl jq openssl; do
    command -v $cmd && echo "$cmd: OK" || echo "$cmd: MISSING"
done
```

---

## 📌 Remember

> **"With great power comes great responsibility"**
>
> This tool is for ethical security research and authorized testing only.
> 
> **ALWAYS get permission. ALWAYS stay legal. ALWAYS be ethical.**

---

**Last Updated:** January 28, 2026  
**Version:** 2.0  
**License:** Educational Use Only
