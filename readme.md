# IP Tracer - Comprehensive IP Intelligence Tool

[![Version](https://img.shields.io/badge/version-2.2-blue.svg)](https://github.com/cicada-369/IP-Tracer)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Bash](https://img.shields.io/badge/language-Bash-red.svg)](https://www.gnu.org/software/bash/)

A comprehensive IP address investigation tool that combines traditional network reconnaissance with modern threat intelligence APIs to provide detailed analysis of IP addresses. Perfect for cybersecurity professionals, incident responders, and network administrators.

## 🚀 Features

### Core Capabilities
- **Single IP Analysis** - Detailed investigation of individual IP addresses
- **Batch Processing** - Process hundreds of IPs from text files automatically
- **Automated Reporting** - Generate timestamped reports in text format
- **Multi-source Intelligence** - Combines five threat-intelligence APIs plus OSINT

### Network Reconnaissance Tools
- **Connectivity Testing** (`ping`) - Basic reachability and response time
- **WHOIS Lookup** (`whois`) - Registration and ownership information
- **DNS Analysis** (`nslookup`, `dig`) - Forward/reverse DNS resolution
- **Network Tracing** (`traceroute`) - Path discovery and routing analysis  
- **Port Scanning** (`nmap`) - Service discovery and OS fingerprinting
- **Geolocation** (API-based) - Geographic and ISP information

### Threat Intelligence Sources
- **🛡️ AbuseIPDB** - IP reputation and abuse confidence scoring
- **🔍 VirusTotal** - Malware detection and URL associations
- **📡 Shodan** - Internet-connected device and vulnerability data
- **🔐 Censys** - Certificate, service, and infrastructure analysis
- **📊 SecurityTrails** - Historical DNS and passive DNS records
- **🌐 Additional OSINT** - 20+ manual verification sources

## 📦 Installation

### Prerequisites
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install dnsutils traceroute nmap curl whois jq netcat-openbsd

# CentOS/RHEL/Fedora
sudo yum install bind-utils traceroute nmap curl whois jq nc
# or
sudo dnf install bind-utils traceroute nmap curl whois jq nc

# macOS
brew install nmap wget jq
```

### Download Script
```bash
# Clone repository
git clone https://github.com/cicada-369/IP-Tracer.git
cd IP-Tracer

# Make executable
chmod +x ip_tracer.sh

# Check dependencies
./ip_tracer.sh --check
```

## 🔑 API Configuration

### Required API Keys
The script supports multiple threat intelligence APIs. While not required, configuring these APIs significantly enhances the analysis:

| Service | Free Tier | API Key Source | Environment Variable |
|---------|-----------|----------------|---------------------|
| **AbuseIPDB** | ✅ 1,000/day | [Get API Key](https://www.abuseipdb.com/api) | `ABUSEIPDB_API_KEY` |
| **VirusTotal** | ✅ 500/day | [Get API Key](https://www.virustotal.com/gui/join-us) | `VIRUSTOTAL_API_KEY` |
| **Shodan** | ✅ 100/month | [Get API Key](https://account.shodan.io/) | `SHODAN_API_KEY` |
| **Censys** | ✅ 250/month | [Get API Keys](https://search.censys.io/account/api) | `CENSYS_API_ID`, `CENSYS_API_SECRET` |
| **SecurityTrails** | ✅ 50/month | [Get API Key](https://securitytrails.com/corp/api) | `SECURITYTRAILS_API_KEY` |

### Setup Methods

#### Method 1: A protected environment file (Recommended)

Create the file outside the repository and restrict it to your user:

```bash
mkdir -p ~/.config/ip-tracer
chmod 700 ~/.config/ip-tracer
touch ~/.config/ip-tracer/env
chmod 600 ~/.config/ip-tracer/env
```

Add one variable per line:

```text
ABUSEIPDB_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here
CENSYS_API_ID=your_id_here
CENSYS_API_SECRET=your_secret_here
SECURITYTRAILS_API_KEY=your_key_here
```

Never commit this file. `.env`, `.env.*`, and `secrets/` are ignored.

#### Method 2: Load the keys only for this tool

Create `~/.local/bin/ip-tracer`:

```bash
#!/usr/bin/env bash
set -euo pipefail
set -a
. "$HOME/.config/ip-tracer/env"
set +a
exec "$HOME/projects/IP-Tracer/ip_tracer.sh" "$@"
```

```bash
mkdir -p ~/.local/bin
chmod 700 ~/.local/bin/ip-tracer
ip-tracer --help
```

This keeps the keys out of your shell profile and out of unrelated processes.

#### Method 3: Session-only variables

Use this when you do not want the keys written to disk:

```bash
read -r -s -p 'AbuseIPDB key: ' ABUSEIPDB_API_KEY; export ABUSEIPDB_API_KEY; echo
read -r -s -p 'VirusTotal key: ' VIRUSTOTAL_API_KEY; export VIRUSTOTAL_API_KEY; echo
```

**Never edit the keys into `ip_tracer.sh` itself.** A committed key is a leaked
key: rotate it at the provider and purge it from history.

## 🎯 Usage

### Single IP Analysis
```bash
# Basic usage
./ip_tracer.sh 8.8.8.8

# Analyze suspicious IP
./ip_tracer.sh 203.0.113.45
```

### Batch Processing
Create an IP list file (`suspicious_ips.txt`):
```text
# DNS Servers
8.8.8.8
1.1.1.1

# Suspicious IPs from logs
203.0.113.1
198.51.100.15
192.0.2.146

# Infrastructure analysis
10.0.0.1
```

Process the batch:
```bash
# Process all IPs from file
./ip_tracer.sh -f suspicious_ips.txt

# Alternative syntax
./ip_tracer.sh --batch ip_list.txt
```

### Passive Mode
Run only non-intrusive sources — WHOIS, DNS, geolocation, the threat-intelligence
APIs, and OSINT:

```bash
./ip_tracer.sh --passive 203.0.113.45
./ip_tracer.sh --passive -f suspicious_ips.txt
```

Passive mode skips ping, traceroute, and nmap. Use it when the target is not
yours and you have no authorization to probe it.

### Other Commands
```bash
# Check dependencies
./ip_tracer.sh --check

# Show help
./ip_tracer.sh --help

# Show version
./ip_tracer.sh --version
```

## 📊 Output Files

### Single IP Analysis
- **Report File**: `ip_trace_8.8.8.8_20250813_143022.txt`
- **Format**: Detailed text report with all findings

### Batch Processing
- **Individual Reports**: `ip_trace_{IP}_{DATE}_{TIME}.txt` for each IP
- **Batch Summary**: `batch_summary_{DATE}_{TIME}.csv` with processing results
- **Format**: CSV with IP, report filename, and completion timestamp

### Sample Report Structure
```
IP TRACER REPORT
=================================================================================
Target IP: 8.8.8.8
Analysis Date: Wed Aug 13 14:30:22 PDT 2025
Generated by: IP Tracer Script v2.2
=================================================================================

1. CONNECTIVITY TEST (ping)
----------------------------------------
Testing connectivity to 8.8.8.8...
PING 8.8.8.8 (8.8.8.8): 56 data bytes
64 bytes from 8.8.8.8: icmp_seq=0 ttl=116 time=14.123 ms
...

2. WHOIS INFORMATION  
----------------------------------------
...

7. REPUTATION & SECURITY ANALYSIS
----------------------------------------
Checking AbuseIPDB for 8.8.8.8...
{
  "abuseConfidencePercentage": 0,
  "countryCode": "US",
  "usageType": "Data Center/Web Hosting/Transit"
}
...
```

## 🛠️ Advanced Usage

### Batch Processing Best Practices
```bash
# Large IP lists - process in smaller chunks
split -l 50 large_ip_list.txt batch_
for file in batch_*; do
    ./ip_tracer.sh -f "$file"
    sleep 60  # Wait between batches
done
```

### Analyzing Results
```bash
# Search across all reports
grep -l "malicious" ip_trace_*.txt

# Find high-confidence abuse reports
grep -h "abuseConfidencePercentage" ip_trace_*.txt | grep -v ": 0"

# Extract all open ports
grep "Port.*Open" ip_trace_*.txt

# View batch summary
column -t -s',' batch_summary_*.csv
```

### Integration with Other Tools
```bash
# Extract IPs from log files
grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' access.log | sort -u > extracted_ips.txt
./ip_tracer.sh -f extracted_ips.txt

# Process fail2ban IPs
fail2ban-client status sshd | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' > banned_ips.txt
./ip_tracer.sh -f banned_ips.txt
```

## 📈 Use Cases

### 🔍 Incident Response
- **Malware C2 Analysis** - Investigate command and control infrastructure
- **Threat Actor Profiling** - Build intelligence on attacker infrastructure  
- **IOC Validation** - Verify and enrich indicators of compromise
- **Timeline Reconstruction** - Use historical DNS data for incident timelines

### 🛡️ Threat Hunting
- **Infrastructure Correlation** - Link related malicious infrastructure
- **Reputation Monitoring** - Track IP reputation changes over time
- **Service Enumeration** - Identify suspicious services and configurations
- **Geolocation Analysis** - Analyze geographic patterns in threats

### 🌐 Network Security
- **Perimeter Monitoring** - Analyze external connections and traffic
- **Access Review** - Investigate unusual or suspicious network access
- **Vulnerability Assessment** - Identify exposed services and potential risks
- **Compliance Auditing** - Document network reconnaissance for audits

### 🔬 Security Research
- **Botnet Tracking** - Monitor and analyze botnet infrastructure
- **Campaign Analysis** - Study threat campaigns and TTPs
- **Infrastructure Mapping** - Map adversary infrastructure relationships
- **Passive DNS Research** - Historical domain and IP relationships

## ⚖️ Legal and Ethical Considerations

**⚠️ IMPORTANT**: This tool is designed for legitimate security research, incident response, and network administration purposes only.

### Permitted Uses
- ✅ Analyzing your own network infrastructure
- ✅ Investigating security incidents with proper authorization
- ✅ Academic and security research on publicly available data
- ✅ Threat intelligence gathering from public sources

### Prohibited Uses
- ❌ Unauthorized scanning of networks you don't own
- ❌ Aggressive or disruptive scanning that impacts services
- ❌ Using gathered intelligence for malicious purposes
- ❌ Violating terms of service of API providers

### Best Practices
- Always ensure you have proper authorization before scanning
- Respect API rate limits and terms of service
- Use responsibly and ethically in professional contexts
- Document usage for compliance and audit purposes

## 🔧 Troubleshooting

### Common Issues

#### Missing Dependencies
```bash
# Check what's missing
./ip_tracer.sh --check

# Install missing tools
sudo apt-get install dnsutils traceroute nmap curl whois jq
```

#### API Rate Limiting
```bash
# Increase delays between batch processing
# Edit script and modify sleep time from 10 to 30 seconds

# Use fewer APIs if hitting limits
# Comment out API sections temporarily
```

#### Permission Errors
```bash
# Make script executable
chmod +x ip_tracer.sh

# Run nmap as root for OS detection (optional)
sudo ./ip_tracer.sh 192.168.1.1
```

#### Large Batch Processing
```bash
# Split large files
split -l 25 huge_ip_list.txt smaller_batch_

# Process with longer delays
# Edit sleep time in script for API protection
```

### Performance Tips
- **Batch Size**: Keep batches under 50 IPs for optimal performance
- **API Keys**: Configure all APIs for maximum intelligence value
- **Rate Limiting**: Increase delays if experiencing API errors
- **Filtering**: Pre-filter IP lists to remove duplicates and invalid IPs

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

### Development Guidelines
- Follow existing code style and formatting
- Test changes with both single IP and batch processing
- Update documentation for new features
- Ensure backward compatibility

### Feature Requests
- Additional threat intelligence sources
- New output formats (JSON, XML)
- Integration with SIEM platforms
- Custom reporting templates

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **API Providers**: Thanks to AbuseIPDB, VirusTotal, Shodan, Censys, and SecurityTrails for their excellent APIs
- **Open Source Tools**: Built upon the foundation of traditional network tools (nmap, whois, dig, etc.)
- **Security Community**: Inspired by the need for comprehensive IP intelligence in security operations

---

**Disclaimer**: This tool is provided "as is" without warranty. Users are responsible for complying with all applicable laws and regulations. Always obtain proper authorization before scanning networks or systems you do not own.
