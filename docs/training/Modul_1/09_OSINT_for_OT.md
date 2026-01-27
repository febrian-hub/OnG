Lesson 09: OSINT for OT Infrastructur

Lesson 09: Open-Source Intelligence
(OSINT) for OT Infrastructure
Learning Objectives
●​
●​
●​
●​
●​

Conduct advanced OSINT reconnaissance on critical infrastructure
Analyze supply chain relationships and vendor dependencies
Enumerate OT assets without active network scanning
Extract intelligence from public sources (Shodan, certificates, social media)
Build target profiles for red team operations

1. OSINT Methodology for OT
1.1 OSINT Kill Chain for ICS
Phase 1: Target Identification
└── Identify organization, subsidiaries, critical facilities
Phase 2: Passive Reconnaissance
├── Search engines (Google, Bing dorking)
├── IoT search engines (Shodan, Censys, FOFA)
├── Domain/IP enumeration
├── Certificate transparency logs
└── Social media, job postings
Phase 3: Infrastructure Mapping
├── Network ranges (ASN, WHOIS)
├── Subdomain enumeration
├── Cloud infrastructure (AWS, Azure)
└── Third-party connections (vendors, contractors)
Phase 4: Technology Stack Identification
├── ICS vendors and products
├── Software versions, firmware
├── Network architecture (VPN, firewalls)
└── SCADA/HMI platforms
Phase 5: Personnel Intelligence
├── Employee enumeration (LinkedIn, corporate site)
├── Organizational chart
├── Technical contacts (email, phone)
└── Social engineering vectors

Phase 6: Vulnerability Correlation
├── Match identified tech to known CVEs
├── Identify outdated/EOL systems
└── Map attack surface

1.2 OSINT Legal and Ethical Boundaries
Legal Activities (Public Information):
●​
●​
●​
●​

Searching public databases
Analyzing Shodan/Censys results
Reading job postings, press releases
Viewing publicly accessible websites

Illegal/Unethical Activities:
●​
●​
●​
●​

Accessing systems without authorization
Social engineering employees for credentials
Dumpster diving on private property
Using OSINT to facilitate actual attacks without authorization

Rule: OSINT should be purely passive and use only publicly available information.

2. Search Engine OSINT
2.1 Advanced Google Dorking for ICS
Find Exposed HMI/SCADA Interfaces:
intitle:"SCADA Login"
intitle:"SCADA" intitle:"Login"
intitle:"HMI" inurl:login
intitle:"Wonderware InTouch"
intitle:"WinCC" inurl:login
intitle:"FactoryTalk"
intitle:"Ignition by Inductive Automation"
intitle:"GE iFIX"
intitle:"Siemens SIMATIC"
intitle:"Schneider Electric" inurl:scada
Exposed Configuration Files:
filetype:conf intext:modbus
filetype:conf intext:scada
filetype:xml intext:opc
filetype:s7p site:company.com (Siemens Step 7 projects)
filetype:acd site:company.com (Allen-Bradley logix)
filetype:sql intext:scada

filetype:db intext:historian
Exposed Network Diagrams:
filetype:pdf intext:"network diagram" site:company.com
filetype:vsd intext:SCADA (Visio diagrams)
filetype:pdf intext:"control system" site:utility.com
filetype:ppt intext:"ICS architecture"
Vendor Documentation Leaks:
site:company.com filetype:pdf "PLC"
site:company.com filetype:pdf "RTU configuration"
inurl:manual filetype:pdf modbus
intext:"default password" filetype:pdf scada
Job Postings (Technology Intel):
site:linkedin.com "company name" "SCADA engineer"
site:indeed.com "Siemens S7" "city name"
site:glassdoor.com "Wonderware" "control system"
# Extract technologies mentioned in job descriptions
Example: Extracting Tech Stack from Job Posting:
Job Title: SCADA Engineer - Electric Utility
Requirements:
- 5+ years experience with GE iFIX and OSIsoft PI
- Proficiency in Allen-Bradley ControlLogix PLCs
- DNP3 and Modbus protocol knowledge
- Experience with Cisco industrial switches
- VMware vSphere for SCADA virtualization
→ Intelligence Gathered:
- HMI: GE iFIX
- Historian: OSIsoft PI
- PLCs: Allen-Bradley ControlLogix
- Protocols: DNP3, Modbus
- Network: Cisco industrial switches
- Virtualization: VMware vSphere

2.2 Bing, Baidu, Yandex for Regional Targets
Bing Dorks:
ip:192.168.0.0/16 SCADA (Bing indexes IP addresses)
ip:10.0.0.0/8 HMI

Baidu (Chinese infrastructure):
SCADA 中国 (SCADA China)
工控系统 (Industrial control systems)
Yandex (Russian/Eastern European):
SCADA site:.ru
АСУ ТП site:.ru (Automated control systems)

3. IoT Search Engines
3.1 Shodan Advanced Queries
Modbus Devices:
port:502
port:502 country:"US"
port:502 city:"New York"
port:502 org:"Electric Company"
product:modbus
"Modbus" port:502
Siemens S7 PLCs:
port:102
"Siemens, SIMATIC" port:102
"S7-300" port:102
"S7-1200" port:102
port:102 country:DE (Germany - Siemens HQ)
Ethernet/IP (Rockwell):
port:44818
"Allen-Bradley"
"ControlLogix"
product:"Rockwell"
DNP3 (SCADA):
port:20000
"dnp3"
port:20000 country:US org:"Utility"
OPC UA:
port:4840
"OPC UA"
port:4840 product:opc

BACnet (Building Automation):
port:47808
"BACnet"
SCADA Web Interfaces:
http.title:"SCADA"
http.title:"WinCC"
http.title:"InTouch"
http.html:"Wonderware"
ICS-Specific HTTP Headers:
http.header:"Siemens"
http.header:"Rockwell"
http.header:"Schneider"
Combine Queries:
port:502 country:US org:"Water" -honeypot
# Find Modbus in US water utilities, exclude honeypots
Shodan CLI Automation:
# Install Shodan CLI
pip install shodan
# Initialize with API key
shodan init <YOUR_API_KEY>
# Search and download results
shodan search --fields ip_str,port,org,product "port:502" --limit 1000 > modbus_devices.csv
# Parse results
cat modbus_devices.csv | awk -F',' '{print $1}' | sort -u > modbus_ips.txt
# Count by organization
cat modbus_devices.csv | awk -F',' '{print $3}' | sort | uniq -c | sort -rn
# Filter by country
shodan search "port:502 country:US" --fields ip_str,org,product > us_modbus.csv

3.2 Censys for OT Discovery
Censys Search Syntax:
# Modbus
services.port: 502

# Siemens S7
services.port: 102
# ICS protocols
protocols: ("modbus" OR "dnp3" OR "s7comm")
# Combine with organization
services.port: 502 AND autonomous_system.name: "Electric Company"
# TLS certificates (find SCADA servers with certs)
parsed.subject.common_name: scada
parsed.subject.organization: "Utility Company"
Censys CLI:
# Install
pip install censys
# Configure
censys config
# Search
censys search "services.port: 502" --max-records 100 > censys_modbus.json
# Parse JSON
cat censys_modbus.json | jq -r '.[] | .ip'

3.3 FOFA (China-based)
FOFA Queries:
port="502"
port="102"
protocol="modbus"
protocol="s7comm"
app="SCADA"

3.4 ZoomEye
ZoomEye Queries:
port:502
service:modbus
device:PLC

4. Network Infrastructure OSINT

4.1 ASN and IP Range Enumeration
Find Organization's ASN:
# Using whois
whois -h whois.radb.net "Company Name" | grep origin
# Example output:
# origin: AS12345
# Get IP ranges for ASN
whois -h whois.radb.net AS12345 | grep route
# Output:
# route: 203.0.113.0/24
# route: 198.51.100.0/22
Automated ASN Enumeration:
# Using amass
amass intel -asn 12345 -whois
# Using bgpview API
curl -s "https://api.bgpview.io/asn/12345/prefixes" | jq -r '.data.ipv4_prefixes[].prefix'
# Save IP ranges
curl -s "https://api.bgpview.io/asn/12345/prefixes" | jq -r '.data.ipv4_prefixes[].prefix' >
target_ranges.txt

4.2 Subdomain Enumeration
Passive Subdomain Discovery:
# Using subfinder
subfinder -d company.com -o subdomains.txt
# Using amass (passive mode)
amass enum -passive -d company.com -o amass_subdomains.txt
# Certificate Transparency logs (crt.sh)
curl -s "https://crt.sh/?q=%company.com&output=json" | jq -r '.[].name_value' | sort -u >
crt_subdomains.txt
# Combine and deduplicate
cat subdomains.txt amass_subdomains.txt crt_subdomains.txt | sort -u > all_subdomains.txt
Look for OT-Related Subdomains:
# Filter for ICS-related keywords

grep -E "scada|hmi|plc|ot|ics|control|automation|historian|mes" all_subdomains.txt
# Example results:
# scada.company.com
# hmi-backup.company.com
# plant1-scada.company.com
# historian.ops.company.com

4.3 Certificate Transparency Intelligence
crt.sh for OT Infrastructure:
# Search for organization certificates
curl -s "https://crt.sh/?q=%Utility+Company&output=json" | jq .
# Extract unique subdomains
curl -s "https://crt.sh/?q=%company.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' |
sort -u
# Find certificates with "scada" in CN/SAN
curl -s "https://crt.sh/?q=%scada%&output=json" | jq -r '.[] | select(.name_value |
contains("company.com")) | .name_value'
Analyze Certificate Details:
# Get certificate details
curl -s "https://crt.sh/?id=1234567890&output=json" | jq .
# Extract:
# - Issuer (is it self-signed? Internal CA?)
# - Subject Alternative Names (more subdomains)
# - Validity period (outdated cert = possible neglected system)

4.4 Cloud Infrastructure Discovery
AWS S3 Bucket Enumeration:
# Common naming patterns
company-scada-backups
company-ics-configs
company-plc-programs
# Use bucket_finder
python bucket_finder.py company
# Use s3scanner
s3scanner scan --buckets-file potential_buckets.txt
Azure Blob Storage:

https://companyname.blob.core.windows.net/
https://company-scada.blob.core.windows.net/
Google Cloud Storage:
https://storage.googleapis.com/company-backups/

5. Social Media and Personnel Intelligence
5.1 LinkedIn Reconnaissance
Employee Enumeration:
Search: "Company Name" AND "SCADA Engineer"
Search: "Company Name" AND "Control Systems"
Search: "Company Name" AND "Automation Engineer"
Extract Information:
●​ Job Titles: Identify roles (SCADA admin, PLC programmer, OT security)
●​ Technologies: Skills listed (Siemens TIA Portal, Rockwell Studio 5000)
●​ Tenure: Long-term employees (institutional knowledge, potential social engineering
targets)
●​ Connections: Network of employees (org chart mapping)
Automated LinkedIn Scraping (using linkedin-scraper):
from linkedin_scraper import Person, actions
from selenium import webdriver
driver = webdriver.Chrome()
email = "your_linkedin_email"
password = "your_linkedin_password"
actions.login(driver, email, password)
# Search for employees
company = "Company Name"
people = []
# Search URL
search_url =
f"https://www.linkedin.com/search/results/people/?keywords={company}%20SCADA"
driver.get(search_url)
# Extract profiles (simplified)
# ... (scraping logic)

driver.quit()

5.2 GitHub Intelligence
Search for Company Repositories:
# Search organization repos
https://github.com/orgs/CompanyName/repositories
# Search user repos mentioning company
user:username "company name"
# Search code
"company.com" filename:.env
"company.com" filename:config.yml
"192.168.1.100" language:Python (Internal IP leaks)
Common Leaks:
●​
●​
●​
●​
●​

HMI configuration files (.scada, .hmi)
PLC programs (.s7p, .acd, .rslogix)
Network diagrams (Visio .vsd, .drawio)
Credentials (.env, config.json)
Internal documentation (README with architecture)

Search Example:
# Find Siemens Step 7 projects
filename:.s7p
# Find Allen-Bradley Logix projects
filename:.acd
# Find SCADA credentials
"modbus" AND "password" filename:.py
# Find internal IPs
"192.168" AND "SCADA" language:Python

5.3 Pastebin and Leak Sites
Search Pastebin:
# Use PastebinAPI or manual search
site:pastebin.com "company.com" password
site:pastebin.com "company.com" SCADA
site:pastebin.com "company.com" config
Have I Been Pwned:

# Check if company domain was in breach
curl "https://haveibeenpwned.com/api/v3/breaches?domain=company.com" -H "hibp-api-key:
YOUR_API_KEY"
Dehashed (breach database):
# Search for company email addresses
curl "https://api.dehashed.com/search?query=email:company.com" -H "Authorization:
Your_API_Key"

6. Document and Image OSINT
6.1 Metadata Extraction
EXIF Data from Images:
# Install exiftool
sudo apt install libimage-exiftool-perl
# Extract metadata
exiftool network_diagram.jpg
# Look for:
# - GPS coordinates (facility location)
# - Camera/software info
# - Author (employee name)
# - Creation date
# - Company name in metadata
PDF Metadata:
# Extract PDF metadata
exiftool document.pdf
pdfinfo document.pdf
# Extract PDF text
pdftotext document.pdf
# Search for keywords
pdfgrep -i "IP address\|PLC\|SCADA" document.pdf

6.2 Google Image Search
Reverse Image Search for Network Diagrams:
1.​ Upload image to Google Images
2.​ Find similar diagrams from same organization

3.​ Extract additional network topology info

7. Supply Chain and Vendor Analysis
7.1 Vendor Identification
From Job Postings:
●​ Required skills mention vendor products (Siemens, Rockwell, Schneider)
From Press Releases:
site:company.com "awarded contract" SCADA
site:company.com "partnership" automation
From Annual Reports/SEC Filings:
●​ Major technology purchases disclosed

7.2 Third-Party Attack Surface
Identify Vendors with Access:
●​ Remote maintenance contractors
●​ System integrators
●​ Engineering firms
Find Vendor Connections:
●​ VPN gateways (often third-party branded)
●​ Support portals (teamviewer, logmein, etc.)

8. Threat Intelligence Integration
8.1 Correlate OSINT with Threat Intel
Map Discovered Assets to Known Threats:
Discovered: Siemens S7-1200 PLC (v4.2.1)
↓
Threat Intel: CVE-2020-15368 affects S7-1200 v4.2.1
↓
Risk Assessment: Critical vulnerability, likely unpatched

8.2 APT Group Targeting
Identify Relevant APT Groups:

●​ Energy Sector: Sandworm, XENOTIME, APT33
●​ Water/Wastewater: Unknown actors (ransomware gangs)
●​ Manufacturing: APT41, Lazarus
Map TTPs:
●​ If Siemens PLCs discovered → Research Stuxnet, Industroyer TTPs
●​ If Triconex SIS discovered → Research XENOTIME/Triton

9. OSINT Automation Framework
9.1 Automated OSINT Collection
Recon-ng:
# Install
sudo apt install recon-ng
# Launch
recon-ng
# Load modules
marketplace install all
# Create workspace
workspaces create company_osint
# Add domain
db insert domains domain company.com
# Run modules
modules load recon/domains-hosts/bing_domain_web
run
modules load recon/hosts-hosts/resolve
run
# Export results
show hosts
theHarvester:
# Install
sudo apt install theharvester
# Run
theHarvester -d company.com -b all -l 500 -f company_harvest.html

# Output: emails, subdomains, IPs, employees

9.2 Custom OSINT Pipeline
Python Automation Script:
#!/usr/bin/env python3
import requests
import json
import subprocess
def osint_pipeline(target_domain):
"""
Automated OSINT collection for OT infrastructure
"""
results = {
"domain": target_domain,
"subdomains": [],
"ips": [],
"technologies": [],
"employees": []
}
# Step 1: Subdomain enumeration
print("[*] Enumerating subdomains...")
cmd = f"subfinder -d {target_domain} -silent"
subdomains = subprocess.check_output(cmd, shell=True).decode().splitlines()
results["subdomains"] = subdomains
# Step 2: Certificate Transparency
print("[*] Checking certificate transparency logs...")
crt_url = f"https://crt.sh/?q=%{target_domain}&output=json"
response = requests.get(crt_url)
if response.status_code == 200:
certs = response.json()
for cert in certs:
results["subdomains"].append(cert.get("name_value"))
results["subdomains"] = list(set(results["subdomains"]))
# Step 3: Shodan search for exposed services
print("[*] Searching Shodan for exposed ICS services...")
# (Requires Shodan API key)
# Step 4: GitHub search
print("[*] Searching GitHub for leaks...")
# (Requires GitHub API)

# Save results
with open(f"{target_domain}_osint.json", "w") as f:
json.dump(results, f, indent=2)
print(f"[+] OSINT collection complete. Results saved to {target_domain}_osint.json")
return results
# Usage
# osint_pipeline("company.com")

10. Hands-On Lab Exercises
Lab 1: Search Engine OSINT
1.​ Choose a publicly traded utility company (legal target for OSINT)
2.​ Conduct Google dorking to find:
○​ Exposed documents (PDF, DOCX with metadata)
○​ Job postings revealing technology stack
○​ Network diagrams or architecture docs
3.​ Document findings in structured report

Lab 2: Shodan Reconnaissance
1.​ Search Shodan for Modbus devices in your country/city
2.​ Analyze results:
○​ Count devices by organization
○​ Identify common vendors
○​ Map geographic distribution
3.​ Cross-reference with public utility databases
4.​ Create threat landscape report

Lab 3: Subdomain and ASN Enumeration
1.​ Select target organization (with authorization or use bug bounty scope)
2.​ Enumerate subdomains using 3+ tools (subfinder, amass, crt.sh)
3.​ Find organization's ASN, extract IP ranges
4.​ Map OT-related subdomains (scada., hmi., plc., etc.)
5.​ Generate network map

Lab 4: Employee and Vendor Intelligence
1.​ Use LinkedIn to enumerate employees with OT roles
2.​ Extract technology skills from profiles
3.​ Identify vendor relationships from company website/press releases
4.​ Map supply chain (vendors with potential network access)
5.​ Create target profile for red team operation

11. Tools & Resources
OSINT Tools
●​
●​
●​
●​
●​
●​

Shodan: https://www.shodan.io/
Censys: https://search.censys.io/
theHarvester: https://github.com/laramies/theHarvester
Recon-ng: https://github.com/lanmaster53/recon-ng
Subfinder: https://github.com/projectdiscovery/subfinder
Amass: https://github.com/OWASP/Amass

Search Engines
●​
●​
●​
●​
●​

Google: https://www.google.com/
Shodan: https://www.shodan.io/
Censys: https://search.censys.io/
FOFA: https://fofa.info/
ZoomEye: https://www.zoomeye.org/

Databases
●​
●​
●​
●​

crt.sh: https://crt.sh/
BGPView: https://bgpview.io/
Have I Been Pwned: https://haveibeenpwned.com/
Dehashed: https://www.dehashed.com/

Learning
●​ OSINT Framework: https://osintframework.com/
●​ IntelTechniques: https://inteltechniques.com/

12. Knowledge Check
1.​ What is the difference between active reconnaissance and OSINT?
2.​ Describe three Google dorks to find exposed SCADA interfaces.
3.​ How do you use Shodan to find Modbus devices in a specific organization?
4.​ What information can you extract from certificate transparency logs?
5.​ How would you enumerate subdomains for an OT infrastructure passively?
6.​ What OSINT techniques can reveal an organization's technology stack?
7.​ Why is LinkedIn valuable for OT intelligence gathering?
8.​ How do you identify an organization's IP ranges using ASN?
9.​ What are the ethical and legal boundaries of OSINT?
10.​Describe how to automate OSINT collection for multiple targets.

