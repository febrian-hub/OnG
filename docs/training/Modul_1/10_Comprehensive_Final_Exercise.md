Lesson 10: COMPREHENSIVE
RECONNAISSANCE LAB

Lesson 10: COMPREHENSIVE
RECONNAISSANCE LAB
Overview
This capstone lab integrates all techniques from Module 1 into a realistic OT reconnaissance
scenario. You will conduct end-to-end intelligence gathering against a simulated industrial
facility, combining OSINT, passive network monitoring, active scanning, protocol analysis,
and threat modeling.
Duration: 8-12 hours Difficulty: Advanced Prerequisites: Completion of Lessons 1-9

Lab Scenario
Target Organization: AquaPure Water Treatment Facility
Background: AquaPure is a medium-sized municipal water treatment facility serving
500,000 residents. The facility has recently undergone digital transformation, upgrading from
legacy RTUs to modern PLCs and SCADA systems. Your red team has been authorized to
conduct a comprehensive security assessment.
Scope of Engagement:
●​
●​
●​
●​
●​

Authorized: Passive reconnaissance, OSINT, non-intrusive network scanning
Out of Scope: Exploitation, denial of service, disruption of operations
Network Range: 10.10.0.0/16 (internal), 203.0.113.0/24 (DMZ)
Timeline: 5 business days
Deliverable: Comprehensive reconnaissance report with threat model

Lab Environment Setup
Required Infrastructure
Option 1: LabShock Docker Environment (Recommended)
# Clone LabShock (OT cyber range)
git clone https://github.com/zakharb/labshock
cd labshock
# Deploy full environment
docker-compose up -d

# Includes:
# - OpenPLC Runtime (Modbus TCP)
# - ScadaBR (HMI/SCADA)
# - Node-RED (SCADA backend)
# - Historian (InfluxDB + Grafana)
# - OPC UA server
# - Network monitoring (Zeek + Suricata)
# - DMZ with web servers
Option 2: Manual Setup
# Deploy individual components:
# 1. OpenPLC Runtime
docker run -p 502:502 -p 8080:8080 --name openplc hassioaddons/openplc
# 2. ScadaBR
docker run -p 8081:8080 --name scadabr iiotbr/scadabr
# 3. OPC UA Server (node-opcua)
npm install -g node-opcua-server
node-opcua-server
# 4. S7 Simulator (Snap7 server)
python3 -c "from snap7.server import Server; s = Server(); s.start(); import time;
time.sleep(99999)"
# 5. Vulnerable Web Server (DVWA for HMI simulation)
docker run -p 80:80 vulnerables/web-dvwa
# 6. Network Tap Point (span port or tap)
# Configure your virtualization platform for traffic mirroring
Network Topology:
Internet
│
├── DMZ (203.0.113.0/24)
│ ├── Web Server (203.0.113.10)
│ ├── VPN Gateway (203.0.113.1)
│ └── OPC UA Gateway (203.0.113.50)
│
└── Firewall
│
├── Corporate Network (10.10.1.0/24)
│ ├── Engineering Workstation (10.10.1.100)
│ ├── SCADA Server (10.10.1.50)
│ └── Historian (10.10.1.51)

│
└── OT Network (10.10.10.0/24)
├── PLC-001 Modbus (10.10.10.10)
├── PLC-002 S7 (10.10.10.11)
├── PLC-003 EtherNet/IP (10.10.10.12)
├── HMI-001 (10.10.10.50)
└── RTU-001 DNP3 (10.10.10.20)

Phase 1: OSINT Reconnaissance (2 hours)
Objectives
●​
●​
●​
●​

Gather publicly available information about AquaPure facility
Identify technology vendors and products in use
Enumerate personnel and organizational structure
Map external attack surface

Tasks
Task 1.1: Google Dorking
Search queries to execute:
1. site:aquapure.local filetype:pdf
2. "AquaPure" "SCADA" site:linkedin.com
3. inurl:aquapure.local intitle:login
4. "AquaPure Water Treatment" filetype:docx
5. "AquaPure" "network diagram"
Document findings:
- Exposed documents (save metadata)
- Job postings (extract technology mentions)
- Network architecture hints
Task 1.2: Shodan/Censys Search
# Shodan queries
shodan search "org:'AquaPure' port:502"
shodan search "net:203.0.113.0/24"
shodan search "ssl.cert.subject.cn:aquapure.local"
# Censys queries
censys search "autonomous_system.name:'AquaPure'"
censys search "services.port: 502 AND location.country: 'US'"
# Document findings:
# - Exposed ICS services (IP, port, product)
# - SSL certificates (subdomains, validity)

# - Geolocation data
Task 1.3: Subdomain Enumeration
# Passive enumeration
subfinder -d aquapure.local -o subdomains.txt
amass enum -passive -d aquapure.local -o amass_subs.txt
# Certificate transparency
curl -s "https://crt.sh/?q=%aquapure.local&output=json" | jq -r '.[].name_value' | sort -u >
crt_subs.txt
# Combine
cat subdomains.txt amass_subs.txt crt_subs.txt | sort -u > all_subdomains.txt
# Filter for OT-related
grep -E "scada|hmi|plc|ot|ics|control|plant" all_subdomains.txt > ot_subdomains.txt
Task 1.4: Employee Enumeration
LinkedIn searches:
1. "AquaPure" "SCADA Engineer"
2. "AquaPure" "Control Systems"
3. "AquaPure" "Automation"
Extract:
- Names and job titles
- Technologies mentioned in skills
- Tenure (identify senior engineers)
- Contact information (for social engineering pretexts)
Create organizational chart (mock):
┌─────────────────────────┐
│ Director of Operations │
└───────────┬─────────────┘
│
┌───────┴───────┐
│
│
┌───▼────┐ ┌────▼────┐
│ SCADA │ │ Plant │
│ Manager│ │ Manager │
└───┬────┘ └────┬────┘
│
│
┌───▼─────────┐ ┌──▼──────┐
│ SCADA Admin │ │PLC Techs│
└─────────────┘ └─────────┘
Task 1.5: Vendor Identification

Sources:
1. Job postings (required skills: Siemens TIA, Wonderware, OSIsoft)
2. Press releases (site:aquapure.local "contract awarded")
3. Annual reports (capital expenditure on automation)
Document vendor products:
- PLCs: Siemens S7-1200, Allen-Bradley CompactLogix
- HMI: Wonderware InTouch v10.1
- SCADA: Ignition by Inductive Automation
- Historian: OSIsoft PI System
- Network: Cisco IE-3000 Industrial Switches
Deliverable 1: OSINT Intelligence Report (2-3 pages)
●​
●​
●​
●​
●​
●​

Executive summary
Exposed internet-facing assets
Technology stack
Personnel intelligence
Vendor dependencies
Recommendations

Phase 2: Passive Network Reconnaissance (2 hours)
Objectives
●​ Capture and analyze OT network traffic without active probing
●​ Identify devices, protocols, and communication patterns
●​ Build baseline of normal operations

Tasks
Task 2.1: Packet Capture Setup
# Set up packet capture (assuming SPAN/TAP access)
sudo tcpdump -i eth0 -w aquapure_capture.pcap -G 3600 -W 2
# Capture for 1 hour during normal operations
# Filter for ICS ports
sudo tcpdump -i eth0 'port 102 or port 502 or port 20000 or port 44818 or port 4840' -w
ics_traffic.pcap
Task 2.2: GRASSMARLIN Analysis
# Launch GRASSMARLIN
java -jar GRASSMARLIN.jar
# Import PCAP
File → Import → ics_traffic.pcap

# Analyze:
1. Logical Map view (identify device hierarchy)
2. Physical Map view (network topology)
3. Protocol Distribution (which protocols in use)
4. Device Inventory (MAC OUI, IP, protocol)
# Export results
File → Export → CSV
# Document findings:
# - Number of PLCs detected
# - SCADA server communication patterns
# - HMI polling frequency
# - Unexpected devices (rogue? legitimate but unknown?)
Task 2.3: Wireshark Protocol Analysis
# Open capture in Wireshark
wireshark ics_traffic.pcap
# Modbus Analysis
Filter: modbus
1. Identify master (client) IPs
2. Identify slave (server) IPs and unit IDs
3. Analyze function codes (read/write ratio)
4. Extract register addresses being accessed
# S7comm Analysis
Filter: s7comm
1. Identify PLC IP addresses
2. Extract CPU model and firmware version
3. Analyze function codes (program upload? suspicious)
# Statistics → Protocol Hierarchy
Document protocol distribution:
- Modbus: 45%
- S7comm: 30%
- OPC UA: 15%
- HTTP: 10%
# Statistics → Conversations
Identify communication pairs:
- 10.10.1.50 (SCADA) ↔ 10.10.10.10 (PLC-001) - Modbus
- 10.10.1.50 (SCADA) ↔ 10.10.10.11 (PLC-002) - S7comm
- 10.10.1.100 (EWS) ↔ 10.10.10.11 (PLC-002) - S7comm (program upload?)
Task 2.4: Zeek Log Analysis

# Process PCAP with Zeek (with ICS plugins)
zeek -r ics_traffic.pcap /opt/zeek/share/zeek/site/icsnpp-modbus/__load__.zeek
# Analyze modbus.log
cat modbus.log | zeek-cut id.orig_h id.resp_h unit_id func | sort -u
# Example output:
# 10.10.1.50 10.10.10.10 1 READ_HOLDING_REGISTERS
# 10.10.1.50 10.10.10.10 1 READ_INPUT_REGISTERS
# 10.10.1.100 10.10.10.10 1 WRITE_SINGLE_REGISTER
# Analyze conn.log for baseline
cat conn.log | zeek-cut id.orig_h id.resp_h service duration orig_bytes resp_bytes | \
awk '$3=="modbus"{sum+=$4; count++} END {print "Avg Modbus connection duration:",
sum/count}'
# Identify anomalies:
# - Unexpected source IPs accessing PLCs
# - Write operations from non-authorized hosts
# - Unusual connection patterns
Task 2.5: Asset Inventory Creation
Create asset_inventory.json:
{
"devices": [
{
"ip": "10.10.10.10",
"mac": "00:1B:1B:1E:45:89",
"hostname": "PLC-001",
"device_type": "PLC",
"vendor": "Schneider Electric",
"model": "Modicon M340",
"firmware": "Unknown",
"protocols": ["Modbus TCP"],
"open_ports": [502],
"purdue_level": "Level 1",
"criticality": "High",
"function": "Chemical dosing control",
"last_seen": "2024-01-15T14:23:00Z"
},
{
"ip": "10.10.10.11",
"mac": "00:50:56:AB:CD:EF",
"hostname": "PLC-002",
"device_type": "PLC",
"vendor": "Siemens",
"model": "S7-1200",

"firmware": "V4.2.1",
"protocols": ["S7comm"],
"open_ports": [80, 102, 161],
"purdue_level": "Level 1",
"criticality": "High",
"function": "Pump control station 1",
"vulnerabilities": ["CVE-2020-15368"],
"last_seen": "2024-01-15T14:25:00Z"
}
]
}
Deliverable 2: Passive Reconnaissance Report
●​
●​
●​
●​
●​

Network topology diagram
Asset inventory (IP, vendor, model, protocol)
Communication flow diagrams
Protocol analysis summary
Baseline behavioral patterns

Phase 3: Active Reconnaissance (3 hours)
Objectives
●​
●​
●​
●​

Perform safe active scanning of OT network
Enumerate devices and services
Fingerprint operating systems and firmware versions
Identify vulnerabilities

Tasks
Task 3.1: Conservative Nmap Scanning
# Ping sweep (identify live hosts)
sudo nmap -sn 10.10.10.0/24 -oA ping_sweep
# Extract live IPs
cat ping_sweep.gnmap | grep "Status: Up" | awk '{print $2}' > live_hosts.txt
# Port scan (ICS ports only, slow rate)
sudo nmap -Pn -sT -p 80,102,161,443,502,1089,1091,2222,4840,8080,20000,44818,47808
\
--max-retries 1 --scan-delay 100ms --max-rate 50 \
-iL live_hosts.txt -oA ics_port_scan
# Service version detection (minimal)
sudo nmap -Pn -sT -sV --version-intensity 0 \

-p 102,502,44818 \
-iL live_hosts.txt -oA ics_service_scan
Task 3.2: NSE Script Enumeration
# Modbus discovery
sudo nmap -Pn -sT -p 502 --script modbus-discover.nse 10.10.10.10 -oN modbus_enum.txt
# S7comm enumeration
sudo nmap -Pn -sT -p 102 --script s7-info.nse 10.10.10.11 -oN s7_enum.txt
# OPC UA discovery
sudo nmap -Pn -sT -p 4840 --script opcua-info.nse 10.10.10.50 -oN opcua_enum.txt
# Ethernet/IP (if applicable)
sudo nmap -Pn -sU -p 44818 --script enip-info.nse 10.10.10.12 -oN enip_enum.txt
# Document findings:
# - Device models and serial numbers
# - Firmware versions
# - Available function codes/services
# - Vendor-specific information
Task 3.3: ISF Framework Reconnaissance
# Launch ISF
python3 isf.py
# S7 Scanner
isf > use scanners/s7comm_scanner
isf (S7comm Scanner) > set target 10.10.10.11
isf (S7comm Scanner) > run
# Document:
# - CPU model
# - Firmware version
# - System name
# - Serial number
# Modbus Scanner
isf > use scanners/modbus_scanner
isf (Modbus Scanner) > set target 10.10.10.10
isf (Modbus Scanner) > set unit_id 1
isf (Modbus Scanner) > run
# Document:
# - Valid unit IDs
# - Accessible function codes

# - Register map (if enumeration successful)
Task 3.4: Protocol-Specific Enumeration
Modbus Register Mapping:
#!/usr/bin/env python3
# modbus_register_scanner.py
import snap7
from pymodbus.client import ModbusTcpClient
def scan_modbus_registers(ip, unit_id=1, start=0, end=1000):
client = ModbusTcpClient(ip, port=502)
client.connect()
valid_registers = []
for addr in range(start, end):
try:
result = client.read_holding_registers(addr, 1, unit=unit_id)
if not result.isError():
value = result.registers[0]
valid_registers.append({"address": addr, "value": value})
print(f"[+] Register {addr}: {value}")
except:
pass
client.close()
return valid_registers
# Execute
registers = scan_modbus_registers('10.10.10.10')
# Save to JSON
import json
with open("modbus_register_map.json", "w") as f:
json.dump(registers, f, indent=2)
S7comm Program Upload (if authorized):
import snap7
plc = snap7.client.Client()
plc.connect('10.10.10.11', 0, 1)
# Get PLC info
cpu_info = plc.get_cpu_info()

print(f"PLC: {cpu_info.ModuleTypeName}")
print(f"Firmware: {cpu_info.ASName}")
# List blocks
blocks = plc.list_blocks()
print(f"Blocks: {blocks}")
# Upload OB1 (main program block)
ob1 = plc.upload('OB', 1)
with open("OB1.mc7", "wb") as f:
f.write(ob1)
print("[+] Uploaded OB1 for analysis")
plc.disconnect()
Task 3.5: Web Interface Reconnaissance
# Identify web servers
cat ics_port_scan.gnmap | grep "80/open\|443/open\|8080/open"
# Enumerate web interfaces
for ip in $(cat web_servers.txt); do
echo "[*] Scanning $ip"
# Identify technology
whatweb http://$ip
# Directory enumeration (gentle)
gobuster dir -u http://$ip -w /usr/share/wordlists/dirb/common.txt -t 5 -q -o ${ip}_dirs.txt
# Nikto scan (slow mode)
nikto -h http://$ip -Tuning 1 -o ${ip}_nikto.txt
done
# Document findings:
# - HMI login pages (default credentials?)
# - Exposed configuration interfaces
# - Version disclosure (check for CVEs)
Deliverable 3: Active Reconnaissance Report
●​
●​
●​
●​
●​
●​

Comprehensive port scan results
Service version matrix (IP, port, service, version)
Device fingerprinting (vendor, model, firmware)
Register/tag enumeration (Modbus, OPC UA, etc.)
Web interface inventory
Identified vulnerabilities (CVE mapping)

Phase 4: Vulnerability Assessment (2 hours)
Objectives
●​
●​
●​
●​

Correlate discovered assets with known vulnerabilities
Assess security posture (authentication, encryption, patching)
Identify high-risk exposures
Prioritize findings by risk

Tasks
Task 4.1: CVE Correlation
#!/usr/bin/env python3
# cve_correlator.py
import json
import requests
def get_cves_for_product(vendor, product, version):
"""
Query CVE database for vulnerabilities
"""
# Use NVD API
url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
params = {
"keywordSearch": f"{vendor} {product} {version}"
}
response = requests.get(url, params=params)
if response.status_code == 200:
data = response.json()
return data.get("result", {}).get("CVE_Items", [])
return []
# Load asset inventory
with open("asset_inventory.json") as f:
inventory = json.load(f)
# Check each device for CVEs
for device in inventory["devices"]:
vendor = device["vendor"]
model = device["model"]
firmware = device.get("firmware", "Unknown")
print(f"\n[*] Checking {device['ip']} - {vendor} {model}")

cves = get_cves_for_product(vendor, model, firmware)
if cves:
print(f"[!] Found {len(cves)} potential CVEs:")
for cve in cves[:5]: # Top 5
cve_id = cve["cve"]["CVE_data_meta"]["ID"]
description = cve["cve"]["description"]["description_data"][0]["value"]
print(f" {cve_id}: {description[:100]}...")
device["vulnerabilities"] = [cve["cve"]["CVE_data_meta"]["ID"] for cve in cves]
else:
print("[+] No known CVEs found")
# Save updated inventory
with open("asset_inventory_with_cves.json", "w") as f:
json.dump(inventory, f, indent=2)
Task 4.2: Authentication Testing
# Test for default credentials
# Create credential list
cat > default_creds.txt << EOF
admin:admin
admin:password
admin:12345
root:root
administrator:administrator
siemens:siemens
user:user
EOF
# Test Modbus (no auth by default, but some gateways have web interfaces)
for ip in $(cat modbus_devices.txt); do
echo "[*] Testing $ip for web interface with default creds"
hydra -C default_creds.txt http-get://$ip
done
# Test S7 PLCs (no password protection in older models)
for ip in $(cat s7_devices.txt); do
python3 -c "import snap7; plc = snap7.client.Client(); plc.connect('$ip', 0, 1); print('[+] $ip:
No password protection'); plc.disconnect()"
done
# Document:
# - Devices with no authentication
# - Devices with default credentials
# - Devices with custom credentials (rate limited testing)

Task 4.3: Encryption Assessment
# Check if industrial protocols use encryption
tshark -r ics_traffic.pcap -Y "modbus || s7comm || dnp3" -T fields -e ip.src -e ip.dst -e tcp.port
|\
sort -u > unencrypted_traffic.txt
# Result: Most ICS protocols are plaintext (expected)
# Check OPC UA security
nmap -Pn -p 4840 --script opcua-info.nse 10.10.10.50 | grep -i security
# Document:
# - Protocols using plaintext (Modbus, S7comm, DNP3)
# - Protocols with encryption (OPC UA with SignAndEncrypt?)
# - Web interfaces using HTTP vs HTTPS
Task 4.4: Network Segmentation Assessment
# From passive capture, analyze cross-network traffic
cat conn.log | zeek-cut id.orig_h id.resp_h | awk '{print $1, $2}' | sort -u
# Check for:
# 1. IT → OT traffic (should be restricted)
# 2. OT → Internet traffic (should be blocked)
# 3. SCADA → PLC on different subnets (acceptable)
# Document violations:
# - 10.10.1.100 (EWS) → 10.10.10.10 (PLC): ALLOWED (expected)
# - 10.10.10.10 (PLC) → 8.8.8.8 (Internet DNS): VIOLATION (PLC shouldn't reach internet)
# - 203.0.113.10 (DMZ) → 10.10.10.50 (HMI): VIOLATION (DMZ shouldn't access OT
directly)
Task 4.5: Risk Scoring
Create risk matrix for each finding:
Finding: Siemens S7-1200 PLC (10.10.10.11) running vulnerable firmware
(CVE-2020-15368)
- Likelihood: High (exploit publicly available)
- Impact: Critical (DoS causes plant shutdown)
- Risk Score: CRITICAL
Finding: Modbus accessible without authentication (10.10.10.10)
- Likelihood: High (no authentication required)
- Impact: High (unauthorized control of chemical dosing)
- Risk Score: HIGH

Finding: HMI using default credentials admin:admin (10.10.10.50)
- Likelihood: Medium (requires network access)
- Impact: High (full process visibility and control)
- Risk Score: HIGH
Finding: OPC UA using Security Policy None (10.10.10.51)
- Likelihood: Medium (protocol accessible but requires OPC client)
- Impact: Medium (data disclosure)
- Risk Score: MEDIUM
Deliverable 4: Vulnerability Assessment Report
●​
●​
●​
●​
●​

Vulnerability matrix (device, CVE, CVSS, status)
Authentication findings
Encryption assessment
Network segmentation analysis
Risk-prioritized findings (Critical → Low)

Phase 5: Threat Modeling (2 hours)
Objectives
●​
●​
●​
●​

Map potential attack paths using discovered information
Apply MITRE ATT&CK for ICS framework
Identify crown jewels and critical attack scenarios
Develop defensive recommendations

Tasks
Task 5.1: Crown Jewel Identification
Identify critical assets:
1. Chemical Dosing PLC (10.10.10.10)
- Function: Controls chlorine and fluoride dosing
- Impact if compromised: Water contamination
- Purdue Level: 1
- Criticality: CRITICAL
2. Pump Control PLC (10.10.10.11)
- Function: Controls main water pumps
- Impact if compromised: Loss of water supply
- Purdue Level: 1
- Criticality: CRITICAL
3. SCADA Server (10.10.1.50)
- Function: Centralized monitoring and control

- Impact if compromised: Loss of visibility, unauthorized commands
- Purdue Level: 2
- Criticality: HIGH
4. Historian (10.10.1.51)
- Function: Stores process data
- Impact if compromised: Data integrity loss, compliance issues
- Purdue Level: 3
- Criticality: MEDIUM
Task 5.2: Attack Path Mapping
Scenario 1: Water Contamination Attack
Attack Chain:
1. Initial Access: Spear-phishing engineering staff (T0883)
2. Execution: Malicious macro executes payload (T0871)
3. Persistence: Install backdoor on engineering workstation (T0891)
4. Lateral Movement: RDP from EWS to SCADA server (T0886)
5. Discovery: Enumerate PLCs via Modbus scan (T0840)
6. Collection: Read I/O image to identify chlorine dosing registers (T0877)
7. Impair Process Control: Write excessive chlorine setpoint to Modbus register (T0836)
8. Inhibit Response: Block high chlorine alarms to HMI (T0804)
9. Impact: Water contamination (T0879)
Mitigations:
- Email security (anti-phishing)
- Endpoint protection on EWS
- Network segmentation (prevent EWS → PLC direct access)
- Parameter change monitoring and approval workflow
- Redundant alarm pathways (OOB alerting)
Scenario 2: Denial of Service (Plant Shutdown)
Attack Chain:
1. Initial Access: VPN compromise via stolen credentials (T0883)
2. Lateral Movement: Pivot from DMZ to OT network (T0886)
3. Discovery: Scan for S7 PLCs on port 102 (T0840)
4. Inhibit Response Function: Send PLC STOP command to all S7 PLCs (T0816)
5. Impact: Loss of Control, Loss of Productivity (T0826, T0828)
Mitigations:
- MFA on VPN
- Network segmentation (firewall between DMZ and OT)
- IDS rule for S7comm PLC STOP commands
- PLC write protection (require password for control functions)
Task 5.3: ATT&CK Navigator Layer

Create ATT&CK layer highlighting identified threats:
{
"name": "AquaPure Water Treatment - Threat Model",
"domain": "ics-attack",
"techniques": [
{"techniqueID": "T0883", "color": "#ff0000", "comment": "VPN, spear-phishing"},
{"techniqueID": "T0886", "color": "#ff0000", "comment": "RDP, SMB lateral movement"},
{"techniqueID": "T0877", "color": "#ff6600", "comment": "Modbus register enumeration"},
{"techniqueID": "T0836", "color": "#ff0000", "comment": "Chlorine setpoint modification"},
{"techniqueID": "T0816", "color": "#ff0000", "comment": "S7 PLC STOP command"},
{"techniqueID": "T0804", "color": "#ff6600", "comment": "Alarm suppression"},
{"techniqueID": "T0879", "color": "#cc0000", "comment": "Water contamination"}
]
}
# Load in ATT&CK Navigator and visualize
Task 5.4: Defense-in-Depth Recommendations
Layer 1: Perimeter Security
- Implement MFA for VPN access
- Deploy web application firewall (WAF) for DMZ
- Enable IDS/IPS with ICS-specific rules
Layer 2: Network Segmentation
- Enforce strict firewall rules between IT and OT
- Deploy unidirectional gateways for historian data flow (OT → IT only)
- Implement VLANs and micro-segmentation within OT network
Layer 3: Device Hardening
- Update PLC firmware to latest versions (patch CVE-2020-15368)
- Change all default credentials
- Enable PLC write protection and password policies
- Disable unnecessary services on HMI/SCADA systems
Layer 4: Monitoring and Detection
- Deploy Zeek with ICS plugins for protocol anomaly detection
- Configure SIEM with ICS-specific use cases:
- Modbus write from unauthorized source
- S7comm PLC STOP command
- Parameter changes outside normal range
- Implement file integrity monitoring (FIM) for PLC programs
Layer 5: Response and Recovery
- Develop ICS incident response plan
- Create golden image backups of PLC programs and SCADA configs
- Establish out-of-band communication for emergency shutdown
- Conduct tabletop exercises for water contamination scenario

Deliverable 5: Threat Model and Risk Assessment
●​
●​
●​
●​
●​

Crown jewel analysis
Attack path diagrams (at least 2 scenarios)
ATT&CK Navigator layer
Defense-in-depth recommendations
Executive summary with risk scores

Phase 6: Final Report Compilation (1 hour)
Comprehensive Reconnaissance Report Structure
1. Executive Summary (1 page)
●​
●​
●​
●​

Engagement overview
Key findings summary
Risk assessment (Critical: X, High: Y, Medium: Z)
Top 5 recommendations

2. OSINT Intelligence (3-5 pages)
●​
●​
●​
●​
●​

Exposed internet-facing assets
Technology stack
Personnel and organizational structure
Vendor dependencies
Supply chain risks

3. Network Reconnaissance (5-7 pages)
●​
●​
●​
●​
●​

Network topology
Asset inventory (table format)
Protocol analysis
Communication flows
Baseline behavioral patterns

4. Vulnerability Assessment (5-7 pages)
●​
●​
●​
●​
●​

Identified vulnerabilities (CVE mapping)
Authentication weaknesses
Encryption gaps
Network segmentation issues
Prioritized findings matrix

5. Threat Modeling (3-5 pages)
●​
●​
●​
●​

Crown jewel analysis
Attack scenarios (2-3 detailed)
MITRE ATT&CK mapping
Risk scoring

6. Recommendations (3-5 pages)
●​
●​
●​
●​

Short-term fixes (0-30 days)
Medium-term improvements (30-90 days)
Long-term strategic initiatives (90+ days)
Defense-in-depth architecture

7. Appendices
●​
●​
●​
●​
●​
●​

A: Asset inventory (full JSON)
B: Nmap scan results
C: Packet capture analysis
D: CVE details
E: ATT&CK Navigator layer
F: Tool versions and methodology

Grading Rubric
OSINT Reconnaissance (20 points)
●​
●​
●​
●​

Thoroughness of search engine dorking (5 pts)
Shodan/Censys effectiveness (5 pts)
Subdomain enumeration completeness (5 pts)
Personnel and vendor intelligence (5 pts)

Passive Reconnaissance (20 points)
●​
●​
●​
●​

PCAP capture quality (5 pts)
Protocol analysis depth (5 pts)
Asset inventory accuracy (5 pts)
Behavioral baseline establishment (5 pts)

Active Reconnaissance (20 points)
●​
●​
●​
●​

Safe scanning methodology (5 pts)
Service enumeration completeness (5 pts)
Protocol-specific reconnaissance (5 pts)
Web interface discovery (5 pts)

Vulnerability Assessment (20 points)
●​
●​
●​
●​

CVE correlation accuracy (5 pts)
Authentication testing (5 pts)
Encryption assessment (5 pts)
Risk scoring methodology (5 pts)

Threat Modeling (15 points)

●​
●​
●​
●​

Crown jewel identification (3 pts)
Attack path realism (5 pts)
ATT&CK mapping accuracy (4 pts)
Defensive recommendations (3 pts)

Report Quality (5 points)
●​ Clarity and organization (2 pts)
●​ Technical accuracy (2 pts)
●​ Actionable recommendations (1 pt)
Total: 100 points

Bonus Challenges (+10 points each)
Challenge 1: Develop Custom Exploit
●​
●​
●​
●​

Identify a vulnerability in the lab environment
Develop proof-of-concept exploit (non-destructive)
Document exploit development process
Provide remediation guidance

Challenge 2: Build Detection Rules
●​
●​
●​
●​

Create 10+ Snort/Suricata rules for identified threats
Test rules against PCAP
Tune to minimize false positives
Document detection logic

Challenge 3: Automate Reconnaissance
●​
●​
●​
●​

Develop Python framework that automates Phases 1-3
Generate JSON output for asset inventory
Include CVE correlation
Provide usage documentation

Conclusion
This comprehensive lab integrates all reconnaissance techniques from Module 1, providing
hands-on experience with real-world OT security assessment workflows. The final report
demonstrates your ability to:
1.​ Conduct thorough OSINT without active engagement
2.​ Analyze OT network traffic and protocols
3.​ Perform safe active reconnaissance in industrial environments
4.​ Assess vulnerabilities and prioritize risk
5.​ Model threats using industry frameworks (ATT&CK)

6.​ Develop actionable security recommendations

Additional Resources
Lab Environments
●​ LabShock: https://github.com/zakharb/labshock
●​ GRFICSv2: https://github.com/Fortiphyd/GRFICSv2
●​ CSET: https://github.com/cisagov/cset

Tools Used in This Lab
●​
●​
●​
●​
●​
●​

GRASSMARLIN: https://github.com/nsacyber/GRASSMARLIN
Zeek + ICSNPP: https://github.com/cisagov/icsnpp
Nmap: https://nmap.org/
ISF: https://github.com/dark-lbp/isf
Subfinder: https://github.com/projectdiscovery/subfinder
Wireshark: https://www.wireshark.org/

Reference Materials
●​ SANS ICS515 Course:
https://www.sans.org/cyber-security-courses/ics-scada-cyber-security-essentials/
●​ NIST SP 800-82: https://csrc.nist.gov/publications/detail/sp/800-82/rev-2/final
●​ MITRE ATT&CK for ICS: https://attack.mitre.org/matrices/ics/

Berikut adalah poin-poin utama
("insight") dari

