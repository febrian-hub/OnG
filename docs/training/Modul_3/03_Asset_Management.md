Lesson 03: Asset Mgmnt &
Vulnerability Scanning

Lesson 03: OT Asset Management &
Vulnerability Scanning
Learning Objectives
●​
●​
●​
●​
●​
●​

Deploy passive asset discovery tools for OT networks
Perform safe active scanning without disrupting industrial processes
Build comprehensive asset inventory with firmware versions and CVE mapping
Prioritize vulnerabilities by operational risk
Implement continuous asset monitoring
Develop patch management strategies for OT environments

Introduction
Asset visibility is the foundation of OT security. Unlike IT networks where agents can be
deployed to every endpoint, OT networks contain:
●​
●​
●​
●​

Legacy devices without agent support (20+ year old PLCs)
Safety-critical systems that cannot be modified
Embedded devices with limited resources
Proprietary protocols not supported by standard discovery tools

Key Challenges:
●​
●​
●​
●​

Active scanning can crash PLCs or disrupt operations
Many OT devices don't respond to standard discovery (ICMP, SNMP)
Firmware versions often not exposed via network protocols
No centralized asset database in most facilities

This lesson provides defensive visibility to counter Module 2 attacks:
●​ Rogue devices (Module 2 lateral movement): Detect unauthorized devices on OT
network
●​ Firmware manipulation (Module 2 Lesson 06): Baseline firmware hashes to detect
tampering
●​ Supply chain attacks (Module 2 Lesson 07): Inventory all software/firmware for
vulnerability assessment

1. Passive Asset Discovery
1.1 GRASSMARLIN

GRASSMARLIN (developed by NSA, released as open-source) performs passive network
monitoring to discover ICS/SCADA devices without sending any packets.
Installation:
#!/bin/bash
# install_grassmarlin.sh
# Download GRASSMARLIN
cd /opt
wget
https://github.com/nsacyber/GRASSMARLIN/releases/download/v3.2.1/grassmarlin-3.2.1.zip
unzip grassmarlin-3.2.1.zip
cd GRASSMARLIN-3.2.1
# Install Java (required)
sudo apt install -y openjdk-11-jre
# Run GRASSMARLIN
java -jar grassmarlin.jar
Usage:
# Capture traffic for analysis
sudo tcpdump -i eth1 -w ot_traffic.pcap -G 3600 -W 24 # 24 hours of capture
# Import into GRASSMARLIN
# File -> Import PCAP -> ot_traffic.pcap
# Wait for analysis to complete
# View: Logical Graph (network topology) and Physical View (asset list)
GRASSMARLIN Output:
●​
●​
●​
●​

Network topology diagram showing all communicating devices
Device fingerprinting (vendor, model, protocol)
Protocol distribution (Modbus, S7comm, DNP3, etc.)
Communication patterns and data flows

1.2 Zeek-Based Passive Discovery
# passive_asset_discovery.py
# Extract asset inventory from Zeek logs
import json
from collections import defaultdict
import ipaddress
class PassiveAssetDiscovery:
def __init__(self, zeek_log_dir):

self.zeek_log_dir = zeek_log_dir
self.assets = {}
def discover_from_conn_log(self):
"""Discover assets from Zeek conn.log"""
conn_log = f"{self.zeek_log_dir}/conn.log"
with open(conn_log, 'r') as f:
for line in f:
if line.startswith('#'):
continue
try:
log = json.loads(line)
src_ip = log.get('id.orig_h')
dst_ip = log.get('id.resp_h')
dst_port = log.get('id.resp_p')
proto = log.get('proto')
# Record both source and destination
for ip in [src_ip, dst_ip]:
if ip not in self.assets:
self.assets[ip] = {
'ip': ip,
'mac': None,
'hostname': None,
'vendor': None,
'protocols': set(),
'open_ports': set(),
'first_seen': log.get('ts'),
'last_seen': log.get('ts')
}
# Update last seen
self.assets[ip]['last_seen'] = log.get('ts')
# Record destination port
if dst_port:
self.assets[dst_ip]['open_ports'].add(dst_port)
# Infer protocol from port
if dst_port == 502:
self.assets[dst_ip]['protocols'].add('Modbus TCP')
elif dst_port == 102:
self.assets[dst_ip]['protocols'].add('S7comm')
elif dst_port == 20000:
self.assets[dst_ip]['protocols'].add('DNP3')
elif dst_port == 44818:

self.assets[dst_ip]['protocols'].add('EtherNet/IP')
elif dst_port == 2222:
self.assets[dst_ip]['protocols'].add('EtherCAT')
except:
continue
def discover_from_modbus_log(self):
"""Extract device info from Modbus traffic"""
modbus_log = f"{self.zeek_log_dir}/modbus.log"
try:
with open(modbus_log, 'r') as f:
for line in f:
if line.startswith('#'):
continue
log = json.loads(line)
dst_ip = log.get('id.resp_h')
if dst_ip in self.assets:
self.assets[dst_ip]['device_type'] = 'PLC/RTU'
# Extract Modbus device identification if available
if 'mei_response' in log:
self.assets[dst_ip]['vendor'] = log.get('mei_response', {}).get('vendor')
self.assets[dst_ip]['product_code'] = log.get('mei_response',
{}).get('product_code')
except:
pass
def discover_from_s7comm_log(self):
"""Extract Siemens PLC info from S7comm traffic"""
s7comm_log = f"{self.zeek_log_dir}/s7comm.log"
try:
with open(s7comm_log, 'r') as f:
for line in f:
if line.startswith('#'):
continue
log = json.loads(line)
dst_ip = log.get('id.resp_h')
if dst_ip in self.assets:
self.assets[dst_ip]['device_type'] = 'Siemens PLC'
self.assets[dst_ip]['vendor'] = 'Siemens'

# Extract PLC type from rosctr field
if 'rosctr_name' in log and 'UserData' in log['rosctr_name']:
self.assets[dst_ip]['model'] = 'S7-1200/1500'
except:
pass
def export_inventory(self, output_file='asset_inventory.json'):
"""Export discovered assets to JSON"""
# Convert sets to lists for JSON serialization
for ip, asset in self.assets.items():
asset['protocols'] = list(asset['protocols'])
asset['open_ports'] = list(asset['open_ports'])
with open(output_file, 'w') as f:
json.dump(self.assets, f, indent=2)
print(f"[+] Discovered {len(self.assets)} assets")
print(f"[+] Asset inventory exported to {output_file}")
# Print summary
plc_count = sum(1 for a in self.assets.values() if a.get('device_type') in ['PLC/RTU',
'Siemens PLC'])
print(f"[+] PLCs/RTUs: {plc_count}")
protocols = defaultdict(int)
for asset in self.assets.values():
for proto in asset.get('protocols', []):
protocols[proto] += 1
print(f"[+] Protocol distribution: {dict(protocols)}")
# Usage
if __name__ == '__main__':
discovery = PassiveAssetDiscovery('/opt/zeek/logs/current')
print("[*] Discovering assets from Zeek logs...")
discovery.discover_from_conn_log()
discovery.discover_from_modbus_log()
discovery.discover_from_s7comm_log()
discovery.export_inventory()
Expected Output:
[*] Discovering assets from Zeek logs...
[+] Discovered 47 assets
[+] Asset inventory exported to asset_inventory.json
[+] PLCs/RTUs: 12

[+] Protocol distribution: {'Modbus TCP': 12, 'S7comm': 5, 'DNP3': 2, 'EtherNet/IP': 3}
Sample Inventory JSON:
{
"10.20.10.10": {
"ip": "10.20.10.10",
"mac": "00:1B:1B:9F:4A:2C",
"hostname": null,
"vendor": "Siemens",
"device_type": "Siemens PLC",
"model": "S7-1200/1500",
"protocols": ["S7comm", "Modbus TCP"],
"open_ports": [102, 502],
"first_seen": "2025-01-03T08:00:00.000Z",
"last_seen": "2025-01-03T14:30:00.000Z"
}
}

2. Safe Active Scanning
2.1 Nmap for OT (Conservative Approach)
#!/bin/bash
# safe_ot_scan.sh
# Conservative Nmap scanning for OT networks
TARGET="10.20.10.0/24" # PLC network
echo "[*] Starting SAFE OT network scan"
echo "[!] WARNING: Test in lab first, get change approval for production"
# Phase 1: Ping sweep (ICMP only, no port scan)
echo "[*] Phase 1: Ping sweep (non-intrusive)"
nmap -sn -PE -PP $TARGET -oN ot_ping_sweep.txt
# Phase 2: TCP Connect scan (no SYN scan, full 3-way handshake)
# Only scan known ICS ports
echo "[*] Phase 2: TCP Connect scan on ICS ports only"
nmap -Pn -sT \
-p 102,502,20000,44818,2222,47808,34962,34963,34964 \
--max-retries 1 \
--scan-delay 1000ms \
--max-rate 10 \
$TARGET \
-oN ot_port_scan.txt
# Phase 3: Service version detection (CAUTIOUS)

# Only on devices that responded in Phase 2
echo "[*] Phase 3: Service version detection (minimal probes)"
nmap -Pn -sT \
-p 102,502 \
--version-intensity 0 \
--max-retries 1 \
--scan-delay 2000ms \
$TARGET \
-oN ot_version_scan.txt
echo "[+] Scan complete. Review output files."
echo "[!] Verify no devices went offline during scan"
Safe Nmap Parameters for OT:
●​ -sT: TCP Connect (full 3-way handshake, not SYN scan)
●​ -Pn: Skip ping (assume host is up, avoid ICMP that might crash PLCs)
●​ --max-retries 1: Only retry once
●​ --scan-delay 1000ms: Wait 1 second between probes
●​ --max-rate 10: Limit to 10 packets/second
●​ --version-intensity 0: Minimal version probes
NSE Scripts for ICS (use with caution):
# Modbus device identification
nmap -Pn -sT -p 502 \
--script modbus-discover.nse \
--script-args='modbus-discover.aggressive=false' \
10.20.10.10
# S7comm PLC identification
nmap -Pn -sT -p 102 \
--script s7-info.nse \
10.20.10.10
# BACnet device enumeration
nmap -Pn -sU -p 47808 \
--script bacnet-info.nse \
10.20.10.15

2.2 Tenable OT Security / Nessus Industrial
Tenable OT Security (formerly Indegy) provides safe scanning specifically designed for OT:
# Using Nessus with OT-safe scan policy
# 1. Create custom scan policy in Nessus UI:
# - Discovery: Ping sweep only

# - Port scan: Custom port list (102,502,20000,44818)
# - Service discovery: Minimal
# - Network timing: Paranoid (slowest)
# - Max simultaneous checks per host: 3
# - Max concurrent hosts: 5
# 2. Run scan via CLI
/opt/nessus/bin/nessuscli scan new \
--policy "OT Safe Scan Policy" \
--targets "10.20.10.0/24" \
--name "PLC Network Discovery"
# 3. Export results
/opt/nessus/bin/nessuscli scan export 123 --format csv

3. Asset Inventory Management
3.1 Automated Asset Database
# asset_database.py
# Centralized OT asset inventory with SQLite backend
import sqlite3
import json
import hashlib
from datetime import datetime
class AssetDatabase:
def __init__(self, db_path='ot_assets.db'):
self.db_path = db_path
self.init_database()
def init_database(self):
"""Initialize asset database schema"""
conn = sqlite3.connect(self.db_path)
cursor = conn.cursor()
cursor.execute('''
CREATE TABLE IF NOT EXISTS assets (
id INTEGER PRIMARY KEY AUTOINCREMENT,
ip_address TEXT UNIQUE NOT NULL,
mac_address TEXT,
hostname TEXT,
vendor TEXT,
model TEXT,
device_type TEXT,
firmware_version TEXT,

firmware_hash TEXT,
serial_number TEXT,
purdue_level INTEGER,
criticality TEXT,
location TEXT,
owner TEXT,
first_discovered TEXT,
last_seen TEXT,
status TEXT
)
''')
cursor.execute('''
CREATE TABLE IF NOT EXISTS open_ports (
id INTEGER PRIMARY KEY AUTOINCREMENT,
asset_id INTEGER,
port INTEGER,
protocol TEXT,
service TEXT,
FOREIGN KEY (asset_id) REFERENCES assets(id)
)
''')
cursor.execute('''
CREATE TABLE IF NOT EXISTS vulnerabilities (
id INTEGER PRIMARY KEY AUTOINCREMENT,
asset_id INTEGER,
cve_id TEXT,
cvss_score REAL,
description TEXT,
remediation TEXT,
status TEXT,
discovered_date TEXT,
FOREIGN KEY (asset_id) REFERENCES assets(id)
)
''')
cursor.execute('''
CREATE TABLE IF NOT EXISTS firmware_baseline (
id INTEGER PRIMARY KEY AUTOINCREMENT,
asset_id INTEGER,
firmware_hash TEXT,
capture_date TEXT,
is_golden BOOLEAN,
FOREIGN KEY (asset_id) REFERENCES assets(id)
)
''')

conn.commit()
conn.close()
def add_asset(self, asset_data):
"""Add new asset to database"""
conn = sqlite3.connect(self.db_path)
cursor = conn.cursor()
try:
cursor.execute('''
INSERT INTO assets (
ip_address, mac_address, hostname, vendor, model,
device_type, firmware_version, serial_number,
purdue_level, criticality, location, owner,
first_discovered, last_seen, status
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
''', (
asset_data['ip'],
asset_data.get('mac'),
asset_data.get('hostname'),
asset_data.get('vendor'),
asset_data.get('model'),
asset_data.get('device_type'),
asset_data.get('firmware_version'),
asset_data.get('serial_number'),
asset_data.get('purdue_level'),
asset_data.get('criticality', 'Medium'),
asset_data.get('location'),
asset_data.get('owner'),
datetime.now().isoformat(),
datetime.now().isoformat(),
'Active'
))
asset_id = cursor.lastrowid
# Add open ports
for port_info in asset_data.get('ports', []):
cursor.execute('''
INSERT INTO open_ports (asset_id, port, protocol, service)
VALUES (?, ?, ?, ?)
''', (asset_id, port_info['port'], port_info.get('protocol', 'tcp'), port_info.get('service')))
conn.commit()
print(f"[+] Added asset: {asset_data['ip']} ({asset_data.get('device_type',
'Unknown')})")
except sqlite3.IntegrityError:

print(f"[!] Asset {asset_data['ip']} already exists, updating instead")
self.update_asset(asset_data)
conn.close()
def update_asset(self, asset_data):
"""Update existing asset"""
conn = sqlite3.connect(self.db_path)
cursor = conn.cursor()
cursor.execute('''
UPDATE assets
SET last_seen = ?, mac_address = ?, hostname = ?,
vendor = ?, model = ?, firmware_version = ?
WHERE ip_address = ?
''', (
datetime.now().isoformat(),
asset_data.get('mac'),
asset_data.get('hostname'),
asset_data.get('vendor'),
asset_data.get('model'),
asset_data.get('firmware_version'),
asset_data['ip']
))
conn.commit()
conn.close()
def add_vulnerability(self, ip_address, cve_data):
"""Add CVE to asset"""
conn = sqlite3.connect(self.db_path)
cursor = conn.cursor()
# Get asset ID
cursor.execute('SELECT id FROM assets WHERE ip_address = ?', (ip_address,))
result = cursor.fetchone()
if not result:
print(f"[!] Asset {ip_address} not found")
return
asset_id = result[0]
cursor.execute('''
INSERT INTO vulnerabilities (
asset_id, cve_id, cvss_score, description, remediation, status, discovered_date
) VALUES (?, ?, ?, ?, ?, ?, ?)
''', (

asset_id,
cve_data['cve_id'],
cve_data.get('cvss_score', 0.0),
cve_data.get('description'),
cve_data.get('remediation'),
'Open',
datetime.now().isoformat()
))
conn.commit()
conn.close()
print(f"[+] Added {cve_data['cve_id']} to {ip_address}")
def get_critical_assets(self):
"""Get all critical assets"""
conn = sqlite3.connect(self.db_path)
cursor = conn.cursor()
cursor.execute('''
SELECT ip_address, device_type, vendor, model, criticality
FROM assets
WHERE criticality = 'Critical'
ORDER BY purdue_level
''')
assets = cursor.fetchall()
conn.close()
return assets
def get_vulnerable_assets(self, cvss_threshold=7.0):
"""Get assets with high-severity vulnerabilities"""
conn = sqlite3.connect(self.db_path)
cursor = conn.cursor()
cursor.execute('''
SELECT DISTINCT a.ip_address, a.device_type, v.cve_id, v.cvss_score
FROM assets a
JOIN vulnerabilities v ON a.id = v.asset_id
WHERE v.cvss_score >= ? AND v.status = 'Open'
ORDER BY v.cvss_score DESC
''', (cvss_threshold,))
vulnerabilities = cursor.fetchall()
conn.close()
return vulnerabilities

def export_csv(self, output_file='asset_inventory.csv'):
"""Export inventory to CSV"""
conn = sqlite3.connect(self.db_path)
cursor = conn.cursor()
cursor.execute('''
SELECT ip_address, mac_address, hostname, vendor, model,
device_type, firmware_version, purdue_level, criticality,
location, owner, last_seen
FROM assets
ORDER BY purdue_level, ip_address
''')
import csv
with open(output_file, 'w', newline='') as csvfile:
writer = csv.writer(csvfile)
writer.writerow(['IP', 'MAC', 'Hostname', 'Vendor', 'Model', 'Type',
'Firmware', 'Purdue Level', 'Criticality', 'Location', 'Owner', 'Last Seen'])
for row in cursor.fetchall():
writer.writerow(row)
conn.close()
print(f"[+] Inventory exported to {output_file}")
# Usage example
if __name__ == '__main__':
db = AssetDatabase()
# Add PLC asset
plc = {
'ip': '10.20.10.10',
'mac': '00:1B:1B:9F:4A:2C',
'vendor': 'Siemens',
'model': 'S7-1200 CPU 1214C',
'device_type': 'PLC',
'firmware_version': 'V4.5.2',
'serial_number': 'S C-X4U304308012',
'purdue_level': 2,
'criticality': 'Critical',
'location': 'Water Treatment - Building A',
'owner': 'Operations Team',
'ports': [
{'port': 102, 'protocol': 'tcp', 'service': 'S7comm'},
{'port': 502, 'protocol': 'tcp', 'service': 'Modbus'}
]
}

db.add_asset(plc)
# Add vulnerability
db.add_vulnerability('10.20.10.10', {
'cve_id': 'CVE-2022-38465',
'cvss_score': 9.8,
'description': 'Siemens SIMATIC S7-1200 CPU vulnerable to unauthenticated remote
code execution',
'remediation': 'Update to firmware V4.6.0 or later'
})
# Get critical assets
print("\n[*] Critical Assets:")
for asset in db.get_critical_assets():
print(f" {asset[0]} - {asset[1]} ({asset[2]} {asset[3]})")
# Get vulnerable assets
print("\n[*] High-Risk Vulnerabilities (CVSS >= 7.0):")
for vuln in db.get_vulnerable_assets():
print(f" {vuln[0]} - {vuln[2]} (CVSS: {vuln[3]})")
# Export to CSV
db.export_csv()

4. Vulnerability Management
4.1 CVE Correlation
# cve_correlation.py
# Correlate asset inventory with CVE database
import requests
import json
import time
from asset_database import AssetDatabase
class CVECorrelation:
def __init__(self, nvd_api_key=None):
self.nvd_api_key = nvd_api_key
self.nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
def search_cves(self, vendor, product, version=None):
"""Search NVD for CVEs affecting specific product"""
# Build search query
keyword = f"{vendor} {product}"

if version:
keyword += f" {version}"
params = {
'keywordSearch': keyword,
'resultsPerPage': 100
}
headers = {}
if self.nvd_api_key:
headers['apiKey'] = self.nvd_api_key
try:
response = requests.get(self.nvd_url, params=params, headers=headers)
if response.status_code == 200:
data = response.json()
cves = []
for item in data.get('vulnerabilities', []):
cve = item.get('cve', {})
cve_id = cve.get('id')
# Extract CVSS score
cvss_data = cve.get('metrics', {}).get('cvssMetricV31', [])
cvss_score = 0.0
if cvss_data:
cvss_score = cvss_data[0].get('cvssData', {}).get('baseScore', 0.0)
# Extract description
descriptions = cve.get('descriptions', [])
description = descriptions[0].get('value', '') if descriptions else ''
cves.append({
'cve_id': cve_id,
'cvss_score': cvss_score,
'description': description,
'published': cve.get('published')
})
return cves
else:
print(f"[!] NVD API error: {response.status_code}")
return []
except Exception as e:
print(f"[!] Error searching CVEs: {e}")
return []

def correlate_asset_inventory(self, db_path='ot_assets.db'):
"""Correlate all assets in database with CVEs"""
import sqlite3
conn = sqlite3.connect(db_path)
cursor = conn.cursor()
# Get all assets
cursor.execute('SELECT id, ip_address, vendor, model, firmware_version FROM
assets')
assets = cursor.fetchall()
db = AssetDatabase(db_path)
for asset in assets:
asset_id, ip, vendor, model, firmware = asset
if not vendor or not model:
continue
print(f"\n[*] Checking CVEs for {ip} ({vendor} {model})")
# Search CVEs
cves = self.search_cves(vendor, model, firmware)
print(f"[+] Found {len(cves)} potential CVEs")
# Add high-severity CVEs to database
for cve in cves:
if cve['cvss_score'] >= 4.0: # Medium or higher
db.add_vulnerability(ip, cve)
# Rate limit (NVD allows 5 requests/30 seconds without API key)
time.sleep(6)
conn.close()
print("\n[+] CVE correlation complete")
# Usage
if __name__ == '__main__':
correlator = CVECorrelation(nvd_api_key='YOUR_API_KEY') # Get free key from
nvd.nist.gov
correlator.correlate_asset_inventory()

4.2 Risk Prioritization Matrix
# vulnerability_prioritization.py

# Prioritize vulnerabilities by operational risk
class VulnerabilityPrioritization:
def __init__(self, db_path='ot_assets.db'):
self.db_path = db_path
def calculate_risk_score(self, cvss, criticality, exploitability, purdue_level):
"""
Calculate operational risk score
Risk = (CVSS * 0.3) + (Criticality * 0.3) + (Exploitability * 0.2) + (Purdue Impact * 0.2)
Scale: 0-10 (10 = highest risk)
"""
# Map criticality to numeric
criticality_map = {'Low': 2, 'Medium': 5, 'High': 7, 'Critical': 10}
criticality_score = criticality_map.get(criticality, 5)
# Map exploitability
exploit_map = {'Not Defined': 5, 'Unproven': 3, 'Proof of Concept': 6, 'Functional': 8,
'High': 10}
exploit_score = exploit_map.get(exploitability, 5)
# Purdue level impact (Level 0-1 = highest impact)
purdue_impact = {0: 10, 1: 9, 2: 8, 3: 6, 4: 4, 5: 2}.get(purdue_level, 5)
# Calculate weighted risk
risk = (cvss * 0.3) + (criticality_score * 0.3) + (exploit_score * 0.2) + (purdue_impact *
0.2)
return round(risk, 2)
def prioritize_vulnerabilities(self):
"""Generate prioritized vulnerability report"""
import sqlite3
conn = sqlite3.connect(self.db_path)
cursor = conn.cursor()
cursor.execute('''
SELECT
a.ip_address,
a.device_type,
a.vendor,
a.model,
a.criticality,
a.purdue_level,

v.cve_id,
v.cvss_score,
v.description
FROM assets a
JOIN vulnerabilities v ON a.id = v.asset_id
WHERE v.status = 'Open'
''')
vulnerabilities = []
for row in cursor.fetchall():
ip, device_type, vendor, model, criticality, purdue, cve, cvss, desc = row
# Calculate risk score
risk_score = self.calculate_risk_score(
cvss,
criticality,
'Functional', # Assume functional exploit for OT CVEs
purdue
)
vulnerabilities.append({
'ip': ip,
'device': f"{vendor} {model}",
'cve': cve,
'cvss': cvss,
'risk_score': risk_score,
'purdue_level': purdue,
'criticality': criticality,
'description': desc[:100] + '...'
})
# Sort by risk score (descending)
vulnerabilities.sort(key=lambda x: x['risk_score'], reverse=True)
conn.close()
return vulnerabilities
def generate_report(self, output_file='vulnerability_report.txt'):
"""Generate human-readable vulnerability report"""
vulns = self.prioritize_vulnerabilities()
with open(output_file, 'w') as f:
f.write("="*80 + "\n")
f.write("OT VULNERABILITY PRIORITIZATION REPORT\n")
f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
f.write("="*80 + "\n\n")

f.write(f"Total Vulnerabilities: {len(vulns)}\n\n")
# Group by risk level
critical_risk = [v for v in vulns if v['risk_score'] >= 8.0]
high_risk = [v for v in vulns if 6.0 <= v['risk_score'] < 8.0]
medium_risk = [v for v in vulns if 4.0 <= v['risk_score'] < 6.0]
f.write(f"CRITICAL RISK (Score >= 8.0): {len(critical_risk)}\n")
f.write(f"HIGH RISK (Score 6.0-7.9): {len(high_risk)}\n")
f.write(f"MEDIUM RISK (Score 4.0-5.9): {len(medium_risk)}\n\n")
f.write("="*80 + "\n")
f.write("TOP 10 HIGHEST RISK VULNERABILITIES\n")
f.write("="*80 + "\n\n")
for i, vuln in enumerate(vulns[:10], 1):
f.write(f"{i}. {vuln['cve']} - Risk Score: {vuln['risk_score']}\n")
f.write(f" Asset: {vuln['ip']} ({vuln['device']})\n")
f.write(f" CVSS: {vuln['cvss']} | Purdue Level: {vuln['purdue_level']} | Criticality:
{vuln['criticality']}\n")
f.write(f" {vuln['description']}\n\n")
print(f"[+] Vulnerability report generated: {output_file}")
# Print summary
print(f"\n[*] Vulnerability Summary:")
print(f" CRITICAL: {len(critical_risk)}")
print(f" HIGH: {len(high_risk)}")
print(f" MEDIUM: {len(medium_risk)}")
# Usage
if __name__ == '__main__':
prioritizer = VulnerabilityPrioritization()
prioritizer.generate_report()

5. Patch Management for OT
5.1 Challenges
Unlike IT environments where patches can be deployed automatically, OT patch
management faces:
1.​ Downtime Requirements: PLCs cannot be patched while controlling processes
2.​ Testing Requirements: Patches must be validated in lab before production
3.​ Vendor Dependencies: Many vendors release patches slowly (or never for legacy
systems)
4.​ Change Control: All changes require engineering review and management approval

5.​ Legacy Systems: 20+ year old PLCs with no available patches

5.2 OT Patch Management Process
# patch_management_workflow.py
# Track patch deployment for OT environment
import sqlite3
from datetime import datetime
class PatchManagement:
def __init__(self, db_path='ot_patches.db'):
self.db_path = db_path
self.init_database()
def init_database(self):
conn = sqlite3.connect(self.db_path)
cursor = conn.cursor()
cursor.execute('''
CREATE TABLE IF NOT EXISTS patches (
id INTEGER PRIMARY KEY AUTOINCREMENT,
vendor TEXT,
product TEXT,
patch_version TEXT,
cves_addressed TEXT,
release_date TEXT,
severity TEXT,
status TEXT,
lab_tested BOOLEAN,
lab_test_date TEXT,
production_deployed BOOLEAN,
deployment_date TEXT,
affected_assets TEXT,
notes TEXT
)
''')
conn.commit()
conn.close()
def add_patch(self, patch_data):
"""Add new patch to tracking system"""
conn = sqlite3.connect(self.db_path)
cursor = conn.cursor()
cursor.execute('''
INSERT INTO patches (

vendor, product, patch_version, cves_addressed,
release_date, severity, status, lab_tested,
production_deployed, affected_assets
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
''', (
patch_data['vendor'],
patch_data['product'],
patch_data['patch_version'],
','.join(patch_data.get('cves', [])),
patch_data['release_date'],
patch_data.get('severity', 'Medium'),
'Pending Review',
False,
False,
','.join(patch_data.get('affected_assets', []))
))
conn.commit()
conn.close()
print(f"[+] Added patch: {patch_data['vendor']} {patch_data['product']}
{patch_data['patch_version']}")
def update_lab_test(self, patch_id, success, notes):
"""Update lab test results"""
conn = sqlite3.connect(self.db_path)
cursor = conn.cursor()
status = 'Lab Approved' if success else 'Lab Failed'
cursor.execute('''
UPDATE patches
SET lab_tested = ?, lab_test_date = ?, status = ?, notes = ?
WHERE id = ?
''', (True, datetime.now().isoformat(), status, notes, patch_id))
conn.commit()
conn.close()
print(f"[+] Updated lab test for patch ID {patch_id}: {status}")
def schedule_deployment(self, patch_id, maintenance_window):
"""Schedule patch deployment"""
conn = sqlite3.connect(self.db_path)
cursor = conn.cursor()
cursor.execute('''
UPDATE patches

SET status = 'Scheduled for Deployment'
WHERE id = ?
''', (patch_id,))
conn.commit()
conn.close()
print(f"[+] Patch ID {patch_id} scheduled for deployment: {maintenance_window}")
def mark_deployed(self, patch_id):
"""Mark patch as deployed to production"""
conn = sqlite3.connect(self.db_path)
cursor = conn.cursor()
cursor.execute('''
UPDATE patches
SET production_deployed = ?, deployment_date = ?, status = 'Deployed'
WHERE id = ?
''', (True, datetime.now().isoformat(), patch_id))
conn.commit()
conn.close()
print(f"[+] Patch ID {patch_id} marked as deployed")
def get_pending_patches(self):
"""Get patches pending review or deployment"""
conn = sqlite3.connect(self.db_path)
cursor = conn.cursor()
cursor.execute('''
SELECT id, vendor, product, patch_version, cves_addressed, severity, status
FROM patches
WHERE production_deployed = 0
ORDER BY severity DESC, release_date ASC
''')
patches = cursor.fetchall()
conn.close()
return patches
# Usage
if __name__ == '__main__':
pm = PatchManagement()
# Add new patch
pm.add_patch({

'vendor': 'Siemens',
'product': 'S7-1200 CPU',
'patch_version': 'V4.6.0',
'cves': ['CVE-2022-38465', 'CVE-2022-38466'],
'release_date': '2023-11-15',
'severity': 'Critical',
'affected_assets': ['10.20.10.10', '10.20.10.11', '10.20.10.12']
})
# Lab test
pm.update_lab_test(1, success=True, notes='Tested in lab, no issues with process
control')
# Schedule deployment
pm.schedule_deployment(1, '2025-01-15 02:00-06:00')
# Mark deployed
pm.mark_deployed(1)

6. Hands-On Lab
Objective
Build complete asset inventory for water treatment facility, correlate with CVEs, prioritize
vulnerabilities.

Lab Steps
Step 1: Deploy Passive Discovery
# Capture 48 hours of traffic
sudo tcpdump -i eth1 -w ot_baseline.pcap -G 172800 -W 1
# Analyze with Zeek
zeek -r ot_baseline.pcap \
local.zeek \
icsnpp/modbus \
icsnpp/s7comm \
icsnpp/dnp3
# Run passive discovery script
python3 passive_asset_discovery.py
Step 2: Safe Active Scanning
# Run safe OT scan
bash safe_ot_scan.sh

# Review results
cat ot_port_scan.txt
Step 3: Build Asset Database
# Import discovered assets
python3 asset_database.py
Step 4: CVE Correlation
# Correlate with CVE database
python3 cve_correlation.py
Step 5: Prioritize Vulnerabilities
# Generate prioritized report
python3 vulnerability_prioritization.py

Deliverables
1.​ Complete asset inventory (CSV export)
2.​ Network topology diagram
3.​ CVE correlation report
4.​ Prioritized vulnerability remediation plan
5.​ Patch deployment schedule

7. Tools and Resources
Asset Discovery
●​
●​
●​
●​

GRASSMARLIN: https://github.com/nsacyber/GRASSMARLIN
Nozomi Networks: Commercial passive discovery
Claroty: Commercial asset management
Armis: Agentless device discovery

Vulnerability Scanning
●​ Tenable OT Security: OT-safe vulnerability scanner
●​ Nessus: With OT scan policies
●​ Rapid7 Nexpose: ICS modules

CVE Databases
●​
●​
●​
●​

NVD: https://nvd.nist.gov
ICS-CERT Advisories: https://www.cisa.gov/ics-advisories
Siemens ProductCERT: https://cert-portal.siemens.com
Schneider Electric: https://www.se.com/ww/en/work/support/cybersecurity/

Conclusion
OT asset management requires:
●​
●​
●​
●​
●​

Passive discovery first to avoid disrupting operations
Conservative active scanning with proper testing and approval
Continuous monitoring to detect rogue devices
Vulnerability correlation with operational risk prioritization
Methodical patch management with lab testing

