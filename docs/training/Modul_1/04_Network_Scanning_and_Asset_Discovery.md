Lesson 04: Network Scanning & Asset
Discovery

Lesson 04: Network Scanning & Asset
Discovery in ICS/SCADA/OT
Environments
Learning Objectives
●​
●​
●​
●​
●​

Perform safe active reconnaissance in OT networks
Utilize passive network monitoring for asset discovery
Master specialized ICS scanning tools (nmap NSE, plcscan, ISF)
Conduct OSINT for critical infrastructure intelligence
Build comprehensive asset inventories without disrupting operations

1. Challenges of OT Network Scanning
1.1 Differences from IT Scanning
Critical Considerations:
Aspect

IT Networks

OT Networks

Device Stability

Tolerates aggressive scans

Crashes from unexpected packets

Bandwidth

High (1-100 Gbps)

Low (10-100 Mbps, serial links)

Scan Impact

Minimal

Can trigger safety shutdowns

Device Types

Servers, workstations

PLCs, RTUs, IEDs, sensors

Response Time

Milliseconds acceptable

Real-time determinism required

Security Tools

Widely deployed

Often absent or disabled

1.2 Safe Scanning Principles
1. Passive Before Active: Always start with passive monitoring 2. Progressive Intensity:
Gradually increase scan aggressiveness 3. Timing/Rate Limiting: Use slow scan rates
(--min-rate, --max-rate) 4. Protocol-Aware Scanning: Use ICS-specific tools 5. Test
Environment First: Validate techniques in lab 6. Coordinate with OT Team: Obtain
authorization and outage windows 7. Have Rollback Plan: Know how to recover devices if
issues occur

1.3 Risk Mitigation Strategies
Pre-Scan Checklist:
●​
●​ Test scan techniques in lab environment
DoS-Prone Devices (scan with extreme caution):
●​
●​
●​
●​
●​

ABB RTU560 series (firmware < 1.2.0)
Schneider Quantum PLCs with Modbus/TCP
Legacy GE Fanuc VersaMax
Siemens S7-300/400 with heavy network load
Older Rockwell CompactLogix (firmware < v20)

2. Passive Asset Discovery
2.1 Passive Network Monitoring Techniques
Advantages:
●​
●​
●​
●​

Zero risk: No packets sent to devices
Comprehensive: Captures all active communications
Behavioral analysis: Identifies communication patterns
Anomaly detection: Baselines normal operations

Deployment Methods:
1.​ SPAN/Mirror Port: Switch port mirroring
2.​ Network TAP: Physical tap device (non-intrusive)
3.​ Inline Sensor: IDS/IPS deployment (risky in OT)

2.2 GRASSMARLIN - Passive ICS Mapper
Background:
●​
●​
●​
●​

Developed by NSACYBER
Passive network mapping for ICS/SCADA
Identifies devices, protocols, and communication patterns
Visualizes network topology

Installation:
# Download from https://github.com/nsacyber/GRASSMARLIN
wget
https://github.com/nsacyber/GRASSMARLIN/releases/latest/download/GRASSMARLIN.jar
# Run

java -jar GRASSMARLIN.jar
PCAP Analysis Workflow:
1.​ Import PCAP: File → Import → PCAP
2.​ Automatic Device Fingerprinting: Analyzes protocols, MAC OUIs, traffic patterns
3.​ Logical Network Map: Visualizes devices and connections
4.​ Protocol Distribution: Identifies ICS protocols in use
5.​ Export Results: CSV/XML for inventory management
Command-Line Mode (for automation):
java -jar GRASSMARLIN.jar --import traffic.pcap --export devices.csv
Device Fingerprinting Logic:
●​
●​
●​
●​

MAC OUI: Vendor identification (Siemens, Rockwell, Schneider)
Protocol Signatures: Modbus, DNP3, S7comm, Ethernet/IP
Traffic Patterns: Polling intervals, master-slave relationships
Port Numbers: Standard ICS ports (102, 502, 20000, 44818)

2.3 Wireshark for OT Asset Discovery
Identify Devices from PCAP:
# Extract unique IPs communicating on ICS ports
tshark -r capture.pcap -Y "tcp.port == 502 || tcp.port == 102 || tcp.port == 44818 || tcp.port ==
20000" \
-T fields -e ip.src -e ip.dst | sort -u
# Count protocol distribution
tshark -r capture.pcap -q -z io,phs
Wireshark Statistics:
●​ Statistics → Protocol Hierarchy: Identify ICS protocols
●​ Statistics → Conversations: Map device communication pairs
●​ Statistics → Endpoints: List all IPs with traffic volume
Extract Modbus Device IDs:
tshark -r capture.pcap -Y "modbus" -T fields -e ip.src -e modbus.unit_id | sort -u
Extract S7comm Device Names:
tshark -r capture.pcap -Y "s7comm.param.func == 0xf0" -T fields -e s7comm.data.pdu_szl_id

2.4 Zeek (Bro) for ICS Monitoring
Zeek ICS Protocol Analyzers:

●​ Modbus: modbus.log
●​ DNP3: dnp3.log
●​ Ethernet/IP: enip.log (via plugin)
●​ S7comm: Via custom parser
Installation with ICS Plugins:
# Install Zeek
sudo apt install zeek
# Install ICSNPP (ICS Network Protocol Parsers)
git clone https://github.com/cisagov/icsnpp-modbus
git clone https://github.com/cisagov/icsnpp-dnp3
git clone https://github.com/cisagov/icsnpp-enip
cd icsnpp-modbus && zkg install .
cd ../icsnpp-dnp3 && zkg install .
cd ../icsnpp-enip && zkg install .
Analyze PCAP with Zeek:
zeek -r capture.pcap /opt/zeek/share/zeek/policy/protocols/modbus
# Output files:
# - modbus.log: Modbus transactions
# - conn.log: All connections
# - weird.log: Protocol anomalies
Extract Modbus Asset List:
cat modbus.log | zeek-cut id.orig_h id.resp_h unit_id func | sort -u
Custom Zeek Script for Asset Inventory:
# asset_inventory.zeek
@load base/frameworks/notice
module AssetInventory;
export {
redef enum Notice::Type += {
NewICSDevice
};
global ics_devices: set[addr];
}
event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool) {
if (c$id$resp_h !in ics_devices) {

add ics_devices[c$id$resp_h];
NOTICE([$note=NewICSDevice,
$msg=fmt("New Modbus device discovered: %s", c$id$resp_h),
$conn=c]);
}
}
event zeek_done() {
print "ICS Devices Discovered:", ics_devices;
}
Run: zeek -r capture.pcap asset_inventory.zeek

2.5 NetworkMiner for ICS Forensics
Features:
●​
●​
●​
●​

Extract files from PCAP
Identify operating systems
Extract credentials (including ICS HMI logins)
Host details and geolocation

ICS-Specific Usage:
# Run NetworkMiner on Windows or with Wine on Linux
wine NetworkMiner.exe
# Load PCAP: File → Open → capture.pcap
# Navigate to:
# - Hosts tab: Device OS fingerprinting
# - Files tab: Extracted engineering files (.s7p, .ACD, etc.)
# - Credentials tab: Plaintext ICS passwords
# - Parameters tab: Protocol-specific data

3. Active Scanning with Nmap
3.1 Safe Nmap Scanning Techniques
Conservative Scan (recommended starting point):
nmap -Pn -sT -p 102,502,1089,1091,2222,4840,20000,44818,47808 \
--max-retries 1 --max-rtt-timeout 500ms --scan-delay 100ms \
--min-rate 10 --max-rate 50 \
192.168.1.0/24 -oA ics_scan_conservative
Parameters Explained:
●​ -Pn: Skip ping (ICS devices often don't respond to ping)

●​ -sT: TCP connect scan (safest, completes handshake)
●​ -p <ports>: Target only ICS ports
●​ --max-retries 1: Reduce probe count
●​ --max-rtt-timeout 500ms: Faster timeout
●​ --scan-delay 100ms: 100ms between probes
●​ --min-rate 10 --max-rate 50: Rate limiting (packets/sec)
●​ -oA <basename>: Output all formats (xml, nmap, gnmap)
Aggressive Scan (only in lab or with approval):
nmap -Pn -sS -sV -O --script=banner,ics-detect \
-p 102,502,1089,1091,2222,4840,20000,44818,47808,9600 \
--version-intensity 0 --max-retries 2 \
192.168.1.0/24 -oA ics_scan_aggressive

3.2 Nmap NSE Scripts for ICS
ICS-Specific NSE Scripts:
# List available ICS scripts
ls /usr/share/nmap/scripts/ | grep -E
"modbus|s7|enip|dnp3|opcua|bacnet|codesys|omron|pcworx"
# Common scripts:
# - modbus-discover.nse
# - s7-info.nse
# - enip-info.nse
# - dnp3-info.nse
# - opcua-info.nse
# - bacnet-info.nse
# - codesys-v2-discover.nse
# - omron-info.nse
# - pcworx-info.nse
Modbus Discovery:
nmap -Pn -sT -p 502 --script modbus-discover.nse 192.168.1.100
# Output:
# 502/tcp open modbus
# | modbus-discover:
# | Slave ID: 1
# | Slave ID data: \x01\x03\x00\x00\x00\x01
# |_ Holding Registers (0-9): 100, 200, 0, 0, 50, ...
S7 PLC Enumeration:
nmap -Pn -sT -p 102 --script s7-info.nse 192.168.1.100

# Output:
# 102/tcp open iso-tsap
# | s7-info:
# | Module: 6ES7 315-2AH14-0AB0
# | Basic Hardware: 6ES7 315-2AH14-0AB0
# | Version: 2.6.9
# | System Name: SIMATIC 300(1)
# | Copyright: Original Siemens Equipment
# | Serial Number: S C-X4U421302009
# |_ Plant Identification: Not Set
Ethernet/IP Enumeration:
nmap -Pn -sU -p 44818 --script enip-info.nse 192.168.1.100
# Output:
# 44818/udp open EtherNet/IP
# | enip-info:
# | Vendor: Rockwell Automation (0x01)
# | Product Name: 1766-L32BXB/A
# | Serial Number: 60A1B2C3
# | Product Code: 0x001F (CompactLogix Controller)
# | Revision: 20.11
# |_ Device IP: 192.168.1.100
DNP3 Reconnaissance:
nmap -Pn -sT -p 20000 --script dnp3-info.nse 192.168.1.100
OPC UA Discovery:
nmap -Pn -sT -p 4840 --script opcua-info.nse 192.168.1.100
# Output:
# 4840/tcp open OPC UA
# | opcua-info:
# | Server URI: urn:DESKTOP-12345:UnifiedAutomation:UaExpert
# | Product Name: UaExpert
# | Manufacturer: Unified Automation
# | Security Policies:
# | - None
# | - Basic256Sha256 (Sign, SignAndEncrypt)
# |_ User Tokens: Anonymous, Username

3.3 Custom Nmap NSE Script for ICS
modbus-enum.nse (extended enumeration):

description = [[
Enumerates Modbus devices and attempts to read holding registers
]]
author = "ICS Security Researcher"
license = "Same as Nmap"
categories = {"discovery", "intrusive"}
portrule = shortport.port_or_service(502, "modbus", "tcp")
action = function(host, port)
local socket = nmap.new_socket()
local status, err = socket:connect(host, port)
if not status then
return "Connection failed: " .. err
end
local output = {}
-- Try unit IDs 1-10
for unit_id = 1, 10 do
-- Modbus Read Holding Registers (FC 03)
local trans_id = string.pack(">I2", unit_id)
local proto_id = "\x00\x00"
local length = "\x00\x06"
local func_code = "\x03"
local start_addr = "\x00\x00"
local count = "\x00\x0A"
local request = trans_id .. proto_id .. length .. string.char(unit_id) .. func_code ..
start_addr .. count
status, err = socket:send(request)
if not status then break end
status, response = socket:receive()
if status and #response > 9 then
local resp_func = string.byte(response, 8)
if resp_func == 0x03 then
table.insert(output, string.format("Unit ID %d: ACTIVE", unit_id))
end
end
end
socket:close()
if #output > 0 then

return stdnse.format_output(true, output)
else
return "No Modbus slaves responded"
end
end
Usage:
nmap -Pn -sT -p 502 --script modbus-enum.nse 192.168.1.100

3.4 UDP Scanning for BACnet/ENIP
BACnet Discovery (UDP 47808):
nmap -Pn -sU -p 47808 --script bacnet-info.nse 192.168.1.0/24
# BACnet uses broadcast Who-Is messages
# More effective with specialized tools like bacnet-stack
Ethernet/IP Broadcast Discovery:
# Use specialized tool for EtherNet/IP List Identity broadcast
git clone https://github.com/ottowayi/pycomm3
python3 -c "from pycomm3 import CIPDriver; print(CIPDriver.discover())"

4. Specialized ICS Scanning Tools
4.1 plcscan - PLC Discovery Tool
Installation:
git clone https://github.com/yanlinlin82/plcscan
cd plcscan
gcc -o plcscan plcscan.c -lpthread
sudo mv plcscan /usr/local/bin/
Usage:
# Scan for Siemens S7 PLCs
sudo plcscan -t siemens 192.168.1.0/24
# Scan for Modbus devices
sudo plcscan -t modbus 192.168.1.0/24
# Scan for all supported types
sudo plcscan 192.168.1.0/24
# Supported types: siemens, modbus, omron, ge_fanuc

Output Example:
[+] Scanning 192.168.1.0/24 for Siemens PLCs...
[+] 192.168.1.10 - Siemens S7-300 CPU 315-2 DP (Version 3.3.5)
[+] 192.168.1.20 - Siemens S7-1200 CPU 1214C (Version 4.2.1)

4.2 ISF (Industrial Exploitation Framework)
Installation:
git clone https://github.com/dark-lbp/isf
cd isf
pip3 install -r requirements.txt
python3 isf.py
ISF Console:
isf > show scanners
ICS Scanners:
------------scanners/s7comm_scanner
- Siemens S7 PLC scanner
scanners/modbus_scanner
- Modbus device scanner
scanners/enip_scanner
- Ethernet/IP scanner
scanners/vxworks_scanner
- VxWorks device scanner
scanners/bacnet_scanner
- BACnet scanner
isf > use scanners/s7comm_scanner
isf (S7comm Scanner) > set target 192.168.1.0/24
isf (S7comm Scanner) > run
[+] 192.168.1.10
Module: 6ES7 315-2AH14-0AB0
Version: 2.6.9
System Name: SIMATIC 300(1)
Modbus Scanner Module:
isf > use scanners/modbus_scanner
isf (Modbus Scanner) > set target 192.168.1.0/24
isf (Modbus Scanner) > set port 502
isf (Modbus Scanner) > set unit_id 1
isf (Modbus Scanner) > run

4.3 Redpoint - ICS Enumeration Tool
Download:
# Commercial tool by Digital Bond (now archived)

# Open-source alternatives: ISF, plcscan
Functionality:
●​ Identifies PLCs, RTUs, IEDs
●​ Uses legitimate protocol commands (non-intrusive)
●​ Supports: Modbus, DNP3, BACnet, Ethernet/IP, S7

4.4 SCADA Shutdown Tool (Research Only)
WARNING: For authorized testing only
#!/usr/bin/env python3
"""
Multi-protocol ICS device enumeration and testing
WARNING: Can disrupt operations - use only in authorized testing
"""
import socket
import struct
import sys
def test_modbus(ip, port=502):
"""Test Modbus connectivity"""
try:
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(2)
sock.connect((ip, port))
# Read Device Identification (FC 0x2B/0x0E)
trans_id = b'\x00\x01'
proto_id = b'\x00\x00'
length = b'\x00\x05'
unit_id = b'\x01'
func_code = b'\x2B'
mei_type = b'\x0E'
read_device_id = b'\x01\x00'
request = trans_id + proto_id + length + unit_id + func_code + mei_type +
read_device_id
sock.send(request)
response = sock.recv(1024)
if len(response) > 9:
print(f"[+] {ip}:502 - Modbus ACTIVE")
return True

except:
pass
finally:
sock.close()
return False
def test_s7(ip, port=102):
"""Test Siemens S7 connectivity"""
try:
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(2)
sock.connect((ip, port))
# COTP Connection Request
cotp_cr = bytes.fromhex('0300001611e0000000010000c00100c10200c20200')
sock.send(cotp_cr)
response = sock.recv(1024)
if len(response) > 0 and response[5:6] == b'\xd0':
print(f"[+] {ip}:102 - Siemens S7 ACTIVE")
return True
except:
pass
finally:
sock.close()
return False
def test_enip(ip, port=44818):
"""Test Ethernet/IP connectivity"""
try:
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(2)
sock.connect((ip, port))
# ListIdentity command
command = struct.pack('<H', 0x0063)
length = struct.pack('<H', 0)
session = b'\x00' * 4
status = b'\x00' * 4
context = b'\x00' * 8
options = b'\x00' * 4
request = command + length + session + status + context + options
sock.send(request)

response = sock.recv(1024)
if len(response) > 24:
print(f"[+] {ip}:44818 - Ethernet/IP ACTIVE")
return True
except:
pass
finally:
sock.close()
return False
def scan_network(network):
"""Scan network for ICS devices"""
import ipaddress
net = ipaddress.IPv4Network(network, strict=False)
for ip in net.hosts():
ip_str = str(ip)
test_modbus(ip_str)
test_s7(ip_str)
test_enip(ip_str)
if __name__ == "__main__":
if len(sys.argv) < 2:
print(f"Usage: {sys.argv[0]} <network_cidr>")
sys.exit(1)
scan_network(sys.argv[1])

5. OSINT for Critical Infrastructure
5.1 Shodan for ICS/SCADA
Shodan Search Queries:
# Modbus devices
port:502
# Siemens S7 PLCs
port:102
# Ethernet/IP (Rockwell)
port:44818

# BACnet (Building Automation)
port:47808
# DNP3 (SCADA)
port:20000
# OPC UA
port:4840
# Niagara Fox (Building Automation)
port:1911 product:"Niagara"
# SCADA HMI
"SCADA" country:US
# Specific vendors
org:"Siemens" port:102
org:"Schneider Electric" port:502
org:"Rockwell Automation"
# Combined queries
port:502 country:US city:"New York"
Shodan CLI:
# Install
pip install shodan
# Initialize
shodan init <API_KEY>
# Search
shodan search "port:502"
shodan search "Siemens S7"
# Download results
shodan download modbus_devices.json.gz "port:502"
shodan parse modbus_devices.json.gz --fields ip_str,port,org,country

5.2 Censys for OT Devices
Censys Queries:
# Modbus
services.port: 502
# S7comm
services.port: 102

# ICS protocols
protocols: ("modbus" OR "s7comm" OR "dnp3")
# Combine with organization
services.port: 502 AND autonomous_system.name: "Electric Company"

5.3 FOFA (China-based search engine)
FOFA Queries:
port="502"
port="102"
protocol="modbus"
protocol="s7comm"

5.4 Google Dorking for ICS Web Interfaces
Google Dork Queries:
# SCADA HMI web interfaces
inurl:scada
inurl:hmi
intitle:"SCADA Login"
intitle:"Wonderware InTouch"
intitle:"WinCC"
# Engineering portals
intitle:"TIA Portal"
inurl:"/portal/login"
# Historians
intitle:"PI Vision"
intitle:"OSIsoft"
# Building automation
intitle:"Niagara" inurl:"/config"
intitle:"BACnet" inurl:"/admin"
# IP cameras (often on OT networks)
inurl:/view/index.shtml
intitle:"Network Camera"
# Manufacturer defaults
intitle:"admin" inurl:login.asp "Siemens"

5.5 Certificate Transparency Logs

crt.sh for ICS Certificate Discovery:
# Search for OPC UA certificates
curl "https://crt.sh/?q=%opcua%&output=json" | jq .
# Search by organization
curl "https://crt.sh/?q=%Electric%Company%&output=json" | jq .
# Identify subdomains
curl "https://crt.sh/?q=%.company.com&output=json" | jq '.[].name_value' | sort -u

5.6 GitHub/GitLab Code Search
Search for exposed credentials/configs:
# HMI configuration files
extension:scada
extension:db1
extension:s7p
# Credentials in scripts
"modbus" AND "password" filename:.py
"s7comm" AND "192.168" filename:.py
# Network diagrams
"PLC" filetype:vsd
"SCADA" filetype:pdf
# Use github-search or grep.app

6. Building Asset Inventory
6.1 Asset Inventory Schema
Recommended Fields:
{
"ip_address": "192.168.1.10",
"mac_address": "00:1B:1B:1E:45:89",
"hostname": "PLC-REACTOR-01",
"device_type": "PLC",
"vendor": "Siemens",
"model": "S7-315-2PN/DP",
"firmware_version": "3.3.5",
"serial_number": "S C-X4U421302009",
"protocols": ["S7comm", "Profinet"],
"open_ports": [80, 102, 161],

"purdue_level": "Level 1",
"criticality": "High",
"location": "Building A, Reactor Control Room",
"function": "Reactor temperature control",
"last_scanned": "2024-01-15T10:30:00Z",
"notes": "Primary controller for reactor 1"
}

6.2 Automated Inventory Script
#!/usr/bin/env python3
import json
import subprocess
import xmltodict
def nmap_scan_to_inventory(target_network):
"""
Run Nmap scan and parse to asset inventory
"""
# Run Nmap with XML output
cmd = [
"nmap", "-Pn", "-sT", "-sV",
"-p", "80,102,502,2222,4840,20000,44818,47808",
"--script", "banner,ics-detect",
"-oX", "scan_output.xml",
target_network
]
subprocess.run(cmd)
# Parse XML output
with open("scan_output.xml") as f:
data = xmltodict.parse(f.read())
inventory = []
hosts = data['nmaprun'].get('host', [])
if not isinstance(hosts, list):
hosts = [hosts]
for host in hosts:
if host.get('status', {}).get('@state') != 'up':
continue
asset = {
"ip_address": host.get('address', {}).get('@addr'),
"mac_address": None,
"open_ports": [],

"protocols": [],
"device_info": {}
}
# Extract MAC if available
addresses = host.get('address', [])
if not isinstance(addresses, list):
addresses = [addresses]
for addr in addresses:
if addr.get('@addrtype') == 'mac':
asset['mac_address'] = addr.get('@addr')
asset['vendor'] = addr.get('@vendor')
# Extract ports
ports = host.get('ports', {}).get('port', [])
if not isinstance(ports, list):
ports = [ports]
for port in ports:
if port.get('state', {}).get('@state') == 'open':
port_num = port.get('@portid')
asset['open_ports'].append(int(port_num))
# Identify protocol
if port_num == '502':
asset['protocols'].append('Modbus')
elif port_num == '102':
asset['protocols'].append('S7comm')
elif port_num == '44818':
asset['protocols'].append('Ethernet/IP')
elif port_num == '20000':
asset['protocols'].append('DNP3')
elif port_num == '4840':
asset['protocols'].append('OPC UA')
inventory.append(asset)
# Save inventory
with open("asset_inventory.json", "w") as f:
json.dump(inventory, f, indent=2)
print(f"[+] Inventory saved: {len(inventory)} devices")
return inventory
# Usage
nmap_scan_to_inventory("192.168.1.0/24")

7. Hands-On Lab Exercises
Lab 1: Passive Asset Discovery
1.​ Download ICS traffic PCAP from https://github.com/automayt/ICS-pcap
2.​ Analyze with GRASSMARLIN
3.​ Extract asset list with IP, vendor, protocol, communication patterns
4.​ Generate network topology diagram

Lab 2: Safe Active Scanning
1.​ Deploy OpenPLC + ScadaBR lab environment
2.​ Perform conservative Nmap scan
3.​ Use NSE scripts (modbus-discover, s7-info if applicable)
4.​ Compare active scan results with passive findings
5.​ Document any devices that didn't respond as expected

Lab 3: ISF Framework Enumeration
1.​ Install ISF framework
2.​ Use s7comm_scanner on Snap7 server
3.​ Use modbus_scanner on OpenPLC
4.​ Document enumerated device details
5.​ Attempt authenticated operations (read-only)

Lab 4: OSINT for ICS
1.​ Search Shodan for Modbus devices in specific country/city
2.​ Identify exposed HMI web interfaces via Google dorks
3.​ Search GitHub for HMI configuration files (use test data)
4.​ Build OSINT report on a fictional industrial facility

8. Tools & Resources
Passive Tools
●​ GRASSMARLIN: https://github.com/nsacyber/GRASSMARLIN
●​ Zeek + ICSNPP: https://github.com/cisagov/icsnpp
●​ NetworkMiner: https://www.netresec.com/?page=NetworkMiner

Active Scanners
●​ Nmap + NSE: https://nmap.org/
●​ plcscan: https://github.com/meeas/plcscan
●​ ISF: https://github.com/dark-lbp/isf

OSINT Platforms
●​
●​
●​
●​

Shodan: https://www.shodan.io/
Censys: https://search.censys.io/
FOFA: https://fofa.info/
ZoomEye: https://www.zoomeye.org/

Documentation
●​ ICS-CERT Advisories: https://www.cisa.gov/ics-advisories
●​ Purdue Model: ISA-95/IEC 62264

9. Knowledge Check
1.​ Why is passive reconnaissance preferred over active scanning in OT networks?
2.​ What Nmap parameters reduce scan aggressiveness for ICS devices?
3.​ How does GRASSMARLIN fingerprint ICS devices without active probing?
4.​ What are the default ports for Modbus, S7comm, Ethernet/IP, and DNP3?
5.​ What information can you extract from Shodan about exposed ICS devices?
6.​ How would you safely enumerate Modbus unit IDs on a device?
7.​ What are the risks of UDP scanning in OT environments?
8.​ Describe the process of building an asset inventory from Nmap XML output.
9.​ What OSINT techniques can reveal ICS infrastructure without network scanning?
10.​How do you identify ICS protocols in a network capture using Wireshark?
Obtain written authorization from asset owner
Document all IP ranges and device types
Identify critical devices that should NOT be scanned
Schedule during maintenance windows if possible
Have OT engineer on standby
Prepare incident response plan
Backup device configurations before scanning

