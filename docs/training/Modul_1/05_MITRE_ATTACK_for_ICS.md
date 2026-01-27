Lesson 05: MITRE ATT&CK for ICS
Framework

Lesson 05: MITRE ATT&CK for ICS
Framework
Learning Objectives
●​
●​
●​
●​
●​

Master the MITRE ATT&CK for ICS framework structure and taxonomy
Analyze real-world ICS cyber attack campaigns using ATT&CK techniques
Map defensive controls to ICS-specific TTPs
Build threat models for OT environments
Utilize ATT&CK Navigator for ICS threat intelligence

1. MITRE ATT&CK for ICS Overview
1.1 Framework Structure
Official Resource: https://attack.mitre.org/matrices/ics/
Tactics (11 Categories):
1.​ Initial Access: Entry into ICS network
2.​ Execution: Running malicious code
3.​ Persistence: Maintaining foothold
4.​ Privilege Escalation: Gaining higher permissions
5.​ Evasion: Avoiding detection
6.​ Discovery: Gathering information
7.​ Lateral Movement: Pivoting through network
8.​ Collection: Data gathering
9.​ Command and Control: Maintain communications
10.​Inhibit Response Function: Disrupt safety/control
11.​Impair Process Control: Manipulate industrial processes
Key Differences from Enterprise ATT&CK:
●​
●​
●​
●​

Impact-focused: Emphasizes physical consequences
OT-specific techniques: PLC manipulation, safety system attacks
Process knowledge: Requires understanding of industrial processes
Two-phase attacks: IT infiltration → OT impact

1.2 ICS-Specific Tactics
Tactic 10: Inhibit Response Function (unique to ICS):
●​ T0800: Activate Firmware Update Mode

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

T0803: Block Command Message
T0804: Block Reporting Message
T0805: Block Serial COM
T0806: Brute Force I/O
T0809: Data Destruction
T0814: Denial of Service
T0816: Device Restart/Shutdown
T0835: Manipulate I/O Image
T0881: Service Stop
T0892: Change Operating Mode

Tactic 11: Impair Process Control:
●​
●​
●​
●​
●​

T0806: Brute Force I/O
T0836: Modify Parameter
T0839: Module Firmware
T0856: Spoof Reporting Message
T0855: Unauthorized Command Message

2. Real-World Attack Case Studies
2.1 Stuxnet (2010) - ATT&CK Mapping
Target: Iranian nuclear enrichment facility (Natanz)
ATT&CK Technique Mapping:
Tactic

Technique
ID

Technique
Name

Stuxnet Implementation

Initial Access

T0883

Internet
Accessible
Device

USB worm propagation to
air-gapped network

Execution

T0873

Project File
Infection

Infected Step 7 (.s7p) project files

Persistence

T0839

Module Firmware

Rootkit in Siemens S7-300/400 PLC
firmware

Evasion

T0872

Indicator
Removal on Host

Hid infected PLC blocks from Step 7

Discovery

T0877

I/O Image

Read PLC I/O to identify target
centrifuges

Lateral
Movement

T0886

Remote Services

Exploited Windows shares, WinCC
databases

Collection

T0868

Detect Operating
Mode

Monitored PLC mode to activate
payload

C2

T0885

Commonly Used
Port

HTTP to external servers for updates

Inhibit
Response

T0809

Data Destruction

Zero-day exploits exhaustion

Impair Process
Control

T0836

Modify
Parameter

Manipulated centrifuge frequency
(1410 Hz → 1064 Hz → 1410 Hz
cycles)

Impact

T0879

Damage to
Property

Physical destruction of ~1000 IR-1
centrifuges

Technical Breakdown:
Initial Access (T0883):
●​ 4 zero-day Windows exploits (MS10-046, MS10-073, MS10-061, MS10-092)
●​ USB worm (.lnk vulnerability CVE-2010-2568)
●​ Infected Realtek/JMicron driver certificates (stolen)
Persistence (T0839):
●​ PLC firmware rootkit
●​ Replaced OB1 (main cyclic execution block)
●​ Injected custom FB (Function Block) code
Impair Process Control (T0836):
●​ Frequency converter attack:
○​ Normal operation: 1064 Hz
○​ Attack phase 1: Accelerate to 1410 Hz for 15 minutes
○​ Attack phase 2: Decelerate to 2 Hz for 50 minutes
○​ Repeat cycle to cause mechanical stress
●​ Replayed "normal" sensor values to operators (T0856 - Spoof Reporting Message)
Evasion (T0872):

●​ Step 7 rootkit hid malicious blocks
●​ Operators saw clean PLC memory
●​ Modified CP (Communication Processor) to filter requests

2.2 Ukraine Power Grid Attack (2015) - ATT&CK Mapping
Adversary: Sandworm (Russian GRU Unit 74455)
ATT&CK Mapping:
Tactic

Technique

Implementation

Initial Access

T0883

Spear-phishing emails with malicious Excel macros
(BlackEnergy3)

Execution

T0871

Execution through API

Persistence

T0891

Modify Program

Privilege Escalation

T0890

Exploitation for Privilege Escalation

Lateral Movement

T0866

Exploitation of Remote Services

Collection

T0802

Automated Collection

C2

T0885

Commonly Used Port

Inhibit Response

T0816

Device Restart/Shutdown

Inhibit Response

T0804

Block Reporting Message

Impair Process
Control

T0855

Unauthorized Command Message

Impact

T0826

Loss of View

Impact

T0827

Loss of Control

Impact

T0828

Loss of Productivity

Timeline:
1.​ March 2015: Initial spear-phishing
2.​ May-October 2015: Reconnaissance, lateral movement, credential harvesting
3.​ December 23, 2015 15:30: Coordinated attack
○​ 15:30-16:01: Manual breaker operations at 3 distribution companies

○​
○​
○​
○​

Telephone DoS (call flooding) to prevent customer reports
Serial-to-Ethernet converter firmware wipe
UPS sabotage at control centers
KillDisk malware execution

2.3 Triton/Trisis (2017) - ATT&CK Mapping
Target: Schneider Electric Triconex Safety Instrumented System (SIS)
ATT&CK Mapping:
Tactic

Technique

Implementation

Initial Access

T0866

Exploitation of Remote Services

Discovery

T0846

Remote System Discovery

Lateral Movement

T0886

Remote Services

Collection

T0861

Point & Tag Identification

Execution

T0874

Hooking

Persistence

T0839

Module Firmware

Impair Process Control

T0836

Modify Parameter

Inhibit Response

T0800

Activate Firmware Update Mode

Impact

T0880

Loss of Safety

Triton Framework Components:
# Triton framework modules (reconstructed from MITRE/FireEye analysis)
1. TsHi.py - TriStation protocol handler
2. TsLow.py - Low-level communication
3. TsBase.py - Base library
4. TS_cnames.py - Triconex constant definitions
5. inject.bin - Malicious payload for SIS controller
6. imain.bin - Main module to execute on SIS
Attack Sequence:
1.​ Reconnaissance of TriStation protocol
2.​ Development of custom framework
3.​ Injection of malicious logic into SIS
4.​ Failed activation (triggered SIS failure state - detected)

5.​ Forensic investigation revealed attack
Why Triton Was Catastrophic-Intent:
●​
●​
●​
●​

SIS is the "last line of defense" against physical disasters
Disabling SIS allows unsafe process conditions to persist
Could enable explosions, toxic releases, or equipment damage
Demonstrates nation-state capability to cause mass casualty events

2.4 Industroyer/CrashOverride (2016) - ATT&CK Mapping
Target: Ukraine power transmission (follow-up to 2015 attack)
ATT&CK Mapping:
Tactic

Technique

Implementation

Initial Access

T0883

Internet Accessible Device

Execution

T0853

Scripting

Persistence

T0891

Modify Program

Discovery

T0840

Network Connection Enumeration

Lateral Movement

T0886

Remote Services

Collection

T0877

I/O Image

C2

T0869

Standard Application Layer Protocol

Inhibit Response

T0814

Denial of Service

Impair Process Control

T0855

Unauthorized Command Message

Impact

T0837

Loss of Protection

Industroyer Protocol Payload Modules:
●​
●​
●​
●​

101.dll: IEC 60870-5-101 (serial SCADA)
104.dll: IEC 60870-5-104 (IP SCADA)
61850.dll: IEC 61850 (substation automation)
OPC.dll: OPC DA (SCADA interoperability)

Sophistication:
●​ First malware to directly control electric grid switches
●​ Protocol-aware (IEC 61850, IEC 104, OPC DA)

●​ Designed for repeatable attacks
●​ Modular architecture for different protocols

3. ATT&CK Technique Deep Dives
3.1 T0883 - Internet Accessible Device
Description: Adversaries gain initial access via internet-connected ICS devices
Affected Systems:
●​
●​
●​
●​

HMIs with remote access enabled
Engineering workstations with VPN
Historian servers accessible via web
IP cameras on OT network

Detection:
●​ Monitor inbound connections from internet to OT networks
●​ IDS rules for suspicious remote desktop connections
●​ Baseline legitimate remote access patterns
Mitigation:
●​ Eliminate direct internet access to OT devices
●​ Implement VPN with MFA for remote access
●​ Use jump boxes in DMZ

3.2 T0836 - Modify Parameter
Description: Adversaries alter PLC/controller parameters to manipulate processes
Examples:
●​
●​
●​
●​

Stuxnet: Centrifuge frequency modification
Temperature setpoint changes in chemical reactors
Pressure relief valve thresholds
Motor speed controllers

Detection:
●​ Baseline normal parameter ranges
●​ Alert on parameter writes from unauthorized sources
●​ Compare current parameters to golden configuration
Mitigation:
●​ Implement parameter change approval workflows
●​ Use PLC write-protection features

●​ Enable audit logging on engineering workstations

3.3 T0839 - Module Firmware
Description: Modification of firmware in PLCs, RTUs, IEDs
Capabilities:
●​ Persist through power cycles
●​ Evade detection (firmware not regularly audited)
●​ Difficult to remove without reflashing
Detection:
●​ Hash verification of firmware images
●​ Monitor for unauthorized firmware updates
●​ Baseline firmware versions
Mitigation:
●​ Enable firmware code signing
●​ Restrict firmware update permissions
●​ Regularly verify firmware integrity

3.4 T0816 - Device Restart/Shutdown
Description: Forceful restart or shutdown of devices (DoS)
Modbus Example:
# Function Code 08, Sub-function 01: Restart Communications
def modbus_restart_device(ip, unit_id=1):
trans_id = b'\x00\x01'
proto_id = b'\x00\x00'
length = b'\x00\x04'
func_code = b'\x08'
sub_function = b'\x00\x01' # Restart
data = b'\x00\x00'
packet = trans_id + proto_id + length + bytes([unit_id]) + func_code + sub_function + data
# Send packet to port 502
S7comm Example:
# PLC STOP command
import snap7
plc = snap7.client.Client()
plc.connect(ip, 0, 1)
plc.plc_stop() # Sends Function 0x29 (PLC STOP)

Detection:
●​ Monitor for diagnostic function codes (Modbus FC 08)
●​ Detect S7comm PLC STOP commands (FC 0x29)
●​ Alert on unexpected device reboots

3.5 T0856 - Spoof Reporting Message
Description: Falsify sensor data to deceive operators
Stuxnet Example:
●​ Recorded 21 seconds of "normal" sensor values
●​ Replayed values during attack phase
●​ Operators saw stable centrifuge operation while they were being destroyed
Implementation Pattern:
●​ Man-in-the-middle between PLC and HMI
●​ Modify SCADA historian data
●​ Inject false values into Modbus responses
Detection:
●​ Compare sensor values from multiple sources
●​ Anomaly detection (values too stable/consistent)
●​ Cryptographic signing of sensor data (rare)

3.6 T0877 - I/O Image
Description: Read PLC I/O table to understand process state
Information Gained:
●​
●​
●​
●​

Digital inputs: Sensor states (on/off, open/closed)
Digital outputs: Actuator commands (pumps, valves)
Analog inputs: Temperature, pressure, flow rates
Analog outputs: Control signals (valve positions)

Modbus Read Example:
# Read all I/O (assume 100 coils, 100 registers)
digital_inputs = read_discrete_inputs(plc_ip, 0, 100) # FC 02
digital_outputs = read_coils(plc_ip, 0, 100)
# FC 01
analog_inputs = read_input_registers(plc_ip, 0, 100) # FC 04
analog_outputs = read_holding_registers(plc_ip, 0, 100) # FC 03
Detection:
●​ Monitor for excessive read operations

●​ Baseline normal polling frequency
●​ Alert on reads from non-SCADA sources

4. ATT&CK Navigator for ICS
4.1 Installation and Setup
Web Version: https://mitre-attack.github.io/attack-navigator/
Local Installation:
git clone https://github.com/mitre-attack/attack-navigator.git
cd attack-navigator/nav-app
npm install
ng serve
# Access at http://localhost:4200

4.2 Creating Custom Layers
Load ICS Matrix:
1.​ Open ATT&CK Navigator
2.​ Click "New Tab"
3.​ Select "Enterprise" → switch to "ICS"
Highlight Stuxnet Techniques:
{
"name": "Stuxnet ATT&CK Layer",
"versions": {
"attack": "13",
"navigator": "4.9.0",
"layer": "4.4"
},
"domain": "ics-attack",
"description": "Techniques used in Stuxnet operation",
"techniques": [
{
"techniqueID": "T0883",
"color": "#ff0000",
"comment": "USB worm propagation"
},
{
"techniqueID": "T0873",
"color": "#ff0000",
"comment": "Step 7 project infection"
},

{
"techniqueID": "T0839",
"color": "#ff0000",
"comment": "PLC firmware rootkit"
},
{
"techniqueID": "T0836",
"color": "#ff0000",
"comment": "Centrifuge frequency manipulation"
},
{
"techniqueID": "T0879",
"color": "#ff0000",
"comment": "Physical destruction of centrifuges"
}
]
}
Save and Load:
●​ File → Save Layer → Download JSON
●​ File → Open Existing Layer → Upload JSON

4.3 Threat Intelligence Integration
Mapping APT Groups to ICS Techniques:
Sandworm (Russia GRU):
●​ Ukraine 2015/2016 attacks
●​ Industroyer, BlackEnergy, KillDisk
●​ Focus: Electric power disruption
XENOTIME:
●​ Triton/Trisis attack
●​ Targeted safety systems
●​ Petrochemical focus
APT33 (Iran):
●​ Saudi Aramco infrastructure targeting
●​ Aviation, energy sectors
●​ Initial access via spear-phishing
Lazarus Group (North Korea):
●​ Limited OT operations observed
●​ Primarily IT/financial focus

5. Defensive Mapping
5.1 MITRE D3FEND for ICS
D3FEND (d3fend.mitre.org): Defensive countermeasures framework
Example Mapping - T0836 (Modify Parameter):
D3FEND Technique

Implementation

Configuration Inventory

Baseline PLC parameters

File Integrity Monitoring

Monitor PLC program changes

Network Traffic Filtering

Block unauthorized engineering workstations

Authentication

Require credentials for parameter writes

5.2 Detection Rules by Technique
T0855 - Unauthorized Command Message:
# Snort/Suricata rule
alert tcp any any -> any 502 (
msg:"Modbus Write from Unauthorized Source";
content:"|06|"; offset:7; depth:1;
!src_ip $AUTHORIZED_SCADA_SERVERS;
sid:1000100;
)
T0816 - Device Restart:
alert tcp any any -> any 502 (
msg:"Modbus Restart Command";
content:"|08 00 01|"; offset:7; depth:3;
sid:1000101;
)
alert tcp any any -> any 102 (
msg:"Siemens PLC STOP Command";
content:"|29|"; offset:17; depth:1;
sid:1000102;
)
T0877 - I/O Image Excessive Read:
# Zeek script for anomalous Modbus reads
@load base/frameworks/notice

global modbus_read_threshold = 100; # Reads per hour
global modbus_read_count: table[addr] of count;
event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool) {
if (headers$function_code in [1, 2, 3, 4]) { # Read functions
if (c$id$orig_h !in modbus_read_count)
modbus_read_count[c$id$orig_h] = 0;
++modbus_read_count[c$id$orig_h];
if (modbus_read_count[c$id$orig_h] > modbus_read_threshold)
NOTICE([$note=ModbusExcessiveRead,
$msg=fmt("Excessive Modbus reads from %s", c$id$orig_h),
$conn=c]);
}
}

6. Threat Modeling Exercise
6.1 Water Treatment Facility Scenario
System Description:
●​
●​
●​
●​

Purdue Level 1: PLCs controlling pumps, valves, chemical dosing
Level 2: SCADA HMI for operators
Level 3: Historian, MES
Protocols: Modbus TCP, OPC UA

Threat Model:
Adversary: Nation-state actor Objective: Contaminate water supply (T0879 - Damage to
Property)
Attack Path:
1.​ Initial Access (T0883): Spear-phishing engineering staff
2.​ Execution (T0871): Malicious macro executes backdoor
3.​ Persistence (T0891): Install scheduled task on EWS
4.​ Lateral Movement (T0886): RDP to SCADA server
5.​ Discovery (T0877): Read PLC I/O to map chemical dosing system
6.​ Collection (T0861): Identify chlorine and fluoride control tags
7.​ Impair Process Control (T0836): Modify chlorine dosing setpoint (0.5 ppm → 10
ppm)
8.​ Inhibit Response (T0804): Block high chlorine alarms
9.​ Impact (T0879): Water contamination, potential casualties
Critical Techniques:

●​ T0836: Modify Parameter (chlorine setpoint)
●​ T0804: Block Reporting Message (suppress alarms)
●​ T0856: Spoof Reporting Message (show normal chlorine levels to operators)

6.2 Defensive Controls per Technique
Technique

Control

Implementation

T0883

Phishing-resistant MFA Require hardware tokens for remote access

T0886

Network Segmentation

Firewall between IT and OT (unidirectional
gateway)

T0877

Anomaly Detection

Alert on PLC reads from non-SCADA sources

T0836

Parameter Monitoring

Alarm on setpoint changes >10% from baseline

T0804

Alarm Forwarding

Send critical alarms to external SOC (bypass
tampering)

T0856

Multi-source Validation

Compare PLC values with independent sensors

7. Hands-On Lab Exercises
Lab 1: ATT&CK Mapping
1.​ Research the Colonial Pipeline ransomware attack (2021)
2.​ Map attack to ATT&CK for ICS techniques
3.​ Identify which tactics were used (even though primary impact was IT-focused)
4.​ Create ATT&CK Navigator layer

Lab 2: Triton Framework Analysis
1.​ Download Triton framework artifacts from public malware repos (or reconstructed
versions)
2.​ Analyze TsHi.py protocol implementation
3.​ Map capabilities to ATT&CK techniques
4.​ Document detection strategies

Lab 3: Defensive Rule Development
1.​ Select 5 high-risk ICS ATT&CK techniques
2.​ Write Snort/Suricata rules for each

3.​ Test rules against ICS protocol PCAPs
4.​ Tune to reduce false positives

Lab 4: Threat Model Development
1.​ Choose industrial process (power plant, manufacturing, oil refinery)
2.​ Document Purdue model architecture
3.​ Identify crown jewels (critical systems)
4.​ Map potential attack paths using ATT&CK techniques
5.​ Recommend defensive controls per layer

8. Tools & Resources
ATT&CK Resources
●​ ATT&CK for ICS: https://attack.mitre.org/matrices/ics/
●​ ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/
●​ MITRE D3FEND: https://d3fend.mitre.org/

Case Study Reports
●​ Stuxnet (Symantec):
https://docs.broadcom.com/doc/security-response-w32-stuxnet-dossier
●​ Ukraine Grid (SANS/E-ISAC):
https://www.sans.org/reading-room/whitepapers/ICS/analysis-cyber-attack-ukrainianpower-grid-36787
●​ Triton (MITRE):
https://www.mitre.org/news-insights/publication/how-triton-malware-disrupted-safetysystem
●​ Industroyer (ESET):
https://www.welivesecurity.com/2017/06/12/industroyer-biggest-threat-industrial-contr
ol-systems-since-stuxnet/

Detection Tools
●​ Zeek + ICSNPP: https://github.com/cisagov/icsnpp
●​ Snort ICS Rules: https://www.snort.org/downloads/#rule-downloads
●​ Suricata ICS Rules: https://github.com/digitalbond/Quickdraw

9. Knowledge Check
1.​ What are the 11 tactics in MITRE ATT&CK for ICS?
2.​ How does T0856 (Spoof Reporting Message) enable process manipulation?
3.​ Map the Stuxnet attack to at least 5 ATT&CK techniques.
4.​ What is the difference between Inhibit Response Function and Impair Process
Control tactics?

5.​ Why is T0839 (Module Firmware) difficult to detect and remove?
6.​ How would you detect T0816 (Device Restart/Shutdown) via network monitoring?
7.​ What defensive controls mitigate T0836 (Modify Parameter)?
8.​ Describe the Triton/Trisis attack objective and why it was catastrophic-intent.
9.​ How does ATT&CK Navigator aid in threat intelligence analysis?
10.​What is the relationship between ATT&CK (offensive) and D3FEND (defensive)?

