Lesson 01: ICS/SCADA/OT
Architecture & Components

Lesson 01: ICS/SCADA/OT Architecture
& Components
Learning Objectives
●​ Understand the fundamental architecture of Industrial Control Systems (ICS),
SCADA, and Operational Technology (OT)
●​ Identify critical components and their functions in industrial environments
●​ Analyze the Purdue Enterprise Reference Architecture (PERA) model
●​ Recognize security implications of air-gapped vs. connected OT networks

1. Industrial Control Systems Overview
1.1 ICS/SCADA/OT Definitions
Industrial Control Systems (ICS): Umbrella term for control systems used in industrial
production including SCADA, DCS, and PLC-based systems.
SCADA (Supervisory Control and Data Acquisition): Centralized systems for monitoring
and controlling geographically dispersed assets. Common in:
●​
●​
●​
●​

Electric power transmission/distribution
Water/wastewater treatment
Oil and gas pipelines
Manufacturing facilities

Operational Technology (OT): Hardware and software that detects or causes changes
through direct monitoring and control of physical devices, processes, and events.
Distributed Control Systems (DCS): Control systems distributed throughout a facility with
autonomous controllers across multiple locations.

1.2 Key Differences: IT vs. OT
Aspect

IT (Information Technology)

OT (Operational Technology)

Priority

Confidentiality → Integrity →
Availability

Availability → Integrity →
Confidentiality

Downtime
Tolerance

Minutes to hours acceptable

Seconds can cause catastrophic
failure

Patch Cycles

Weekly/Monthly

Quarterly/Annually (during
planned outages)

Lifespan

3-5 years

15-30 years

Change
Management

Agile, frequent updates

Rigorous, infrequent changes

Network
Segmentation

VLAN/subnets

Physical/air-gapped networks

2. Purdue Enterprise Reference Architecture (PERA)
Level 0: Physical Process
●​
●​
●​
●​

Components: Sensors, actuators, physical equipment
Function: Direct interaction with physical processes
Protocols: 4-20mA analog signals, discrete I/O
Security Concern: Physical tampering, sensor spoofing

Level 1: Intelligent Devices
●​ Components: PLCs (Programmable Logic Controllers), RTUs (Remote Terminal
Units), IEDs (Intelligent Electronic Devices)
●​ Function: Real-time control, process automation
●​ Protocols: Modbus RTU/TCP, DNP3, Profibus, S7Comm
●​ Security Concern: Firmware manipulation, logic injection

Level 2: Control Systems
●​ Components: HMI (Human-Machine Interface), Engineering Workstations,
Supervisory Control
●​ Function: Operator interface, process visualization, data logging
●​ Protocols: OPC UA, OPC DA, proprietary vendor protocols
●​ Security Concern: HMI exploitation, unauthorized control

Level 3: Operations & Control
●​
●​
●​
●​

Components: SCADA servers, historians, MES (Manufacturing Execution Systems)
Function: Production workflow, batch management, plant operations
Protocols: OPC UA, Ethernet/IP, BACnet
Security Concern: Data manipulation, production disruption

Level 3.5: DMZ (Demilitarized Zone)
●​ Components: Data historians, application servers, remote access gateways

●​ Function: Data exchange between IT and OT networks
●​ Protocols: HTTPS, OPC UA, database protocols
●​ Security Concern: Lateral movement pivot point

Level 4: Business Logistics
●​
●​
●​
●​

Components: ERP (Enterprise Resource Planning), asset management
Function: Manufacturing operations management, supply chain
Protocols: Standard IT protocols (HTTP/S, SQL, SMB)
Security Concern: Traditional IT attack vectors

Level 5: Enterprise Network
●​
●​
●​
●​

Components: Corporate IT infrastructure
Function: Business operations, email, internet access
Protocols: Standard IT protocols
Security Concern: Initial access vector for OT-targeted attacks

3. Critical ICS Components Deep Dive
3.1 Programmable Logic Controllers (PLCs)
Function: Execute control logic to automate industrial processes
Major Vendors:
●​
●​
●​
●​

Siemens (S7-300, S7-400, S7-1200, S7-1500)
Allen-Bradley/Rockwell (ControlLogix, CompactLogix)
Schneider Electric (Modicon M340, M580)
Mitsubishi (MELSEC iQ-R, iQ-F)

Programming Languages (IEC 61131-3):
●​
●​
●​
●​
●​

Ladder Logic (LD)
Function Block Diagram (FBD)
Structured Text (ST)
Instruction List (IL)
Sequential Function Chart (SFC)

Security Weaknesses:
●​
●​
●​
●​
●​

No authentication in legacy protocols
Plaintext communication
Firmware lacks integrity verification
Default credentials rarely changed
Remote access often enabled for convenience

3.2 Remote Terminal Units (RTUs)

Function: Field devices for telemetry and remote control in distributed systems
Characteristics:
●​
●​
●​
●​

Ruggedized for harsh environments
Supports serial and IP communications
Lower processing power than PLCs
Common in utilities (SCADA systems)

Protocols: DNP3, IEC 60870-5-101/104, Modbus

3.3 Human-Machine Interface (HMI)
Function: Graphical interface for operators to monitor and control processes
Major Platforms:
●​
●​
●​
●​

Siemens WinCC
Wonderware InTouch
GE iFIX
Ignition by Inductive Automation

Vulnerabilities:
●​
●​
●​
●​

Often runs on Windows with outdated OS
Direct database access (SQL injection risks)
Web-based interfaces with weak authentication
Hardcoded credentials in configuration files

3.4 Historians
Function: Time-series database for process data collection and analysis
Examples:
●​
●​
●​
●​

OSIsoft PI System
GE Proficy Historian
Wonderware Historian
Honeywell Uniformance PHD

Security Risks:
●​
●​
●​
●​

Contains sensitive operational data
Often accessible from both IT and OT networks
Database vulnerabilities
Data integrity attacks

3.5 Engineering Workstations (EWS)
Function: Program, configure, and maintain control systems

Software:
●​
●​
●​
●​

Siemens TIA Portal
Rockwell Studio 5000
Schneider Unity Pro
Codesys

Attack Surface:
●​
●​
●​
●​

High-privilege access to control systems
Often used for remote vendor support
Removable media usage
Target for supply chain attacks

4. Common Industrial Protocols
4.1 Modbus (1979)
●​
●​
●​
●​

Transport: Serial (RTU), TCP/IP (Modbus TCP)
Function Codes: Read coils (01), Write single register (06), etc.
Port: 502/TCP
Security: None - no authentication, no encryption

4.2 DNP3 (Distributed Network Protocol 3)
●​
●​
●​
●​

Use Case: Electric utilities, water/wastewater
Port: 20000/TCP
Features: Request/response, unsolicited responses, time synchronization
Security: DNP3 Secure Authentication (SAv5) rarely implemented

4.3 S7comm/S7comm-Plus (Siemens)
●​ Port: 102/TCP (ISO-TSAP)
●​ Functions: PLC programming, diagnostics, data exchange
●​ Security: S7comm unencrypted, S7comm-Plus has integrity checks (bypassed in
research)

4.4 OPC UA (OPC Unified Architecture)
●​ Port: 4840/TCP (default)
●​ Security: Built-in encryption, authentication, authorization
●​ Modern Standard: Replacing legacy OPC DA/HDA/AE

4.5 Ethernet/IP
●​ Vendor: Rockwell Automation (Allen-Bradley)
●​ Port: 44818/TCP (TCP-based), 2222/UDP (implicit messaging)
●​ Based on: CIP (Common Industrial Protocol)

4.6 Profinet/Profibus
●​ Vendor: Siemens and consortium
●​ Transport: Industrial Ethernet (Profinet), Serial (Profibus)
●​ Security: No native encryption/authentication

4.7 BACnet (Building Automation)
●​ Port: 47808/UDP (BACnet/IP)
●​ Use Case: HVAC, lighting, access control
●​ Security: Minimal - designed for trusted networks

4.8 IEC 60870-5-104
●​ Use Case: European electric power systems
●​ Port: 2404/TCP
●​ Similar to: DNP3 functionality

5. Network Architecture Patterns
5.1 Air-Gapped Networks
●​ Definition: Physical isolation from external networks
●​ Implementation: No direct network connectivity to internet/corporate network
●​ Bypass Methods:
○​ Removable media (USB - Stuxnet vector)
○​ Compromised vendor laptops
○​ Supply chain attacks
○​ Electromagnetic emanations (theoretical)

5.2 Segmented Networks
●​ Implementation: Firewalls, unidirectional gateways, VLANs
●​ Best Practice: ISA/IEC 62443 zone/conduit model
●​ Common Mistakes:
○​ Bidirectional flows in DMZ
○​ Overly permissive firewall rules
○​ Shared infrastructure (DNS, AD, patching)

5.3 Flat Networks (Legacy)
●​ Characteristics: Minimal segmentation, shared IT/OT infrastructure
●​ Risks: Rapid lateral movement, IT malware propagation to OT

6. Case Studies

6.1 Stuxnet (2010)
●​ Target: Iranian nuclear enrichment centrifuges (Siemens S7-300/400 PLCs)
●​ Attack Chain:
1.​ USB propagation to air-gapped network
2.​ Windows zero-days for privilege escalation
3.​ Siemens Step 7 project infection
4.​ PLC rootkit installation
5.​ Frequency manipulation of centrifuge motors
●​ Impact: Physical destruction of ~1000 centrifuges

6.2 Ukraine Power Grid (2015)
●​ Target: Ukrainian electric distribution companies
●​ Attack Chain:
1.​ Spear-phishing to corporate network
2.​ Lateral movement to OT network
3.​ Operator credential theft
4.​ Manual breaker manipulation via HMI
5.​ Serial-to-Ethernet converter firmware wipe
6.​ UPS disruption for control center
●​ Impact: 225,000 customers without power for 6 hours

6.3 Triton/Trisis (2017)
●​
●​
●​
●​

Target: Safety Instrumented System (Schneider Electric Triconex)
Objective: Disable safety systems (potential for catastrophic failure)
Technique: Custom framework for Triconex protocol manipulation
Detection: Inadvertent SIS shutdown triggered investigation

7. Practical Lab Setup Components
7.1 Virtualization Platforms
●​ VirtualBox: Free, suitable for small labs
●​ VMware Workstation/ESXi: Better performance, advanced networking
●​ Proxmox: Open-source alternative for dedicated hardware

7.2 ICS Simulators
●​
●​
●​
●​

OpenPLC: Open-source PLC (Modbus, DNP3, Ethernet/IP)
ScadaBR: Open-source SCADA system
Factory I/O: 3D factory simulation with PLC integration
GRFICSv2: Chemical plant simulation (Unity 3D + Modbus)

7.3 Network Tools

●​ GNS3: Network simulation with ICS device integration
●​ EVE-NG: Enterprise-grade network emulation
●​ Virtual Serial Port: COM port emulation for serial protocols

8. Hands-On Exercises
Exercise 1: Purdue Model Mapping
Map a real-world industrial facility (choose power plant, water treatment, or manufacturing)
to the Purdue model. Identify:
●​ Components at each level
●​ Communication flows between levels
●​ Potential security boundaries

Exercise 2: Protocol Identification
Download ICS protocol PCAPs from:
●​ https://github.com/automayt/ICS-pcap
●​ https://www.netresec.com/?page=PCAP4SICS
Use Wireshark to identify:
●​
●​
●​
●​

Protocol type (Modbus, DNP3, S7comm)
Function codes/commands
Source/destination devices
Potential security issues (plaintext credentials, etc.)

Exercise 3: Architecture Documentation
Install and configure a basic SCADA environment:
1.​ Deploy OpenPLC Runtime on Linux VM
2.​ Install ScadaBR for HMI/SCADA
3.​ Configure Modbus TCP communication
4.​ Create network diagram documenting:
○​ IP addresses and ports
○​ Protocol flows
○​ Trust boundaries

9. Tools & Resources
Documentation
●​ ICS-CERT Recommended Practices: https://www.cisa.gov/ics

●​ ISA/IEC 62443 Standards:
https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-ofstandards
●​ NIST SP 800-82 Rev 2: https://csrc.nist.gov/publications/detail/sp/800-82/rev-2/final

Protocol References
●​ Modbus Specification: https://modbus.org/specs.php
●​ DNP3 Primer: https://www.dnp.org/
●​ OPC UA Specification:
https://opcfoundation.org/developer-tools/specifications-unified-architecture

Learning Platforms
●​ OpenPLC Project: https://www.openplcproject.com/
●​ PLC Training: https://www.plcacademy.com/
●​ Control Global: https://www.controlglobal.com/

GitHub Repositories
●​ Awesome ICS Security:
https://github.com/hslatman/awesome-industrial-control-system-security
●​ ICS PCAP Collection: https://github.com/automayt/ICS-pcap
●​ OpenPLC: https://github.com/thiagoralves/OpenPLC_v3

10. Knowledge Check
1.​ What is the primary difference in security priorities between IT and OT environments?
2.​ At which Purdue level would you typically find HMI systems?
3.​ Why do ICS protocols like Modbus lack authentication mechanisms?
4.​ What role does the DMZ (Level 3.5) play in ICS architecture?
5.​ Describe the attack chain of Stuxnet and identify the Purdue levels involved.
6.​ What is the purpose of a unidirectional gateway in OT networks?
7.​ Compare RTUs vs PLCs - when would each be used?
8.​ Why is OPC UA considered more secure than OPC DA?
9.​ What are the risks of air-gapped networks, as demonstrated by Stuxnet?
10.​Identify three critical differences between DCS and SCADA systems.

