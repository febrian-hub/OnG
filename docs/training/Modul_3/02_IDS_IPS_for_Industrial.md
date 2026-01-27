Lesson 02: IDS/IPS for Industrial
Protocols

Lesson 02: IDS/IPS for Industrial
Protocols
Learning Objectives
●​ Deploy intrusion detection systems tailored for OT networks
●​ Write custom detection rules for Modbus, S7comm, DNP3, and other industrial
protocols
●​ Configure Zeek with ICSNPP plugins for deep protocol analysis
●​ Implement Snort/Suricata with ICS-specific rulesets
●​ Perform protocol whitelisting and anomaly detection
●​ Tune IDS to minimize false positives in operational environments
●​ Detect attacks from Module 2 (reconnaissance, MITM, malicious writes, C2
beaconing)

Introduction
Traditional IT-focused IDS systems like Snort and Suricata are designed to detect attacks on
HTTP, DNS, SSH, and other IT protocols. However, OT environments use industrial
protocols (Modbus, S7comm, DNP3, EtherNet/IP) that standard IDS cannot parse or
understand.
Key Differences for OT IDS:
●​ Must understand industrial protocol semantics (function codes, register addresses)
●​ Extremely low false positive tolerance (false alerts can trigger unnecessary
shutdowns)
●​ Protocol whitelisting is more effective than signature-based detection
●​ Behavioral analysis and anomaly detection are critical
●​ Must operate passively (no inline blocking that could disrupt processes)
This lesson directly addresses attacks from Module 2:
●​ Reconnaissance (Module 2 Lesson 01): Detect port scans, Modbus reads, S7comm
enumeration
●​ MITM attacks (Module 2 Lesson 03): Detect ARP spoofing, unexpected traffic
patterns
●​ PLC manipulation (Module 2 Lesson 04): Detect unauthorized writes, program
downloads
●​ C2 beaconing (Module 2 Lesson 09): Detect periodic outbound connections, DNS
tunneling

1. ICS IDS Platforms

1.1 Commercial ICS IDS Solutions
Platform

Strengths

Protocols Supported

Pricing

Nozomi
Networks
Guardian

Deep packet inspection,
asset discovery, threat
intelligence

Modbus, S7, DNP3,
EtherNet/IP, OPC UA,
IEC 104, BACnet,
Profinet

Enterprise
($50K+)

Claroty
Continuous
Threat Detection

Integration with vulnerability
management, anomaly
detection

100+ protocols
including proprietary

Enterprise
($40K+)

Dragos Platform

Threat intelligence from
Dragos WorldView,
industrial-specific threat
hunting

Modbus, DNP3, S7,
EtherNet/IP, OPC
DA/UA

Enterprise
($60K+)

Cyberbit

Attack simulation,
automated playbooks

Modbus, DNP3, S7,
IEC 61850

Enterprise

Armis

Agentless asset discovery,
passive monitoring

Multi-protocol support

Mid-market
($30K+)

1.2 Open-Source ICS IDS Solutions
Zeek (formerly Bro) with ICSNPP Plugins:
●​
●​
●​
●​

Developed by CISA (US Cybersecurity and Infrastructure Security Agency)
Protocol parsers for Modbus, DNP3, EtherNet/IP, Profinet, BACnet, S7comm
Scriptable detection logic in Zeek language
Best for: Large-scale deployments, custom detection, research

Suricata with Quickdraw ICS Rules:
●​
●​
●​
●​

High-performance IDS with multi-threading support
ET Open ICS rules, Quickdraw rules from Digital Bond
Lua scripting for complex detection
Best for: Inline IPS deployments (with caution), high-throughput networks

Snort with Digital Bond Rules:
●​ Classic signature-based IDS
●​ Digital Bond Quickdraw ICS rules (legacy, not updated since 2016)
●​ Preprocessors for Modbus, DNP3

●​ Best for: Legacy deployments, simple signature-based detection

2. Zeek with ICSNPP Plugins
2.1 Installation and Configuration
#!/bin/bash
# install_zeek_ics.sh
# Install Zeek with ICSNPP plugins for industrial protocol analysis
# Step 1: Install Zeek
sudo apt update
sudo apt install -y cmake make gcc g++ flex bison libpcap-dev libssl-dev python3
python3-dev swig zlib1g-dev
# Install from source for latest version
cd /opt
wget https://download.zeek.org/zeek-6.0.0.tar.gz
tar -xzf zeek-6.0.0.tar.gz
cd zeek-6.0.0
./configure --prefix=/opt/zeek
make -j$(nproc)
sudo make install
# Add to PATH
echo 'export PATH=/opt/zeek/bin:$PATH' >> ~/.bashrc
source ~/.bashrc
# Step 2: Install Zeek Package Manager
pip3 install zkg
# Step 3: Configure zkg
zkg autoconfig
# Step 4: Install ICSNPP plugins
# Modbus
zkg install icsnpp-modbus
# DNP3
zkg install icsnpp-dnp3
# EtherNet/IP (CIP)
zkg install icsnpp-enip
# S7comm (Siemens)
zkg install icsnpp-s7comm
# BACnet
zkg install icsnpp-bacnet
# Profinet
zkg install icsnpp-profinet

# IEC 60870-5-104
zkg install icsnpp-iec104
# Step 5: Verify installation
zeek --version
zkg list
echo "Zeek with ICSNPP plugins installed successfully"

2.2 Basic Zeek Configuration for OT Network
# /opt/zeek/etc/node.cfg
# Configure Zeek for passive monitoring on OT network
[logger]
type=logger
host=localhost
[manager]
type=manager
host=localhost
[proxy-1]
type=proxy
host=localhost
[worker-1]
type=worker
host=localhost
interface=eth1 # OT network interface
lb_method=custom
lb_procs=4 # Use 4 CPU cores
# /opt/zeek/share/zeek/site/local.zeek
# Load ICS plugins and custom detection scripts
# Load ICSNPP plugins
@load icsnpp/modbus
@load icsnpp/dnp3
@load icsnpp/enip
@load icsnpp/s7comm
@load icsnpp/bacnet
@load icsnpp/iec104
# Load custom detection scripts
@load ./detect_unauthorized_modbus_writes.zeek
@load ./detect_plc_reconnaissance.zeek
@load ./detect_c2_beaconing.zeek
@load ./detect_arp_spoofing.zeek

# Enable JSON logging for SIEM integration
@load policy/tuning/json-logs.zeek
# Configure logging
redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_ISO8601;

2.3 Custom Zeek Detection Scripts
Detect Unauthorized Modbus Writes:
# detect_unauthorized_modbus_writes.zeek
# Alert on Modbus write operations from unauthorized sources
@load base/frameworks/notice
module ModbusSecurity;
export {
redef enum Notice::Type += {
UnauthorizedModbusWrite,
ExcessiveModbusWrites,
ModbusDiagnosticFunction
};
# Whitelist of authorized sources for Modbus writes
global authorized_writers: set[addr] = {
10.20.30.50, # SCADA server
10.20.30.100 # Engineering workstation
} &redef;
# Whitelist of allowed destination PLCs
global plc_network: subnet = 10.20.10.0/24 &redef;
# Track write counts per source IP
global write_counts: table[addr] of count &create_expire=1hr &default=0;
}
# Monitor Modbus write functions
event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool) &priority=5
{
# Only process requests (from client to server)
if (!is_orig)
return;
local src_ip = c$id$orig_h;

local dst_ip = c$id$resp_h;
local func_code = headers$function_code;
# Check if destination is a PLC
if (dst_ip !in plc_network)
return;
# Detect write function codes
# FC 5: Write Single Coil
# FC 6: Write Single Register
# FC 15: Write Multiple Coils
# FC 16: Write Multiple Registers
# FC 23: Read/Write Multiple Registers
if (func_code in [5, 6, 15, 16, 23]) {
# Check if source is authorized
if (src_ip !in authorized_writers) {
NOTICE([$note=UnauthorizedModbusWrite,
$msg=fmt("Unauthorized Modbus write from %s to PLC %s (FC: %d)", src_ip,
dst_ip, func_code),
$conn=c,
$identifier=cat(src_ip, dst_ip),
$suppress_for=5min]);
}
# Track write frequency (detect excessive writes)
++write_counts[src_ip];
if (write_counts[src_ip] > 100) {
NOTICE([$note=ExcessiveModbusWrites,
$msg=fmt("Excessive Modbus writes from %s: %d writes in last hour", src_ip,
write_counts[src_ip]),
$conn=c,
$identifier=cat(src_ip),
$suppress_for=1hr]);
}
}
# Detect diagnostic function (used in reconnaissance)
if (func_code == 8) {
NOTICE([$note=ModbusDiagnosticFunction,
$msg=fmt("Modbus diagnostic function from %s to %s (recon activity?)", src_ip,
dst_ip),
$conn=c,
$identifier=cat(src_ip, dst_ip),
$suppress_for=10min]);
}
}

Detect PLC Reconnaissance:
# detect_plc_reconnaissance.zeek
# Detect reconnaissance activities targeting PLCs
@load base/frameworks/notice
@load base/frameworks/sumstats
module PLCRecon;
export {
redef enum Notice::Type += {
PLCPortScan,
ModbusFunctionCodeScan,
ExcessiveModbusReads
};
global plc_network: subnet = 10.20.10.0/24 &redef;
}
# Detect port scanning targeting PLCs
event SumStats::finish(ss: SumStats::SumStat, key: SumStats::Key, data: SumStats::Result)
{
if (ss$name == "plc_port_scan") {
local scanner = key$host;
local port_count = data["port_scan"]$num;
if (port_count > 5) {
NOTICE([$note=PLCPortScan,
$msg=fmt("Port scan detected from %s: %d ports scanned on PLC network",
scanner, port_count),
$src=scanner,
$suppress_for=1hr]);
}
}
}
# Track connection attempts to multiple ports
event connection_attempt(c: connection) {
local dst_ip = c$id$resp_h;
# Only monitor PLC network
if (dst_ip !in plc_network)
return;
SumStats::observe("plc_port_scan",
[$host=c$id$orig_h],
[$str=cat(c$id$resp_p)]);

}
# Configure SumStats
event zeek_init() {
SumStats::create([
$name="plc_port_scan",
$epoch=5min,
$reducers=set(SumStats::UNIQUE),
$threshold=5.0,
$threshold_val(key: SumStats::Key, result: SumStats::Result) = {
return result["port_scan"]$num;
},
$threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
# Will trigger SumStats::finish event
}
]);
}
# Detect excessive Modbus reads (reconnaissance)
global read_counts: table[addr] of count &create_expire=10min &default=0;
event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool) {
if (!is_orig)
return;
local src_ip = c$id$orig_h;
local dst_ip = c$id$resp_h;
local func_code = headers$function_code;
if (dst_ip !in plc_network)
return;
# Detect read function codes
# FC 1: Read Coils
# FC 2: Read Discrete Inputs
# FC 3: Read Holding Registers
# FC 4: Read Input Registers
if (func_code in [1, 2, 3, 4]) {
++read_counts[src_ip];
# Alert if >100 reads in 10 minutes (likely reconnaissance)
if (read_counts[src_ip] > 100) {
NOTICE([$note=ExcessiveModbusReads,
$msg=fmt("Excessive Modbus reads from %s: %d reads in 10 minutes (possible
recon)", src_ip, read_counts[src_ip]),
$conn=c,
$src=src_ip,
$suppress_for=30min]);

# Reset counter
read_counts[src_ip] = 0;
}
}
}
Detect C2 Beaconing:
# detect_c2_beaconing.zeek
# Detect periodic outbound connections (C2 beaconing)
@load base/frameworks/notice
module C2Detection;
export {
redef enum Notice::Type += {
PeriodicBeaconing,
DNSTunneling,
UnusualDNSQuery
};
# Track connection times per src/dst pair
global conn_times: table[addr, addr, port] of vector of time &create_expire=24hr;
}
event connection_state_remove(c: connection) {
local src = c$id$orig_h;
local dst = c$id$resp_h;
local dport = c$id$resp_p;
# Only monitor outbound connections from OT network
if (!Site::is_local_addr(src) || Site::is_local_addr(dst))
return;
# Record connection time
local key = [src, dst, dport];
if (key !in conn_times)
conn_times[key] = vector();
conn_times[key][|conn_times[key]|] = network_time();
# Analyze if we have enough data points (at least 5 connections)
if (|conn_times[key]| >= 5) {
local times = conn_times[key];
local intervals: vector of interval;

# Calculate intervals between connections
for (i in times) {
if (i > 0) {
intervals[|intervals|] = times[i] - times[i-1];
}
}
# Check for periodic pattern (beaconing)
if (|intervals| >= 4) {
local avg_interval = 0.0sec;
for (interval in intervals) {
avg_interval += intervals[interval];
}
avg_interval = avg_interval / |intervals|;
# Calculate standard deviation
local variance = 0.0;
for (interval in intervals) {
local diff = intervals[interval] - avg_interval;
variance += diff * diff;
}
local stddev = sqrt(variance / |intervals|);
# If stddev is low, connections are periodic (likely beaconing)
if (stddev < 30.0sec && avg_interval > 1min) {
NOTICE([$note=PeriodicBeaconing,
$msg=fmt("Periodic beaconing detected from %s to %s:%d (avg interval: %s,
stddev: %s)",
src, dst, dport, avg_interval, stddev),
$src=src,
$identifier=cat(src, dst, dport),
$suppress_for=6hr]);
}
}
}
}
# Detect DNS tunneling
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
# Check for unusually long DNS queries (potential tunneling)
if (|query| > 50) {
NOTICE([$note=DNSTunneling,
$msg=fmt("Potential DNS tunneling: long query from %s: %s", c$id$orig_h, query),
$conn=c,
$suppress_for=1hr]);
}
# Check for high entropy in subdomain (random-looking)

if (has_high_entropy(query)) {
NOTICE([$note=UnusualDNSQuery,
$msg=fmt("High-entropy DNS query from %s: %s (possible C2)", c$id$orig_h,
query),
$conn=c,
$suppress_for=30min]);
}
}
function has_high_entropy(s: string): bool {
# Simple entropy check (production should use proper Shannon entropy)
local unique_chars: set[string];
for (i in s) {
add unique_chars[s[i]];
}
return |unique_chars| > (|s| * 0.7); # >70% unique characters
}
Detect ARP Spoofing (MITM):
# detect_arp_spoofing.zeek
# Detect ARP spoofing attacks (MITM between SCADA and PLCs)
@load base/frameworks/notice
module ARPSecurity;
export {
redef enum Notice::Type += {
ARPSpoofing,
DuplicateMAC
};
# Track IP-to-MAC mappings
global arp_table: table[addr] of string &create_expire=24hr;
}
event arp_request(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA:
string) {
check_arp_mapping(SPA, SHA);
}
event arp_reply(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA:
string) {
check_arp_mapping(SPA, SHA);
}
function check_arp_mapping(ip: addr, mac: string) {

if (ip in arp_table) {
# Check if MAC has changed
if (arp_table[ip] != mac) {
NOTICE([$note=ARPSpoofing,
$msg=fmt("ARP spoofing detected: IP %s changed from MAC %s to %s", ip,
arp_table[ip], mac),
$src=ip,
$suppress_for=10min]);
}
} else {
# New entry
arp_table[ip] = mac;
}
}

2.4 Running Zeek and Analyzing Logs
#!/bin/bash
# run_zeek_ot_monitoring.sh
# Start Zeek in live capture mode
zeekctl deploy
# Monitor logs in real-time
tail -f /opt/zeek/logs/current/notice.log | jq '.'
# View Modbus traffic
tail -f /opt/zeek/logs/current/modbus.log | jq '.'
# View S7comm traffic
tail -f /opt/zeek/logs/current/s7comm.log | jq '.'
# View DNP3 traffic
tail -f /opt/zeek/logs/current/dnp3.log | jq '.'
Example Zeek Notice Log (JSON):
{
"ts": "2025-01-03T14:23:45.123456Z",
"uid": "CHhAvVGS1DHFjwGM9",
"id.orig_h": "10.20.30.99",
"id.orig_p": 54321,
"id.resp_h": "10.20.10.10",
"id.resp_p": 502,
"proto": "tcp",
"note": "ModbusSecurity::UnauthorizedModbusWrite",
"msg": "Unauthorized Modbus write from 10.20.30.99 to PLC 10.20.10.10 (FC: 16)",
"sub": "Write Multiple Registers",
"src": "10.20.30.99",

"dst": "10.20.10.10",
"p": 502,
"actions": ["Notice::ACTION_LOG"],
"suppress_for": 300.0
}

3. Snort/Suricata Rules for ICS Protocols
3.1 Install Suricata with ICS Rules
#!/bin/bash
# install_suricata_ics.sh
# Install Suricata
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update
sudo apt install -y suricata jq
# Download Emerging Threats ICS rules
sudo suricata-update enable-source et/open
sudo suricata-update enable-source oisf/trafficid
sudo suricata-update
# Download Digital Bond Quickdraw ICS rules (legacy but useful)
cd /tmp
wget https://github.com/digitalbond/Quickdraw-Snort/archive/master.zip
unzip master.zip
sudo cp Quickdraw-Snort-master/*.rules /etc/suricata/rules/
# Enable ICS rules in suricata.yaml
sudo sed -i 's/# - modbus.rules/- modbus.rules/g' /etc/suricata/suricata.yaml
sudo sed -i 's/# - dnp3.rules/- dnp3.rules/g' /etc/suricata/suricata.yaml
# Configure network interface
sudo sed -i 's/interface: eth0/interface: eth1/g' /etc/suricata/suricata.yaml # OT interface
# Start Suricata
sudo systemctl start suricata
sudo systemctl enable suricata
# Verify
sudo suricata --build-info

3.2 Custom Snort/Suricata Rules for ICS
Modbus Rules:
# modbus_custom.rules

# Custom Snort/Suricata rules for Modbus traffic
# Detect Modbus write from unauthorized source
alert tcp !$SCADA_SERVERS any -> $PLC_NETWORK 502 (
msg:"SCADA-CUSTOM Unauthorized Modbus Write";
flow:to_server,established;
content:"|06|"; offset:7; depth:1; # Function Code 6: Write Single Register
classtype:policy-violation;
sid:9000001; rev:1;
)
alert tcp !$SCADA_SERVERS any -> $PLC_NETWORK 502 (
msg:"SCADA-CUSTOM Unauthorized Modbus Write Multiple Registers";
flow:to_server,established;
content:"|10|"; offset:7; depth:1; # Function Code 16: Write Multiple Registers
classtype:policy-violation;
sid:9000002; rev:1;
)
# Detect Modbus diagnostic functions (recon)
alert tcp any any -> $PLC_NETWORK 502 (
msg:"SCADA-RECON Modbus Diagnostic Function";
flow:to_server,established;
content:"|08|"; offset:7; depth:1; # Function Code 8: Diagnostics
classtype:attempted-recon;
sid:9000003; rev:1;
)
# Detect excessive register read (reconnaissance)
alert tcp any any -> $PLC_NETWORK 502 (
msg:"SCADA-RECON Modbus Large Register Read";
flow:to_server,established;
content:"|03|"; offset:7; depth:1; # Function Code 3: Read Holding Registers
byte_test:2,>,100,10; # Quantity > 100 registers
classtype:attempted-recon;
sid:9000004; rev:1;
)
# Detect Modbus exception responses (errors could indicate attack)
alert tcp $PLC_NETWORK 502 -> any any (
msg:"SCADA-ANOMALY Modbus Exception Response";
flow:to_client,established;
content:"|81|"; offset:7; depth:1; # Exception for FC 1
classtype:protocol-command-decode;
sid:9000005; rev:1;
)
# Detect Modbus to non-standard port (covert channel)

alert tcp any any -> $PLC_NETWORK !502 (
msg:"SCADA-ANOMALY Modbus Traffic on Non-Standard Port";
flow:to_server,established;
content:"|00 00|"; depth:2; # Modbus transaction ID
content:"|00 00|"; offset:2; depth:2; # Modbus protocol ID
classtype:protocol-command-decode;
sid:9000006; rev:1;
)
S7comm Rules:
# s7comm_custom.rules
# Detect Siemens S7comm attacks
# Detect PLC STOP command
alert tcp any any -> $PLC_NETWORK 102 (
msg:"SCADA-ATTACK Siemens PLC STOP Command";
flow:to_server,established;
content:"|03 00|"; depth:2; # TPKT version 3
content:"|32|"; distance:5; within:1; # COTP type
content:"|29|"; distance:12; within:1; # S7 Function: STOP
classtype:attempted-dos;
sid:9000101; rev:1;
)
# Detect program download to PLC
alert tcp any any -> $PLC_NETWORK 102 (
msg:"SCADA-SUSPICIOUS S7 Program Download to PLC";
flow:to_server,established;
content:"|03 00|"; depth:2;
content:"|1A|"; distance:17; within:1; # Function: Download block
classtype:policy-violation;
sid:9000102; rev:1;
)
# Detect program upload from PLC (data exfiltration)
alert tcp any any -> $PLC_NETWORK 102 (
msg:"SCADA-EXFIL S7 Program Upload from PLC";
flow:to_server,established;
content:"|03 00|"; depth:2;
content:"|1D|"; distance:17; within:1; # Function: Start Upload
classtype:policy-violation;
sid:9000103; rev:1;
)
# Detect S7 authentication bypass (blank password)
alert tcp any any -> $PLC_NETWORK 102 (
msg:"SCADA-AUTH S7 Authentication with Blank Password";

flow:to_server,established;
content:"|03 00|"; depth:2;
content:"|F0|"; distance:5; within:1; # Setup communication
content:"|00 00 00 00|"; within:4; # Blank password
classtype:attempted-admin;
sid:9000104; rev:1;
)
# Detect S7 from non-engineering workstation
alert tcp !$EWS_NETWORK any -> $PLC_NETWORK 102 (
msg:"SCADA-POLICY S7comm from Unauthorized Source";
flow:to_server,established;
content:"|03 00|"; depth:2;
classtype:policy-violation;
threshold:type limit, track by_src, count 1, seconds 300;
sid:9000105; rev:1;
)
DNP3 Rules:
# dnp3_custom.rules
# Detect DNP3 attacks (SCADA in power/water utilities)
# Detect DNP3 Direct Operate (bypasses SELECT before OPERATE)
alert tcp any any -> $SCADA_NETWORK 20000 (
msg:"SCADA-ATTACK DNP3 Direct Operate Command";
flow:to_server,established;
content:"|05 64|"; depth:2; # DNP3 start bytes
content:"|05|"; distance:10; within:1; # Function Code 5: Direct Operate
classtype:attempted-admin;
sid:9000201; rev:1;
)
# Detect DNP3 cold restart
alert tcp any any -> $SCADA_NETWORK 20000 (
msg:"SCADA-DOS DNP3 Cold Restart Command";
flow:to_server,established;
content:"|05 64|"; depth:2;
content:"|0D|"; distance:10; within:1; # Function Code 13: Cold Restart
classtype:attempted-dos;
sid:9000202; rev:1;
)
# Detect DNP3 write (unauthorized configuration change)
alert tcp any any -> $SCADA_NETWORK 20000 (
msg:"SCADA-CONFIG DNP3 Write Command";
flow:to_server,established;
content:"|05 64|"; depth:2;

content:"|02|"; distance:10; within:1; # Function Code 2: Write
classtype:policy-violation;
sid:9000203; rev:1;
)
# Detect DNP3 file transfer (potential malware delivery)
alert tcp any any -> $SCADA_NETWORK 20000 (
msg:"SCADA-MALWARE DNP3 File Transfer";
flow:to_server,established;
content:"|05 64|"; depth:2;
content:"|15|"; distance:10; within:1; # Function Code 21: File Transport
classtype:trojan-activity;
sid:9000204; rev:1;
)

3.3 Suricata Configuration
# /etc/suricata/suricata.yaml (relevant sections)
vars:
address-groups:
PLC_NETWORK: "[10.20.10.0/24]"
SCADA_SERVERS: "[10.20.30.50/32]"
EWS_NETWORK: "[10.20.30.100/32]"
SCADA_NETWORK: "[10.20.0.0/16]"
# Enable ICS protocol parsers
app-layer:
protocols:
modbus:
enabled: yes
detection-ports:
dp: 502
dnp3:
enabled: yes
detection-ports:
dp: 20000
# Logging
outputs:
- fast:
enabled: yes
filename: fast.log
- eve-log:
enabled: yes
filetype: regular
filename: eve.json
types:

- alert:
payload: yes
payload-buffer-size: 4kb
- modbus:
enabled: yes
- dnp3:
enabled: yes
# Rule files
default-rule-path: /etc/suricata/rules
rule-files:
- suricata.rules
- modbus_custom.rules
- s7comm_custom.rules
- dnp3_custom.rules

4. Protocol Whitelisting and Baseline
4.1 Building a Baseline
# build_ot_baseline.py
# Baseline normal OT network traffic to create whitelist
import pyshark
from collections import defaultdict
import json
class OTBaseline:
def __init__(self, pcap_file):
self.pcap_file = pcap_file
self.legitimate_flows = defaultdict(int)
self.protocol_distribution = defaultdict(int)
self.function_codes = defaultdict(lambda: defaultdict(int))
def analyze_pcap(self):
"""Analyze PCAP to build baseline"""
cap = pyshark.FileCapture(self.pcap_file, display_filter='tcp')
for packet in cap:
try:
src_ip = packet.ip.src
dst_ip = packet.ip.dst
dst_port = packet.tcp.dstport
# Record legitimate flow
flow_key = f"{src_ip}->{dst_ip}:{dst_port}"
self.legitimate_flows[flow_key] += 1

# Track protocols
if dst_port == '502': # Modbus
self.protocol_distribution['Modbus'] += 1
# Extract Modbus function code if available
if hasattr(packet, 'modbus'):
func_code = packet.modbus.func_code
self.function_codes['Modbus'][func_code] += 1
elif dst_port == '102': # S7comm
self.protocol_distribution['S7comm'] += 1
elif dst_port == '20000': # DNP3
self.protocol_distribution['DNP3'] += 1
elif dst_port == '44818': # EtherNet/IP
self.protocol_distribution['EtherNet/IP'] += 1
except AttributeError:
continue
cap.close()
def export_whitelist(self, output_file='ot_whitelist.json'):
"""Export whitelist for enforcement"""
whitelist = {
'flows': dict(self.legitimate_flows),
'protocols': dict(self.protocol_distribution),
'modbus_function_codes': dict(self.function_codes['Modbus'])
}
with open(output_file, 'w') as f:
json.dump(whitelist, f, indent=2)
print(f"[+] Whitelist exported to {output_file}")
print(f"[+] Legitimate flows: {len(self.legitimate_flows)}")
print(f"[+] Protocol distribution: {dict(self.protocol_distribution)}")
def generate_zeek_whitelist(self):
"""Generate Zeek script to enforce whitelist"""
zeek_script = """
# whitelist_enforcement.zeek
# Auto-generated whitelist from baseline analysis
@load base/frameworks/notice
module WhitelistEnforcement;

export {
redef enum Notice::Type += {
UnauthorizedFlow
};
global legitimate_flows: set[addr, addr, port] = {
"""
# Add flows
for flow_key in self.legitimate_flows:
parts = flow_key.split('->')
src = parts[0]
dst_parts = parts[1].split(':')
dst = dst_parts[0]
port = dst_parts[1]
zeek_script += f"
[{src}, {dst}, {port}/tcp],\n"
zeek_script += """

} &redef;

}
event new_connection(c: connection) {
local flow = [c$id$orig_h, c$id$resp_h, c$id$resp_p];
if (flow !in legitimate_flows) {
NOTICE([$note=UnauthorizedFlow,
$msg=fmt("New flow not in whitelist: %s -> %s:%d", c$id$orig_h, c$id$resp_h,
c$id$resp_p),
$conn=c,
$suppress_for=10min]);
}
}
"""
with open('whitelist_enforcement.zeek', 'w') as f:
f.write(zeek_script)
print("[+] Zeek whitelist script generated: whitelist_enforcement.zeek")
# Usage
if __name__ == '__main__':
import sys
if len(sys.argv) < 2:
print("Usage: python3 build_ot_baseline.py <pcap_file>")
sys.exit(1)
pcap_file = sys.argv[1]
print(f"[*] Analyzing {pcap_file} to build baseline...")

baseline = OTBaseline(pcap_file)
baseline.analyze_pcap()
baseline.export_whitelist()
baseline.generate_zeek_whitelist()
print("\n[+] Baseline complete. Deploy whitelist_enforcement.zeek to Zeek.")
Usage:
# Capture 7 days of normal traffic
sudo tcpdump -i eth1 -w ot_baseline.pcap -G 604800 -W 1
# Build baseline
python3 build_ot_baseline.py ot_baseline.pcap
# Deploy to Zeek
sudo cp whitelist_enforcement.zeek /opt/zeek/share/zeek/site/
# Add to local.zeek: @load ./whitelist_enforcement.zeek
sudo zeekctl deploy

5. Anomaly Detection and Machine Learning
5.1 Statistical Anomaly Detection
# anomaly_detection_ot.py
# Detect statistical anomalies in OT traffic
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import json
class OTAnomalyDetector:
def __init__(self, zeek_log_path):
self.zeek_log_path = zeek_log_path
self.model = IsolationForest(contamination=0.01, random_state=42)
def load_zeek_logs(self):
"""Load Zeek connection logs"""
# Read JSON logs
logs = []
with open(self.zeek_log_path, 'r') as f:
for line in f:
logs.append(json.loads(line))
return pd.DataFrame(logs)
def extract_features(self, df):

"""Extract features for anomaly detection"""
features = pd.DataFrame()
# Feature 1: Connection duration
features['duration'] = df['duration'].fillna(0)
# Feature 2: Bytes transferred
features['orig_bytes'] = df['orig_bytes'].fillna(0)
features['resp_bytes'] = df['resp_bytes'].fillna(0)
# Feature 3: Packet count
features['orig_pkts'] = df['orig_pkts'].fillna(0)
features['resp_pkts'] = df['resp_pkts'].fillna(0)
# Feature 4: Connection state (convert to numeric)
state_map = {'S0': 0, 'S1': 1, 'SF': 2, 'REJ': 3, 'RSTO': 4}
features['conn_state'] = df['conn_state'].map(state_map).fillna(-1)
# Feature 5: Destination port
features['dst_port'] = df['id.resp_p'].fillna(0)
return features
def train(self, df):
"""Train anomaly detection model on normal traffic"""
features = self.extract_features(df)
self.model.fit(features)
print("[+] Model trained on normal traffic")
def detect_anomalies(self, df):
"""Detect anomalies in new traffic"""
features = self.extract_features(df)
predictions = self.model.predict(features)
# -1 = anomaly, 1 = normal
anomalies = df[predictions == -1]
return anomalies
# Usage
if __name__ == '__main__':
# Load baseline (normal) traffic
detector = OTAnomalyDetector('/opt/zeek/logs/2025-01-01/conn.log')
baseline_df = detector.load_zeek_logs()
# Train model
detector.train(baseline_df)

# Detect anomalies in current traffic
current_df = detector.load_zeek_logs() # Load current logs
anomalies = detector.detect_anomalies(current_df)
print(f"\n[!] Detected {len(anomalies)} anomalous connections:")
print(anomalies[['ts', 'id.orig_h', 'id.resp_h', 'id.resp_p', 'duration']])

6. Tuning IDS to Minimize False Positives
6.1 Common False Positive Sources in OT
1.​ Legitimate Engineering Activities: Program downloads, PLC reboots
2.​ Scheduled Maintenance: Vendor remote access, firmware updates
3.​ Polling Behavior: SCADA polling PLCs every second
4.​ Startup Sequences: PLCs broadcasting on startup

6.2 Tuning Strategies
Suppress Alerts During Maintenance Windows:
# maintenance_window_suppression.zeek
module MaintenanceMode;
export {
# Define maintenance windows
global maintenance_windows: vector of interval = {
[2025-01-10 02:00:00 .. 2025-01-10 06:00:00], # Planned maintenance
[2025-01-17 02:00:00 .. 2025-01-17 06:00:00]
};
# Suppress specific notice types during maintenance
global suppressed_notices: set[Notice::Type] = {
ModbusSecurity::UnauthorizedModbusWrite,
PLCRecon::PLCPortScan
};
}
hook Notice::policy(n: Notice::Info) {
# Check if we're in maintenance window
for (window in maintenance_windows) {
if (network_time() >= window$start && network_time() <= window$end) {
if (n$note in suppressed_notices) {
# Suppress notice
add n$actions[Notice::ACTION_NONE];
break;
}

}
}
}
Whitelist Known-Good Behavior:
# suricata: suppress.conf
# Suppress false positives for known-good activity
# Suppress S7 program download from engineering workstation during work hours
suppress gen_id 1, sig_id 9000102, track by_src, ip 10.20.30.100
# Suppress Modbus diagnostic from SCADA monitoring tool
suppress gen_id 1, sig_id 9000003, track by_src, ip 10.20.30.50
# Suppress alerts for vendor remote access (with time limit)
suppress gen_id 1, sig_id 9000105, track by_src, ip 203.0.113.50

7. Hands-On Lab: Deploy IDS for OT Network
Lab Objective
Deploy Zeek with ICSNPP plugins and Suricata to monitor a water treatment facility OT
network. Detect attacks from Module 2.

Lab Environment
●​
●​
●​
●​

OT Network: 10.20.10.0/24 (PLCs)
SCADA Network: 10.20.30.0/24
IDS Sensor: Ubuntu 22.04 with TAP/SPAN port access
Attack Scenarios: Modbus reconnaissance, unauthorized writes, C2 beaconing

Lab Steps
Step 1: Deploy Zeek
# Install Zeek with ICSNPP
bash install_zeek_ics.sh
# Configure for OT network
sudo nano /opt/zeek/etc/node.cfg
# Set interface=eth1 (SPAN port receiving mirrored OT traffic)
# Deploy
sudo zeekctl deploy
Step 2: Configure Custom Detection

# Copy custom detection scripts
cd /opt/zeek/share/zeek/site
sudo nano detect_unauthorized_modbus_writes.zeek
# Paste detection script from Section 2.3
# Enable in local.zeek
echo "@load ./detect_unauthorized_modbus_writes.zeek" | sudo tee -a local.zeek
# Reload
sudo zeekctl deploy
Step 3: Generate Test Traffic
# test_modbus_write.py
# Simulate unauthorized Modbus write (should trigger alert)
from pymodbus.client import ModbusTcpClient
client = ModbusTcpClient('10.20.10.10', port=502)
client.connect()
# Write to holding register (will be detected as unauthorized)
client.write_register(100, 9999, unit=1)
client.close()
print("[*] Test write sent to PLC")
Step 4: Verify Detection
# Check Zeek notices
tail -f /opt/zeek/logs/current/notice.log | jq 'select(.note ==
"ModbusSecurity::UnauthorizedModbusWrite")'
# Should see alert:
#{
# "note": "ModbusSecurity::UnauthorizedModbusWrite",
# "msg": "Unauthorized Modbus write from 10.20.30.99 to PLC 10.20.10.10 (FC: 6)",
# ...
#}
Step 5: Deploy Suricata
# Install and configure
bash install_suricata_ics.sh
# Test rules
sudo suricata -T -c /etc/suricata/suricata.yaml
# Run in live mode

sudo suricata -c /etc/suricata/suricata.yaml -i eth1
# Monitor alerts
tail -f /var/log/suricata/fast.log
Step 6: Integration with SIEM
# Forward Zeek logs to SIEM (Splunk example)
sudo /opt/splunkforwarder/bin/splunk add monitor /opt/zeek/logs/current/ -sourcetype
zeek:json
# Forward Suricata logs
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/suricata/eve.json -sourcetype
suricata

Lab Deliverables
1.​ Zeek installation with ICSNPP plugins
2.​ Custom detection scripts (Modbus writes, recon, C2 beaconing)
3.​ Suricata with custom ICS rules
4.​ Baseline whitelist from 24 hours of traffic
5.​ Test report showing successful detection of Module 2 attacks
6.​ SIEM integration (Splunk/ELK dashboard)

8. Real-World Case Study: Detecting Industroyer
Industroyer/CrashOverride (2016 Ukraine power grid attack) used IEC 60870-5-104
protocol to send commands to circuit breakers.
How IDS Would Detect:
# detect_industroyer.zeek
# Detect IEC 104 attack patterns similar to Industroyer
@load icsnpp/iec104
event iec104_asdu(c: connection, is_orig: bool, asdu: IEC104::ASDU) {
# Detect direct control commands (used by Industroyer)
if (asdu$type_id == 45 || asdu$type_id == 46) { # C_SC_NA_1 or C_DC_NA_1
NOTICE([$note=IEC104Attack,
$msg=fmt("IEC 104 control command from %s (Industroyer-like)", c$id$orig_h),
$conn=c]);
}
# Detect station interrogation (reconnaissance)
if (asdu$type_id == 100) { # C_IC_NA_1
NOTICE([$note=IEC104Recon,

$msg=fmt("IEC 104 interrogation from %s", c$id$orig_h),
$conn=c]);
}
}
Suricata Rule:
alert tcp any any -> $SCADA_NETWORK 2404 (
msg:"SCADA-APT IEC 104 Control Command (Industroyer-like)";
flow:to_server,established;
content:"|68|"; offset:0; depth:1; # IEC 104 start byte
content:"|2D|"; distance:6; within:1; # Type ID 45: Single command
classtype:attempted-admin;
reference:url,www.welivesecurity.com/2017/06/12/industroyer-biggest-threat-industrial-contro
l-systems-since-stuxnet/;
sid:9000301; rev:1;
)

9. Tools and Resources
IDS Platforms
●​
●​
●​
●​

Zeek: https://zeek.org
ICSNPP Plugins: https://github.com/cisagov/icsnpp
Suricata: https://suricata.io
Snort: https://www.snort.org

ICS-Specific Rules
●​ Quickdraw (Digital Bond): https://github.com/digitalbond/Quickdraw-Snort
●​ Emerging Threats ICS: https://rules.emergingthreats.net
●​ Cisco Talos ICS: https://www.snort.org/downloads

Commercial IDS
●​
●​
●​
●​

Nozomi Networks: https://www.nozominetworks.com
Claroty: https://claroty.com
Dragos Platform: https://www.dragos.com
Armis: https://www.armis.com

Learning Resources
●​ ICS-CERT: https://www.cisa.gov/ics
●​ SANS ICS515: ICS Visibility, Detection, and Response
●​ Applied Purple Teaming for ICS: https://www.sans.org/white-papers/

Conclusion
Intrusion detection in OT environments requires specialized tools and techniques:
●​
●​
●​
●​
●​

Protocol-aware IDS (Zeek with ICSNPP) to understand Modbus, S7comm, DNP3
Custom detection rules tailored to specific OT attack patterns
Protocol whitelisting based on known-good baseline traffic
Anomaly detection to catch zero-day attacks
Minimal false positives through careful tuning and maintenance windows

In the next lesson, we'll explore OT asset management and safe vulnerability scanning
techniques to maintain visibility over all devices in the industrial network.

