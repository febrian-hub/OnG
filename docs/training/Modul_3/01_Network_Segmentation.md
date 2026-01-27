Lesson 01: Network Segmentation &
Security

Lesson 01: ICS Network Segmentation &
Security Architecture
Learning Objectives
●​ Design defense-in-depth architecture for OT networks using ISA/IEC 62443
standards
●​ Implement Purdue Model for industrial control systems
●​ Deploy unidirectional gateways and secure data diodes
●​ Configure industrial firewalls with deep packet inspection
●​ Establish secure remote access with zero-trust principles
●​ Understand network segmentation to counter Module 2 attack techniques

Introduction
Network segmentation is the foundational defensive control for OT environments. Unlike IT
networks where defense often focuses on endpoint protection and perimeter security, OT
networks rely heavily on network isolation to prevent lateral movement, contain incidents,
and protect safety-critical systems.
This lesson directly addresses attacks covered in Module 2:
●​ Lateral movement (Module 2 Lesson 02): Segmentation limits attacker pivot paths
●​ MITM attacks (Module 2 Lesson 03): Segmentation reduces attack surface for
network positioning
●​ Persistence (Module 2 Lesson 08): Isolated zones prevent multi-layered persistence
across network tiers
●​ C2 communications (Module 2 Lesson 09): Unidirectional gateways block outbound
command channels

1. The Purdue Model for Industrial Control Systems
1.1 Overview
The Purdue Enterprise Reference Architecture (PERA), also called the Purdue Model, is
the de facto standard for organizing ICS networks into hierarchical zones based on function
and trust level.
┌────────────────────────────────────────────────────────
─────┐
│ Level 5: Enterprise Network
│
│ - ERP, Business Intelligence, Corporate IT
│

└────────────────────────────────────────────────────────
─────┘
▲
│ Firewall + DMZ
▼
┌────────────────────────────────────────────────────────
─────┐
│ Level 4: Site Business Planning & Logistics
│
│ - Plant management, scheduling, inventory
│
└────────────────────────────────────────────────────────
─────┘
▲
│ Unidirectional Gateway
▼
┌────────────────────────────────────────────────────────
─────┐
│ Level 3.5: Industrial DMZ (optional)
│
│ - Historian, patch management, remote access VPN
│
└────────────────────────────────────────────────────────
─────┘
▲
│ Industrial Firewall
▼
┌────────────────────────────────────────────────────────
─────┐
│ Level 3: Operations & Control
│
│ - SCADA/HMI, Engineering Workstations, OPC servers
│
└────────────────────────────────────────────────────────
─────┘
▲
│ Firewall + Protocol Filter
▼
┌────────────────────────────────────────────────────────
─────┐
│ Level 2: Supervisory Control
│
│ - PLCs, RTUs, DCS controllers, local HMIs
│
└────────────────────────────────────────────────────────
─────┘
▲
│ Dedicated network (process bus)
▼
┌────────────────────────────────────────────────────────
─────┐
│ Level 1: Basic Control
│
│ - Intelligent sensors, actuators, VFDs
│
└────────────────────────────────────────────────────────
─────┘
▲

│ 4-20mA, HART, fieldbus
▼
┌────────────────────────────────────────────────────────
─────┐
│ Level 0: Physical Process
│
│ - Sensors, motors, valves, pumps (physical equipment)
│
└────────────────────────────────────────────────────────
─────┘

1.2 Level Descriptions
Level 0: Physical Process
●​ Physical equipment: pumps, motors, valves, actuators
●​ Analog signals (4-20mA), HART, Foundation Fieldbus
●​ No IT connectivity
Level 1: Basic Control
●​ Intelligent field devices: smart sensors, VFDs
●​ Direct control of Level 0 equipment
●​ Protocols: Profibus, DeviceNet, Modbus RTU
Level 2: Supervisory Control
●​
●​
●​
●​

PLCs, RTUs, DCS controllers
Execute real-time control logic
Communicate with Level 1 (process bus) and Level 3 (SCADA)
Critical security zone: Compromise here = process manipulation

Level 3: Operations & Control
●​
●​
●​
●​

SCADA servers, HMIs, Engineering Workstations (EWS)
Operator interfaces and process monitoring
Program development and PLC maintenance
High-value target: Attackers often pivot from here to Level 2

Level 3.5: Industrial DMZ
●​
●​
●​
●​
●​

Intermediary zone between IT and OT
Historian servers (one-way data from Level 2)
Patch management servers
Remote access VPN termination
Blast radius containment: Compromise here shouldn't reach Level 2

Level 4: Site Business Planning
●​ Manufacturing execution systems (MES)
●​ Production scheduling
●​ Inventory management

●​ Bridge between operations and enterprise
Level 5: Enterprise Network
●​ Corporate ERP, business intelligence
●​ Standard IT environment
●​ Assumed compromised: Design OT security with this assumption

1.3 Practical Implementation Example: Water Treatment Plant
# water_plant_network_design.py
# Purdue Model implementation for municipal water treatment facility
class PurdueNetworkDesign:
def __init__(self):
self.zones = self.define_zones()
self.conduits = self.define_conduits()
def define_zones(self):
"""Define all security zones in water treatment plant"""
return {
'Level_0': {
'name': 'Physical Process',
'devices': ['Chlorine pumps', 'pH sensors', 'Flow meters', 'Valves'],
'protocols': ['4-20mA analog', 'HART'],
'network': None # No IP network
},
'Level_1': {
'name': 'Basic Control',
'devices': ['Smart actuators', 'VFDs', 'Intelligent sensors'],
'protocols': ['Modbus RTU', 'Profibus DP'],
'network': 'Serial/Fieldbus'
},
'Level_2_Process': {
'name': 'Process Control PLCs',
'devices': ['Water intake PLC (10.20.10.10)',
'Treatment PLC (10.20.10.11)',
'Distribution PLC (10.20.10.12)'],
'protocols': ['Modbus TCP', 'S7comm'],
'network': '10.20.10.0/24',
'vlan': 20,
'security_level': 'SL-3' # High security
},
'Level_2_Safety': {
'name': 'Safety PLCs',
'devices': ['Emergency shutdown PLC (10.20.20.10)',
'Chemical containment PLC (10.20.20.11)'],
'protocols': ['CIP Safety', 'PROFIsafe'],
'network': '10.20.20.0/24',

'vlan': 21,
'security_level': 'SL-4', # Highest security
'isolation': 'Physically separate network'
},
'Level_3_Operations': {
'name': 'SCADA & HMI',
'devices': ['SCADA server (10.20.30.50)',
'HMI workstations (10.20.30.51-55)',
'Engineering workstation (10.20.30.100)'],
'protocols': ['OPC DA/UA', 'S7comm', 'Modbus TCP'],
'network': '10.20.30.0/24',
'vlan': 30,
'security_level': 'SL-2'
},
'Level_3.5_DMZ': {
'name': 'Industrial DMZ',
'devices': ['Historian (10.20.40.10)',
'Patch server (10.20.40.20)',
'VPN gateway (10.20.40.30)'],
'network': '10.20.40.0/24',
'vlan': 40,
'security_level': 'SL-2'
},
'Level_4_MES': {
'name': 'Manufacturing Execution',
'devices': ['MES server (10.20.50.10)',
'Production scheduler (10.20.50.11)'],
'network': '10.20.50.0/24',
'vlan': 50,
'security_level': 'SL-1'
},
'Level_5_Enterprise': {
'name': 'Corporate IT',
'devices': ['ERP', 'Email', 'File shares'],
'network': '10.100.0.0/16',
'security_level': 'SL-0', # Assume compromised
'notes': 'Standard IT security controls'
}
}
def define_conduits(self):
"""Define allowed communication pathways between zones"""
return [
{
'name': 'SCADA to Process PLCs',
'source': 'Level_3_Operations',
'destination': 'Level_2_Process',
'direction': 'bidirectional',

'protocols': ['Modbus TCP:502', 'S7comm:102'],
'enforcement': 'Industrial firewall with DPI',
'allowed_sources': ['10.20.30.50'], # Only SCADA server
'rule_type': 'whitelist'
},
{
'name': 'Engineering to PLCs',
'source': 'Level_3_Operations',
'destination': 'Level_2_Process',
'direction': 'bidirectional',
'protocols': ['S7comm:102'],
'allowed_sources': ['10.20.30.100'], # Only EWS
'time_restriction': 'Business hours only',
'mfa_required': True
},
{
'name': 'Historian Data Collection',
'source': 'Level_2_Process',
'destination': 'Level_3.5_DMZ',
'direction': 'unidirectional', # OT → IT only
'enforcement': 'Data diode hardware',
'protocols': ['OPC UA:4840'],
'notes': 'IT cannot send commands back'
},
{
'name': 'Enterprise to DMZ',
'source': 'Level_5_Enterprise',
'destination': 'Level_3.5_DMZ',
'direction': 'bidirectional',
'protocols': ['HTTPS:443', 'SQL:1433'],
'enforcement': 'Standard firewall',
'rule_type': 'whitelist'
},
{
'name': 'Safety PLC Isolation',
'source': 'Level_2_Safety',
'destination': '*',
'direction': 'none',
'enforcement': 'Physically separate network',
'notes': 'No network connectivity except local HMI'
}
]
def generate_firewall_rules(self, zone_pair):
"""Generate firewall ruleset for zone conduit"""
rules = []
conduit = next((c for c in self.conduits
if c['source'] == zone_pair[0] and c['destination'] == zone_pair[1]), None)

if not conduit:
return ['deny any any'] # Default deny
for protocol in conduit.get('protocols', []):
proto_name, port = protocol.split(':')
for src_ip in conduit.get('allowed_sources', ['any']):
dst_network = self.zones[conduit['destination']]['network']
rule = f"allow tcp {src_ip} -> {dst_network} port {port} # {proto_name}"
rules.append(rule)
rules.append('deny all') # Explicit deny-all at end
return rules
def validate_architecture(self):
"""Check for common security mistakes"""
issues = []
# Check 1: Ensure no direct IT-to-PLC communication
for conduit in self.conduits:
if conduit['source'] == 'Level_5_Enterprise' and 'Level_2' in conduit['destination']:
issues.append(f"CRITICAL: Direct IT-to-PLC conduit found: {conduit['name']}")
# Check 2: Verify safety systems are isolated
safety_conduits = [c for c in self.conduits if 'Safety' in c['source'] or 'Safety' in
c['destination']]
if len(safety_conduits) > 0:
issues.append(f"WARNING: Safety systems have {len(safety_conduits)} network
conduits")
# Check 3: Check for bidirectional historian connections
for conduit in self.conduits:
if 'Historian' in conduit['name'] and conduit['direction'] == 'bidirectional':
issues.append(f"CRITICAL: Bidirectional historian conduit: {conduit['name']}")
return issues
# Example usage
design = PurdueNetworkDesign()
issues = design.validate_architecture()
if issues:
print("Architecture Security Issues:")
for issue in issues:
print(f" - {issue}")
else:
print("Architecture validation passed")

# Generate firewall rules for SCADA-to-PLC conduit
rules = design.generate_firewall_rules(('Level_3_Operations', 'Level_2_Process'))
print("\nFirewall Rules (SCADA to PLCs):")
for rule in rules:
print(f" {rule}")
Expected Output:
Architecture validation passed
Firewall Rules (SCADA to PLCs):
allow tcp 10.20.30.50 -> 10.20.10.0/24 port 502 # Modbus TCP
allow tcp 10.20.30.50 -> 10.20.10.0/24 port 102 # S7comm
deny all

2. ISA/IEC 62443 Security Levels and Zones
2.1 Security Level (SL) Definitions
ISA/IEC 62443 defines five security levels based on threat sophistication:
Security
Level

Threat Profile

Typical Application

SL 0

No protection requirements

Non-critical systems, lab
environments

SL 1

Protection against casual or accidental
violation

Basic manufacturing,
low-criticality processes

SL 2

Protection against intentional violation using
simple means (script kiddies, automated tools)

Standard industrial
facilities, most PLCs

SL 3

Protection against intentional violation using
sophisticated means (skilled attackers with
resources)

Critical infrastructure,
utilities, chemical plants

SL 4

Protection against intentional violation using
sophisticated means with extended resources
(nation-state actors)

Nuclear, large-scale water
systems, national grid

2.2 Zone and Conduit Model

Security Zone: A grouping of logical or physical assets that share common security
requirements.
Conduit: A logical grouping of communication channels connecting two or more zones.
# isa62443_implementation.py
# Implement ISA/IEC 62443 zone and conduit model
import ipaddress
from enum import Enum
class SecurityLevel(Enum):
SL0 = 0
SL1 = 1
SL2 = 2
SL3 = 3
SL4 = 4
class SecurityZone:
def __init__(self, name, security_level, network, criticality):
self.name = name
self.security_level = security_level
self.network = ipaddress.ip_network(network)
self.criticality = criticality # safety, production, business
self.assets = []
def add_asset(self, asset):
"""Add asset to zone"""
if ipaddress.ip_address(asset['ip']) in self.network:
self.assets.append(asset)
return True
return False
def get_security_requirements(self):
"""Return security controls required for this SL"""
requirements = {
SecurityLevel.SL0: [],
SecurityLevel.SL1: [
'User authentication',
'Audit logging'
],
SecurityLevel.SL2: [
'Multi-factor authentication',
'Encryption in transit',
'Intrusion detection',
'Security event logging'
],
SecurityLevel.SL3: [

'Role-based access control',
'Strong encryption (AES-256)',
'Network segmentation',
'Continuous monitoring',
'Integrity verification'
],
SecurityLevel.SL4: [
'Defense-in-depth',
'Unidirectional gateways',
'Hardware security modules',
'Tamper detection',
'Air-gapped networks',
'Real-time threat intelligence'
]
}
# Cumulative requirements
req_list = []
for level in SecurityLevel:
req_list.extend(requirements[level])
if level == self.security_level:
break
return list(set(req_list)) # Remove duplicates
class Conduit:
def __init__(self, name, source_zone, dest_zone):
self.name = name
self.source_zone = source_zone
self.dest_zone = dest_zone
self.allowed_protocols = []
self.enforcement_mechanism = None
self.direction = 'bidirectional' # or 'unidirectional'
def determine_required_sl(self):
"""Conduit SL = max(source SL, destination SL)"""
return max(self.source_zone.security_level,
self.dest_zone.security_level)
def add_protocol(self, protocol, port, direction='bidirectional'):
"""Add allowed protocol to conduit"""
self.allowed_protocols.append({
'protocol': protocol,
'port': port,
'direction': direction
})
def get_enforcement_requirements(self):

"""Determine required enforcement mechanism based on SL"""
required_sl = self.determine_required_sl()
if required_sl == SecurityLevel.SL4:
return 'Unidirectional gateway with DPI and encrypted tunnels'
elif required_sl == SecurityLevel.SL3:
return 'Industrial firewall with DPI and IDS'
elif required_sl == SecurityLevel.SL2:
return 'Firewall with protocol filtering'
else:
return 'Basic ACLs'
# Example: Power plant implementation
def design_power_plant_network():
# Define zones
turbine_control = SecurityZone(
name='Turbine Control System',
security_level=SecurityLevel.SL4, # Safety-critical
network='10.10.10.0/24',
criticality='safety'
)
scada_operations = SecurityZone(
name='SCADA Operations',
security_level=SecurityLevel.SL3,
network='10.10.20.0/24',
criticality='production'
)
historian_dmz = SecurityZone(
name='Historian DMZ',
security_level=SecurityLevel.SL2,
network='10.10.30.0/24',
criticality='business'
)
# Add assets
turbine_control.add_asset({'ip': '10.10.10.10', 'type': 'Safety PLC', 'vendor': 'Siemens'})
scada_operations.add_asset({'ip': '10.10.20.50', 'type': 'SCADA Server', 'vendor':
'Ignition'})
# Define conduits
scada_to_turbine = Conduit(
name='SCADA to Turbine Control',
source_zone=scada_operations,
dest_zone=turbine_control
)
scada_to_turbine.add_protocol('Modbus TCP', 502)

scada_to_turbine.add_protocol('OPC UA', 4840)
turbine_to_historian = Conduit(
name='Turbine to Historian',
source_zone=turbine_control,
dest_zone=historian_dmz
)
turbine_to_historian.direction = 'unidirectional' # One-way only
turbine_to_historian.add_protocol('OPC UA', 4840, direction='outbound')
# Generate security requirements
print(f"Zone: {turbine_control.name}")
print(f"Security Level: {turbine_control.security_level.name}")
print(f"Required Controls:")
for control in turbine_control.get_security_requirements():
print(f" - {control}")
print(f"\nConduit: {scada_to_turbine.name}")
print(f"Required SL: SL-{scada_to_turbine.determine_required_sl().value}")
print(f"Enforcement: {scada_to_turbine.get_enforcement_requirements()}")
design_power_plant_network()
Output:
Zone: Turbine Control System
Security Level: SL4
Required Controls:
- User authentication
- Audit logging
- Multi-factor authentication
- Encryption in transit
- Intrusion detection
- Security event logging
- Role-based access control
- Strong encryption (AES-256)
- Network segmentation
- Continuous monitoring
- Integrity verification
- Defense-in-depth
- Unidirectional gateways
- Hardware security modules
- Tamper detection
- Air-gapped networks
- Real-time threat intelligence
Conduit: SCADA to Turbine Control
Required SL: SL-4

Enforcement: Unidirectional gateway with DPI and encrypted tunnels

3. Unidirectional Gateways and Data Diodes
3.1 Purpose
Unidirectional gateways (data diodes) provide hardware-enforced one-way data flow from
OT to IT networks. This completely eliminates the risk of:
●​ IT malware propagating to OT (defense against Module 2 Lesson 07 supply chain
attacks)
●​ C2 command channels from internet to PLCs (blocks Module 2 Lesson 09 C2)
●​ Ransomware spreading from enterprise to process control (defense against
NotPetya-style attacks)

3.2 How Data Diodes Work
Physical Implementation:
OT Network (Transmit Only)
IT Network (Receive Only)
┌──────────────┐
┌──────────────┐
│ OPC UA
│
│ Historian │
│ Server
│ TX ┌────────┐ │ Database │
│ 10.20.10.50 │──────>│ Fiber │──>│ 10.30.10.10 │
│
│
│ Optic │ │
│
└──────────────┘
│ Diode │ └──────────────┘
└────────┘
No RX path
Physically impossible to send data back
The TX (transmit) fiber from OT connects to RX (receive) fiber on IT side. There is no
physical return path - the IT side literally cannot send packets back to OT.

3.3 Implementation Example
# data_diode_proxy.py
# Application-layer proxy for unidirectional gateway
# Runs on OT side to push data through hardware diode
import time
import snap7
from opcua import Client as OPCClient
import json
import socket
class DataDiodeProxy:
"""
Collects data from OT devices and pushes through unidirectional gateway

Runs on OT-side gateway appliance
"""
def __init__(self, diode_ip, diode_port):
self.diode_ip = diode_ip
self.diode_port = diode_port
self.plc_clients = {}
self.opc_clients = {}
def add_plc_source(self, name, ip, rack=0, slot=1):
"""Add Siemens PLC as data source"""
client = snap7.client.Client()
client.connect(ip, rack, slot)
self.plc_clients[name] = {
'client': client,
'ip': ip
}
def add_opc_source(self, name, endpoint):
"""Add OPC UA server as data source"""
client = OPCClient(endpoint)
client.connect()
self.opc_clients[name] = {
'client': client,
'endpoint': endpoint
}
def collect_plc_data(self, plc_name, tags):
"""Read data from PLC"""
plc = self.plc_clients[plc_name]['client']
data = {}
for tag in tags:
# Read tag based on type
if tag['type'] == 'DB':
raw_data = plc.db_read(tag['db_number'], tag['start'], tag['size'])
# Parse based on data type
if tag['datatype'] == 'REAL':
value = snap7.util.get_real(raw_data, 0)
elif tag['datatype'] == 'INT':
value = snap7.util.get_int(raw_data, 0)
else:
value = raw_data.hex()
data[tag['name']] = value
return data
def collect_opc_data(self, opc_name, node_ids):

"""Read data from OPC UA server"""
opc = self.opc_clients[opc_name]['client']
data = {}
for node_id in node_ids:
node = opc.get_node(node_id)
data[node_id] = node.get_value()
return data
def push_through_diode(self, payload):
"""
Push data through hardware diode (one-way UDP)
Uses UDP because no ACK is possible (diode blocks return traffic)
"""
try:
# Serialize to JSON
message = json.dumps(payload).encode('utf-8')
# Send via UDP (fire-and-forget)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(message, (self.diode_ip, self.diode_port))
sock.close()
return True
except Exception as e:
print(f"Error pushing through diode: {e}")
return False
def run_collection_loop(self):
"""Main loop: collect and push data every 5 seconds"""
# Define PLC tags to collect
plc_tags = [
{'name': 'Water_Flow', 'type': 'DB', 'db_number': 1, 'start': 0, 'size': 4, 'datatype':
'REAL'},
{'name': 'Chlorine_PPM', 'type': 'DB', 'db_number': 1, 'start': 4, 'size': 4, 'datatype':
'REAL'},
{'name': 'pH_Level', 'type': 'DB', 'db_number': 1, 'start': 8, 'size': 4, 'datatype': 'REAL'},
]
# Define OPC nodes to collect
opc_nodes = [
'ns=2;s=Tank1.Level',
'ns=2;s=Tank1.Temperature',
'ns=2;s=Pump1.Status'
]

while True:
try:
payload = {
'timestamp': time.time(),
'source': 'WaterPlant_OT',
'plc_data': {},
'opc_data': {}
}
# Collect from all PLCs
for plc_name in self.plc_clients:
payload['plc_data'][plc_name] = self.collect_plc_data(plc_name, plc_tags)
# Collect from all OPC servers
for opc_name in self.opc_clients:
payload['opc_data'][opc_name] = self.collect_opc_data(opc_name, opc_nodes)
# Push through diode
success = self.push_through_diode(payload)
if success:
print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Data pushed through diode")
except Exception as e:
print(f"Collection error: {e}")
time.sleep(5) # Collect every 5 seconds
# Usage example
if __name__ == '__main__':
# Initialize proxy
proxy = DataDiodeProxy(
diode_ip='10.20.40.10', # Diode appliance IP (OT side)
diode_port=5000
)
# Add data sources
proxy.add_plc_source('Intake_PLC', '10.20.10.10')
proxy.add_plc_source('Treatment_PLC', '10.20.10.11')
proxy.add_opc_source('SCADA_OPC', 'opc.tcp://10.20.30.50:4840')
# Start collection loop
print("Data diode proxy started. Pushing data to IT network...")
proxy.run_collection_loop()

3.4 IT-Side Receiver (Behind Data Diode)
# diode_receiver.py

# Runs on IT side to receive unidirectional data
# Cannot send anything back to OT (hardware prevents it)
import socket
import json
import sqlite3
from datetime import datetime
class DiodeReceiver:
"""Receive data from unidirectional gateway and store in historian"""
def __init__(self, listen_port, db_path='historian.db'):
self.listen_port = listen_port
self.db_path = db_path
self.init_database()
def init_database(self):
"""Initialize historian database"""
conn = sqlite3.connect(self.db_path)
cursor = conn.cursor()
cursor.execute('''
CREATE TABLE IF NOT EXISTS process_data (
id INTEGER PRIMARY KEY AUTOINCREMENT,
timestamp REAL,
source TEXT,
tag_name TEXT,
value REAL,
received_at TEXT
)
''')
conn.commit()
conn.close()
def store_data(self, payload):
"""Store received data in historian database"""
conn = sqlite3.connect(self.db_path)
cursor = conn.cursor()
# Store PLC data
for plc_name, tags in payload.get('plc_data', {}).items():
for tag_name, value in tags.items():
cursor.execute('''
INSERT INTO process_data (timestamp, source, tag_name, value, received_at)
VALUES (?, ?, ?, ?, ?)
''', (payload['timestamp'], plc_name, tag_name, value, datetime.now().isoformat()))

# Store OPC data
for opc_name, nodes in payload.get('opc_data', {}).items():
for node_id, value in nodes.items():
cursor.execute('''
INSERT INTO process_data (timestamp, source, tag_name, value, received_at)
VALUES (?, ?, ?, ?, ?)
''', (payload['timestamp'], opc_name, node_id, value, datetime.now().isoformat()))
conn.commit()
conn.close()
def listen(self):
"""Listen for UDP data from diode"""
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', self.listen_port))
print(f"Listening for data from diode on port {self.listen_port}...")
while True:
try:
data, addr = sock.recvfrom(65535) # Max UDP packet size
payload = json.loads(data.decode('utf-8'))
self.store_data(payload)
print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Received data from
{payload['source']}")
except Exception as e:
print(f"Error receiving data: {e}")
# Usage
if __name__ == '__main__':
receiver = DiodeReceiver(listen_port=5000)
receiver.listen()

3.5 Commercial Data Diode Solutions
●​
●​
●​
●​

Waterfall Security: Unidirectional CloudConnect
Owl Cyber Defense: DualDiode and OPDS
BAE Systems: Unidirectional Gateway
Hirschmann: EAGLE Tofino Data Diode

4. Industrial Firewall Configuration
Unlike traditional IT firewalls, industrial firewalls must:
●​ Understand OT protocols (Modbus, S7comm, DNP3, etc.)

●​ Perform deep packet inspection (DPI) on industrial traffic
●​ Enforce function-code level restrictions (e.g., allow Modbus reads but block writes)
●​ Maintain sub-10ms latency for real-time traffic

4.1 Firewall Placement
┌────────────────────────────────────────────────────────
──────┐
│ Level 5: Enterprise IT (10.100.0.0/16)
│
└────────────────────────────────────────────────────────
──────┘
▲
│ Firewall 1: IT/OT Boundary
▼
┌────────────────────────────────────────────────────────
──────┐
│ Level 3.5: Industrial DMZ (10.20.40.0/24)
│
│ - Data Diode
│
└────────────────────────────────────────────────────────
──────┘
▲
│ Firewall 2: DMZ to Operations
▼
┌────────────────────────────────────────────────────────
──────┐
│ Level 3: Operations (10.20.30.0/24)
│
│ - SCADA Server (10.20.30.50)
│
│ - Engineering Workstation (10.20.30.100)
│
└────────────────────────────────────────────────────────
──────┘
▲
│ Firewall 3: Operations to Control (DPI)
▼
┌────────────────────────────────────────────────────────
──────┐
│ Level 2: Process Control (10.20.10.0/24)
│
│ - PLCs (10.20.10.10-20)
│
└────────────────────────────────────────────────────────
──────┘
Critical Firewall: Firewall 3 (Operations to Control) - This must inspect all SCADA-to-PLC
traffic

4.2 Palo Alto Firewall Configuration for OT
<!-- palo_alto_ot_policy.xml -->
<!-- Deep packet inspection rules for Modbus traffic -->
<config>

<devices>
<entry name="localhost.localdomain">
<vsys>
<entry name="vsys1">
<!-- Security Zones -->
<zone>
<entry name="OT_Operations">
<network>
<layer3>
<member>ethernet1/1</member>
</layer3>
</network>
</entry>
<entry name="OT_Control">
<network>
<layer3>
<member>ethernet1/2</member>
</layer3>
</network>
</entry>
</zone>
<!-- Address Objects -->
<address>
<entry name="SCADA_Server">
<ip-netmask>10.20.30.50/32</ip-netmask>
</entry>
<entry name="Engineering_Workstation">
<ip-netmask>10.20.30.100/32</ip-netmask>
</entry>
<entry name="PLC_Network">
<ip-netmask>10.20.10.0/24</ip-netmask>
</entry>
</address>
<!-- Security Policies -->
<rulebase>
<security>
<rules>
<!-- Allow SCADA to read from PLCs -->
<entry name="SCADA_Read_PLCs">
<from><member>OT_Operations</member></from>
<to><member>OT_Control</member></to>
<source><member>SCADA_Server</member></source>
<destination><member>PLC_Network</member></destination>
<application><member>modbus</member></application>

<service><member>application-default</member></service>
<action>allow</action>
<profile-setting>
<profiles>
<url-filtering><member>default</member></url-filtering>
<file-blocking><member>strict-file-blocking</member></file-blocking>
<virus><member>default</member></virus>
<spyware><member>strict</member></spyware>
<vulnerability><member>strict</member></vulnerability>
</profiles>
</profile-setting>
<log-start>yes</log-start>
<log-end>yes</log-end>
</entry>
<!-- Block Modbus writes from SCADA (read-only operation) -->
<entry name="Block_SCADA_Writes">
<from><member>OT_Operations</member></from>
<to><member>OT_Control</member></to>
<source><member>SCADA_Server</member></source>
<destination><member>PLC_Network</member></destination>
<application><member>modbus</member></application>
<service><member>application-default</member></service>
<action>deny</action>
<!-- Deep packet inspection on Modbus function codes -->
<option>
<disable-server-response-inspection>no</disable-server-response-inspection>
</option>
<category><member>modbus-write</member></category>
<log-start>yes</log-start>
<log-end>yes</log-end>
</entry>
<!-- Allow Engineering to program PLCs (with MFA) -->
<entry name="EWS_Program_PLCs">
<from><member>OT_Operations</member></from>
<to><member>OT_Control</member></to>
<source><member>Engineering_Workstation</member></source>
<destination><member>PLC_Network</member></destination>
<application>
<member>s7comm</member>
<member>modbus</member>
</application>
<service><member>application-default</member></service>
<action>allow</action>
<!-- Require GlobalProtect MFA -->
<source-user><member>engineering-group</member></source-user>
<hip-profiles><member>ot-engineering-compliance</member></hip-profiles>

<log-start>yes</log-start>
<log-end>yes</log-end>
</entry>
<!-- Block all internet access from OT -->
<entry name="Block_OT_Internet">
<from>
<member>OT_Operations</member>
<member>OT_Control</member>
</from>
<to><member>External</member></to>
<source><member>any</member></source>
<destination><member>any</member></destination>
<application><member>any</member></application>
<service><member>any</member></service>
<action>deny</action>
<log-end>yes</log-end>
</entry>
<!-- Default deny all -->
<entry name="Default_Deny">
<from><member>any</member></from>
<to><member>any</member></to>
<source><member>any</member></source>
<destination><member>any</member></destination>
<application><member>any</member></application>
<service><member>any</member></service>
<action>deny</action>
<log-end>yes</log-end>
</entry>
</rules>
</security>
</rulebase>
</entry>
</vsys>
</entry>
</devices>
</config>

4.3 Open-Source Alternative: Tofino Firewall Configuration
# tofino_modbus_filter.py
# Hirschmann Tofino LSM (Loadable Security Module)
# Filters Modbus traffic based on function codes
from scapy.all import *

from scapy.contrib.modbus import *
class ModbusFirewall:
"""
Software-based Modbus firewall for educational purposes
Production environments should use hardware industrial firewalls
"""
def __init__(self, trusted_sources, allowed_function_codes):
self.trusted_sources = trusted_sources
self.allowed_function_codes = allowed_function_codes
self.blocked_count = 0
self.allowed_count = 0
def inspect_modbus_packet(self, packet):
"""Deep packet inspection on Modbus TCP"""
if not packet.haslayer(ModbusADURequest) and not
packet.haslayer(ModbusADUResponse):
return True # Not Modbus, pass through
# Extract source IP
src_ip = packet[IP].src
# Check source authorization
if src_ip not in self.trusted_sources:
self.log_violation(packet, reason="Untrusted source")
self.blocked_count += 1
return False
# Check function code
if packet.haslayer(ModbusADURequest):
func_code = packet[ModbusADURequest].funcCode
if func_code not in self.allowed_function_codes.get(src_ip, []):
self.log_violation(packet, reason=f"Unauthorized function code {func_code}")
self.blocked_count += 1
return False
# Check for suspicious patterns
if self.detect_attack_patterns(packet):
self.log_violation(packet, reason="Attack pattern detected")
self.blocked_count += 1
return False
self.allowed_count += 1
return True

def detect_attack_patterns(self, packet):
"""Detect known Modbus attack patterns"""
if packet.haslayer(ModbusADURequest):
req = packet[ModbusADURequest]
# Check for excessive register read (recon)
if hasattr(req, 'quantity') and req.quantity > 100:
return True # Potential reconnaissance
# Check for diagnostic function codes (used in scanning)
if req.funcCode == 0x08: # Diagnostics
return True
# Check for program download function (S7comm)
# (Would need S7comm parser for full implementation)
return False
def log_violation(self, packet, reason):
"""Log security policy violation"""
print(f"[BLOCK] {packet[IP].src}:{packet[TCP].sport} -> "
f"{packet[IP].dst}:{packet[TCP].dport} | {reason}")
# In production: send to SIEM
# syslog.send(f"Modbus violation: {reason}", severity="WARNING")
def get_statistics(self):
"""Return firewall statistics"""
total = self.allowed_count + self.blocked_count
block_rate = (self.blocked_count / total * 100) if total > 0 else 0
return {
'allowed': self.allowed_count,
'blocked': self.blocked_count,
'total': total,
'block_rate_percent': block_rate
}
# Example configuration
if __name__ == '__main__':
# Define trusted sources and their allowed function codes
firewall = ModbusFirewall(
trusted_sources=['10.20.30.50', '10.20.30.100'],
allowed_function_codes={
'10.20.30.50': [1, 2, 3, 4], # SCADA: Read coils, inputs, holdings, input registers
'10.20.30.100': [1, 2, 3, 4, 5, 6, 15, 16, 23] # EWS: Read + Write
}

)
# Capture and filter traffic (inline mode)
def packet_callback(packet):
if packet.haslayer(TCP) and packet[TCP].dport == 502:
if not firewall.inspect_modbus_packet(packet):
# Drop packet (would require iptables integration in production)
return
# Forward allowed packets
send(packet)
sniff(iface='eth0', prn=packet_callback, filter='tcp port 502')

5. Secure Remote Access Architecture
5.1 Challenges
OT environments often require remote access for:
●​
●​
●​
●​

Vendor support
Remote engineering
After-hours monitoring
Multi-site management

However, remote access introduces risk:
●​
●​
●​
●​

VPN vulnerabilities (Module 2 covers VPN exploits)
Stolen credentials
Insider threats
Persistence via remote access tools

5.2 Defense-in-Depth Remote Access
┌────────────────────────────────────────────────────────
─────┐
│ Remote Engineer
│
│ - Corporate laptop
│
└────────────────────────────────────────────────────────
─────┘
│
│ VPN (1) - MFA required
▼
┌────────────────────────────────────────────────────────
─────┐
│ VPN Gateway (DMZ)
│
│ - Certificate-based authentication
│
│ - MFA (hardware token or biometric)
│
│ - Time-based access (business hours only)
│

└────────────────────────────────────────────────────────
─────┘
│
│ Firewall (2) - Source IP whitelist
▼
┌────────────────────────────────────────────────────────
─────┐
│ Jump Box / Bastion Host (DMZ)
│
│ - Hardened Windows Server
│
│ - Application whitelisting (only TIA Portal, RSLogix allowed)│
│ - Session recording (all RDP sessions logged)
│
│ - No internet access
│
│ - EDR agent (CrowdStrike, SentinelOne)
│
└────────────────────────────────────────────────────────
─────┘
│
│ Firewall (3) - Destination whitelist
▼
┌────────────────────────────────────────────────────────
─────┐
│ OT Network (Level 2/3)
│
│ - Access only to specific PLCs
│
│ - Session timeout: 4 hours max
│
│ - All actions logged to SIEM
│
└────────────────────────────────────────────────────────
─────┘

5.3 Implementation: VPN with MFA
#!/bin/bash
# configure_ot_vpn.sh
# Configure Cisco ASA or pfSense for OT remote access
# 1. Create separate VPN pool for OT access
configure terminal
ip local pool OT_REMOTE_POOL 10.20.99.100-10.20.99.200 mask 255.255.255.0
# 2. Enable certificate-based authentication
crypto ca trustpoint OT_VPN_CA
enrollment url http://ca.company.com:80
subject-name CN=ot-vpn-user
revocation-check crl
rsakeypair OT_VPN_KEY 2048
# 3. Configure group policy with restrictions
group-policy OT_REMOTE_ACCESS internal
group-policy OT_REMOTE_ACCESS attributes
vpn-tunnel-protocol ssl-client

split-tunnel-policy tunnelspecified
split-tunnel-network-list value OT_NETWORKS_ONLY
vpn-idle-timeout 30 # Disconnect after 30 min idle
vpn-session-timeout 240 # Max 4 hour session
# 4. Enable MFA (Duo or RSA SecurID)
aaa-server DUO_MFA protocol radius
aaa-server DUO_MFA host api.duosecurity.com
key <SECRET_KEY>
# 5. Create tunnel group
tunnel-group OT_REMOTE_VPN type remote-access
tunnel-group OT_REMOTE_VPN general-attributes
address-pool OT_REMOTE_POOL
authentication-server-group DUO_MFA
default-group-policy OT_REMOTE_ACCESS
# 6. ACL for split tunneling (only OT networks)
access-list OT_NETWORKS_ONLY standard permit 10.20.10.0 255.255.255.0 # PLCs
access-list OT_NETWORKS_ONLY standard permit 10.20.30.0 255.255.255.0 # SCADA
access-list OT_NETWORKS_ONLY standard deny any
# 7. Time-based access control (business hours only)
time-range BUSINESS_HOURS
periodic weekdays 06:00 to 18:00
periodic weekend 08:00 to 12:00
access-list VPN_TO_OT extended permit ip 10.20.99.0 255.255.255.0 10.20.10.0
255.255.255.0 time-range BUSINESS_HOURS
access-list VPN_TO_OT extended deny ip any any
# 8. Logging
logging enable
logging trap informational
logging host dmz 10.20.40.50 # SIEM server

5.4 Jump Box Hardening
# harden_jump_box.ps1
# Harden Windows Server 2019/2022 jump box for OT access
# 1. Enable AppLocker (application whitelisting)
$RuleCollection = @"
<AppLockerPolicy Version="1">
<RuleCollection Type="Exe" EnforcementMode="Enabled">
<!-- Allow TIA Portal -->
<FilePathRule Id="TIA_PORTAL" Name="Siemens TIA Portal"
UserOrGroupSid="S-1-5-32-545" Action="Allow">

<Conditions>
<FilePathCondition Path="C:\Program Files\Siemens\Automation\Portal V17\*" />
</Conditions>
</FilePathRule>
<!-- Allow RSLogix -->
<FilePathRule Id="RSLOGIX" Name="Rockwell RSLogix 5000"
UserOrGroupSid="S-1-5-32-545" Action="Allow">
<Conditions>
<FilePathCondition Path="C:\Program Files (x86)\Rockwell Software\RSLogix 5000\*"
/>
</Conditions>
</FilePathRule>
<!-- Allow System binaries -->
<FilePathRule Id="SYSTEM" Name="Windows System" UserOrGroupSid="S-1-1-0"
Action="Allow">
<Conditions>
<FilePathCondition Path="%WINDIR%\*" />
<FilePathCondition Path="%PROGRAMFILES%\*" />
</Conditions>
</FilePathRule>
<!-- Deny everything else -->
<FilePathRule Id="DENY_ALL" Name="Deny All" UserOrGroupSid="S-1-1-0"
Action="Deny">
<Conditions>
<FilePathCondition Path="*" />
</Conditions>
</FilePathRule>
</RuleCollection>
</AppLockerPolicy>
"@
$RuleCollection | Out-File C:\applocker_policy.xml
Set-AppLockerPolicy -XMLPolicy C:\applocker_policy.xml
# 2. Disable USB storage
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name
"Start" -Value 4
# 3. Enable PowerShell logging
$RegPath =
"HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $RegPath -Force
Set-ItemProperty -Path $RegPath -Name "EnableScriptBlockLogging" -Value 1
# 4. Configure firewall (whitelist only specific OT devices)

Remove-NetFirewallRule -All # Clear all rules
New-NetFirewallRule -DisplayName "Allow SCADA Server" -Direction Outbound
-RemoteAddress 10.20.30.50 -Action Allow
New-NetFirewallRule -DisplayName "Allow PLC Network" -Direction Outbound
-RemoteAddress 10.20.10.0/24 -Action Allow
New-NetFirewallRule -DisplayName "Block Internet" -Direction Outbound -RemoteAddress
0.0.0.0/0 -Action Block
# 5. Enable RDP session recording
# Requires third-party tool like Observeit or native Windows Session Recording
# 6. Install EDR agent
Start-Process "\\file-server\EDR\CrowdStrike-Installer.exe" -ArgumentList "/quiet" -Wait
# 7. Disable unnecessary services
$ServicesToDisable = @(
"RemoteRegistry",
"WinRM",
"SSDPSRV", # SSDP Discovery
"upnphost" # UPnP
)
foreach ($service in $ServicesToDisable) {
Stop-Service -Name $service -Force
Set-Service -Name $service -StartupType Disabled
}
# 8. Enable audit logging
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"File System" /success:enable /failure:enable
Write-Host "Jump box hardening complete"

6. Hands-On Lab: Design and Implement Network
Segmentation
Lab Environment
Objective: Design and deploy network segmentation for a small water treatment plant
Assets:
●​
●​
●​
●​

3 PLCs (Siemens S7-1200)
1 SCADA server (Windows Server 2019 + Ignition SCADA)
1 Engineering workstation (Windows 10 + TIA Portal)
1 Historian server (Windows Server 2019 + OSIsoft PI)

●​ Corporate IT network (assume compromised)
Requirements:
●​
●​
●​
●​

Implement 5-level Purdue architecture
Configure industrial firewall with whitelist rules
Deploy unidirectional gateway for historian
Establish secure remote access

Lab Steps
Step 1: Network Design
Create network diagram in draw.io or Visio:
[Corporate IT: 10.100.0.0/16]
|
[Firewall 1]
|
[DMZ: 10.20.40.0/24]
- Historian: 10.20.40.10
- VPN Gateway: 10.20.40.30
|
[Data Diode] (unidirectional)
|
[Operations: 10.20.30.0/24]
- SCADA: 10.20.30.50
- EWS: 10.20.30.100
|
[Firewall 2] (DPI)
|
[Control: 10.20.10.0/24]
- PLC1: 10.20.10.10
- PLC2: 10.20.10.11
- PLC3: 10.20.10.12
Step 2: Configure VLANs
# Cisco switch configuration
enable
configure terminal
# Create VLANs
vlan 10
name OT_Control
vlan 30
name OT_Operations
vlan 40
name Industrial_DMZ

vlan 100
name Corporate_IT
# Assign ports to VLANs
interface range GigabitEthernet1/0/1-3
switchport mode access
switchport access vlan 10
description PLCs
interface GigabitEthernet1/0/10
switchport mode access
switchport access vlan 30
description SCADA_Server
interface GigabitEthernet1/0/20
switchport mode access
switchport access vlan 40
description Historian_DMZ
# Trunk to firewall
interface GigabitEthernet1/0/48
switchport mode trunk
switchport trunk allowed vlan 10,30,40,100
description Trunk_to_Firewall
Step 3: Configure Industrial Firewall
Use pfSense or Palo Alto:
# pfSense firewall rules (Operations -> Control)
# Allow SCADA to read from PLCs (Modbus read only)
pass in on OT_OPERATIONS proto tcp from 10.20.30.50 to 10.20.10.0/24 port 502 \
modbus_filter(allow_read=true, allow_write=false) \
label "SCADA_READ_PLCs"
# Allow EWS to program PLCs (S7comm)
pass in on OT_OPERATIONS proto tcp from 10.20.30.100 to 10.20.10.0/24 port 102 \
schedule "BUSINESS_HOURS" \
label "EWS_PROGRAM_PLCs"
# Block all other traffic to PLCs
block in on OT_OPERATIONS to 10.20.10.0/24 label "DEFAULT_DENY_PLCs"
# Block internet from OT networks
block out on WAN from {10.20.10.0/24, 10.20.30.0/24} to any label
"BLOCK_OT_INTERNET"

Step 4: Deploy Data Diode
Install Python scripts from Section 3.3 on gateway appliance:
# On OT-side gateway (10.20.30.200)
sudo apt install python3 python3-pip
pip3 install python-snap7 opcua
# Run diode proxy
python3 data_diode_proxy.py &
# On IT-side receiver (10.20.40.10)
python3 diode_receiver.py &
Step 5: Configure Secure Remote Access
# Install and configure OpenVPN server on DMZ gateway
apt install openvpn easy-rsa
# Generate certificates
make-cadir ~/openvpn-ca
cd ~/openvpn-ca
./easyrsa init-pki
./easyrsa build-ca
./easyrsa build-server-full server nopass
./easyrsa build-client-full vendor-engineer nopass
# Configure server
cat > /etc/openvpn/server.conf <<EOF
port 1194
proto udp
dev tun
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh.pem
server 10.20.99.0 255.255.255.0
push "route 10.20.30.0 255.255.255.0" # Operations network
push "route 10.20.10.0 255.255.255.0" # Control network
client-to-client
keepalive 10 120
cipher AES-256-CBC
auth SHA256
user nobody
group nogroup
persist-key
persist-tun

status /var/log/openvpn-status.log
log-append /var/log/openvpn.log
verb 3
# Require MFA (via Duo proxy)
auth-user-pass-verify /usr/local/bin/duo_openvpn.py via-env
EOF
systemctl start openvpn@server
Step 6: Test and Validate
# validation_tests.py
# Verify network segmentation is working correctly
import socket
import subprocess
import sys
def test_connectivity(src_desc, dst_ip, dst_port, should_succeed):
"""Test if connection succeeds/fails as expected"""
try:
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(2)
result = sock.connect_ex((dst_ip, dst_port))
sock.close()
success = (result == 0)
expected = should_succeed
status = "PASS" if (success == expected) else "FAIL"
print(f"[{status}] {src_desc} -> {dst_ip}:{dst_port} | "
f"Expected: {'Success' if expected else 'Block'}, Got: {'Success' if success else
'Block'}")
return status == "PASS"
except Exception as e:
print(f"[ERROR] {src_desc} -> {dst_ip}:{dst_port} | {e}")
return False
def run_validation():
"""Run full validation suite"""
tests = [
# Test 1: SCADA should reach PLCs on Modbus
("SCADA to PLC1 Modbus", "10.20.10.10", 502, True),
# Test 2: SCADA should reach PLCs on S7comm
("SCADA to PLC1 S7comm", "10.20.10.10", 102, True),

# Test 3: PLCs should NOT reach internet
("PLC1 to Internet", "8.8.8.8", 80, False),
# Test 4: PLCs should NOT reach corporate IT
("PLC1 to Corporate IT", "10.100.10.10", 445, False),
# Test 5: Historian should receive data (one-way)
("Operations to Historian", "10.20.40.10", 5000, True),
# Test 6: Historian should NOT send to OT (data diode blocks)
("Historian to SCADA", "10.20.30.50", 445, False),
]
passed = 0
failed = 0
print("Running network segmentation validation tests...\n")
for test in tests:
if test_connectivity(*test):
passed += 1
else:
failed += 1
print(f"\nResults: {passed} passed, {failed} failed")
if failed == 0:
print("Network segmentation validation SUCCESSFUL")
return 0
else:
print("Network segmentation validation FAILED - review firewall rules")
return 1
if __name__ == '__main__':
sys.exit(run_validation())

Lab Deliverables
1.​ Network architecture diagram (Purdue Model)
2.​ VLAN configuration file
3.​ Firewall ruleset with justifications
4.​ Data diode configuration (OT and IT sides)
5.​ VPN configuration with MFA
6.​ Validation test results

7. Real-World Case Studies

7.1 Ukraine Power Grid Attack (2015)
Attack Vector: Spear-phishing led to compromise of corporate IT network
Lateral Movement: Attackers pivoted from corporate network to OT network due to lack of
segmentation
Impact: 225,000 customers lost power for 6 hours
Segmentation Failures:
●​
●​
●​
●​

No DMZ between IT and OT
Flat network topology
VPN access directly to SCADA network
No unidirectional gateways

Lessons:
●​ Segmentation would have contained breach to IT network
●​ Data diode would have prevented IT-to-OT lateral movement
●​ Industrial firewall with DPI could have detected malicious S7comm traffic

7.2 Triton/Trisis Malware (2017)
Attack: Nation-state malware targeting Schneider Electric Triconex safety systems
Network Position: Attackers reached safety PLCs from engineering workstation
Segmentation Issue: Engineering workstation had access to both corporate network
(email/internet) and safety PLCs
Proper Segmentation Would Have:
●​ Isolated safety PLCs on separate physical network
●​ Required jump box for engineering access (would have detected malware)
●​ Prevented workstation from having simultaneous IT and OT connectivity

7.3 Colonial Pipeline Ransomware (2021)
Attack: DarkSide ransomware via VPN credential compromise
Segmentation Failure: VPN credentials provided access to OT network
Impact: 5,500-mile pipeline shut down for 6 days, fuel shortages across US East Coast
Defense: Proper DMZ with jump boxes would have:
●​ Limited VPN access to DMZ only, not directly to OT
●​ Enabled session recording to detect malicious activity
●​ Provided kill switch to disconnect remote access during incident

8. Tools and Resources
Network Segmentation Design
●​ CSET (Cyber Security Evaluation Tool): Free tool from CISA for assessing ICS
network architecture
●​ ISA Secure System Security Assurance: Templates for 62443 implementation
●​ Purdue Model Templates: Available from Rockwell Automation, Siemens

Industrial Firewalls
●​
●​
●​
●​
●​

Palo Alto PA-Series: Deep packet inspection for ICS protocols
Fortinet FortiGate: ICS-focused firewall with OT protocol parsers
Cisco Firepower: Industrial security with Snort integration
Tofino Xenon: Specialized ICS firewall (Hirschmann/Belden)
Open-Source: pfSense with custom rules, Snort/Suricata with ICS plugins

Unidirectional Gateways
●​
●​
●​
●​

Waterfall Security Solutions: Unidirectional CloudConnect
Owl Cyber Defense: OPDS (Optical Data Diode)
BAE Systems: Unidirectional Gateway
DIY Data Diode: Raspberry Pi-based educational projects

Remote Access Solutions
●​
●​
●​
●​

CyberArk Privileged Access Security: For jump box session management
BeyondTrust: Privileged remote access for OT
Dispel: Secure OT remote access platform
Claroty Secure Remote Access: Purpose-built for industrial environments

Standards and Guidelines
●​
●​
●​
●​

ISA/IEC 62443: Industrial security standards (zones and conduits)
NIST SP 800-82: Guide to Industrial Control Systems Security
NERC CIP: Critical Infrastructure Protection standards (power sector)
NIS Directive: Network and Information Systems Directive (EU)

Conclusion
Network segmentation is the foundation of OT cybersecurity defense. By implementing:
●​
●​
●​
●​
●​

Purdue Model architecture with clearly defined zones
ISA/IEC 62443 security levels and conduit enforcement
Unidirectional gateways to prevent IT-to-OT lateral movement
Industrial firewalls with deep packet inspection
Secure remote access with defense-in-depth

Organizations can significantly reduce the attack surface and contain incidents when they
occur. In the next lesson, we'll build on this foundation by deploying intrusion detection
systems to monitor traffic between these segmented zones.

