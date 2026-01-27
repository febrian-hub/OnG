Lesson 05: Incident Detection and
Threat Hunting

Lesson 05: Incident Detection and Threat
Hunting in OT
Industrial Threat Hunting, Live Detection, and Active Defense

Why This Lesson Matters
In OT environments, incident detection is rarely about catching noisy malware.​
Most real-world attacks against industrial systems are slow, quiet, and deliberate.
Adversaries prioritize:
●​
●​
●​
●​

Stealth
Persistence
Long-term access
Minimal operational disruption until objectives are achieved

Threat hunting in OT is therefore not reactive.​
It is a proactive discipline focused on finding what should not exist in stable environments.
In industrial networks, normal rarely changes.​
This makes threat hunting extremely powerful when done correctly.

Learning Outcomes
After completing this lesson, the student will be able to:
●​
●​
●​
●​
●​
●​
●​

Detect active and dormant attacks in ICS environments
Build hypothesis-driven OT threat hunts
Identify abnormal industrial protocol behavior
Detect compromised engineering and operator workstations
Identify indicators of compromise specific to OT
Respond safely to security events without disrupting production
Support containment and recovery with minimal operational risk

1. Threat Hunting in ICS Environments

1.1 Threat Hunting Philosophy in OT
Threat hunting in IT often relies on:
●​ Malware signatures
●​ Known IOCs
●​ Automated detection rules
Threat hunting in OT relies on:
●​
●​
●​
●​

Stability
Determinism
Behavioral consistency
Process awareness

Key principle:​
If something is new, it deserves investigation.

1.2 Hunt Preparation
Before hunting begins, the environment must have:
●​
●​
●​
●​
●​

A documented network architecture
Asset inventory of PLCs, HMIs, servers, and workstations
Known-good baselines for traffic and behavior
Defined operational windows
Clear escalation paths with operations teams

Hunting without baselines leads to false conclusions.

2. ICS Threat Hunting Methodology
2.1 Hypothesis-Driven Hunting
Threat hunting starts with a hypothesis based on realistic adversary behavior.
A good hypothesis:
●​
●​
●​
●​

Is specific
Is testable
Maps to real attack techniques
Produces measurable results

2.2 Example Hunt Hypotheses
Hypothesis 1: Adversary is conducting reconnaissance via Modbus scan
Assumptions:
●​ Adversary is mapping registers and devices
●​ Increased read requests across multiple addresses
●​ Activity originates from non-PLC assets
Expected Evidence:
●​ Spike in Modbus read requests
●​ Sequential register access
●​ New source IPs interacting with PLCs

Hypothesis 2: Engineering workstation is compromised and beaconing to C2
Assumptions:
●​ Compromised workstation communicates periodically
●​ Outbound traffic pattern is consistent
●​ Destination is external or unexpected
Expected Evidence:
●​ Periodic connections
●​ Small, consistent packet sizes
●​ Communication outside normal maintenance windows

Hypothesis 3: PLC logic has been modified to include a backdoor
Assumptions:
●​ Logic has changed without approved maintenance
●​ Change persists across restarts
●​ No corresponding change ticket exists
Expected Evidence:
●​ Hash mismatch in PLC logic
●​ Upload events from unapproved sources
●​ Logic blocks that are unused or hidden

Hypothesis 4: Man-in-the-middle attack between SCADA and PLC

Assumptions:
●​ Traffic is intercepted or modified
●​ Latency or retransmissions increase
●​ PLC responses differ from expected values
Expected Evidence:
●​
●​
●​
●​

Duplicate packets
Unexpected MAC address changes
ARP instability
Timing anomalies

3. Hunting Techniques in OT
3.1 Network Traffic Analysis
Network visibility is the most reliable hunting surface in OT.
Passive monitoring is preferred.

Baseline Comparison for Connections
tshark -r current.pcap -T fields -e ip.src -e ip.dst -e tcp.port | sort -u > current_conns.txt
diff baseline_conns.txt current_conns.txt

Purpose:
●​ Identify new hosts
●​ Detect unexpected communication paths
●​ Reveal lateral movement
Interpretation:
●​ Any new connection must be explained
●​ Focus on traffic crossing zone boundaries

Protocol Discovery
tshark -r current.pcap -q -z io,phs

Purpose:

●​ Identify new or unexpected protocols
●​ Detect tunneling or covert channels
Interpretation:
●​ ICS environments rarely introduce new protocols
●​ New protocol usage is suspicious by default

Beaconing Detection
zeek -r current.pcap detect_beaconing.zeek

Purpose:
●​ Identify periodic communication
●​ Detect command-and-control behavior
Interpretation:
●​ Consistent timing patterns indicate automation
●​ Even internal beaconing can indicate persistence

3.2 Industrial Protocol Behavioral Analysis
Focus areas:
●​
●​
●​
●​

Write operations
Function code frequency
Command sequencing
Timing anomalies

Examples of suspicious behavior:
●​
●​
●​
●​

Writes outside maintenance windows
Diagnostic function usage
Rapid register cycling
Repeated force commands

3.3 File Integrity Monitoring for PLC Logic
PLC logic is equivalent to executable code.
Any change must be justified.

import snap7
import hashlib
def monitor_plc_integrity(plc_ip, baseline_hash):
plc = snap7.client.Client()
plc.connect(plc_ip, 0, 1)
ob1 = plc.upload('OB', 1)
current_hash = hashlib.sha256(ob1).hexdigest()
if current_hash != baseline_hash:
print("[!] ALERT: PLC logic has changed!")
print(f"Baseline: {baseline_hash}")
print(f"Current: {current_hash}")
return False
plc.disconnect()
return True

Operational Notes:
●​ Baseline hashes must be captured during trusted states
●​ Hash checks should be scheduled and controlled
●​ Any mismatch requires engineering validation

4. Indicators of Compromise in OT
4.1 Common OT-Specific IOCs
Network Indicators:
●​ Unknown IPs communicating with PLCs
●​ Communication outside defined zones
●​ ARP instability or duplicate MACs
System Indicators:
●​ New user accounts in SCADA systems
●​ Unexpected services or processes on HMI
●​ Unauthorized scheduled tasks
Controller Indicators:
●​ Modified PLC firmware
●​ Unexpected program blocks

●​ Logic changes without downtime
Protocol Indicators:
●​ Use of diagnostic or rarely used function codes
●​ Write commands from non-engineering hosts
●​ Excessive polling behavior

4.2 IOC Context Is Critical
In OT, an IOC alone is not enough.
Every indicator must be evaluated against:
●​
●​
●​
●​

Operational schedules
Maintenance activities
Engineering workflows
Safety constraints

False positives are dangerous if they trigger unsafe responses.

5. Responding to OT Security Events
5.1 Detection Does Not Mean Immediate Containment
In IT, containment often means isolation.
In OT, containment may:
●​ Stop production
●​ Trigger safety shutdowns
●​ Cause physical damage
Response must be deliberate.

5.2 Safe Response Workflow
1.​ Validate the alert
2.​ Correlate with process state
3.​ Notify operations and engineering
4.​ Assess safety impact
5.​ Contain only if risk outweighs disruption
6.​ Preserve evidence

7.​ Document all actions

5.3 When Immediate Action Is Required
Immediate action is justified when:
●​
●​
●​
●​

Safety systems are targeted
Control logic is actively manipulated
Physical damage is imminent
Human safety is at risk

In these cases, security takes precedence over availability.

6. Hands-On Labs
Lab 1: Unauthorized Modbus Write Hunt
●​ Identify write operations
●​ Attribute source hosts
●​ Validate legitimacy

Lab 2: PLC Logic Baseline
●​ Capture trusted hashes
●​ Detect unauthorized changes

Lab 3: Rogue Device Detection
●​ Identify new MAC and IP addresses
●​ Trace physical origin

Lab 4: SCADA Server Investigation
●​ Analyze running processes
●​ Identify persistence mechanisms

Lab 5: IOC Database Construction
●​ Collect indicators from simulated attacks
●​ Classify by type and severity
●​ Prepare for SIEM ingestion

Key Takeaways
●​
●​
●​
●​
●​
●​

Threat hunting in OT relies on stability and predictability
Hypothesis-driven hunts reduce noise
Network telemetry is the most reliable hunting surface
PLC logic integrity is mission critical
Response actions must prioritize safety
Coordination with operations is mandatory

