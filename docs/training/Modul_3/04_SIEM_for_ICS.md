Lesson 04: SIEM for ICS
Environments

Lesson 04: SIEM for ICS Environments
Industrial-Grade Detection, Correlation, and Investigation

Why This Lesson Matters
In IT environments, SIEM platforms are primarily used to detect data breaches, malware,
privilege abuse, and service disruption.
In industrial environments, SIEM platforms protect physical processes, human safety,
production continuity, regulatory compliance, and critical infrastructure.
A missed alert in an IT environment may result in data loss or downtime.
A missed alert in an ICS environment may result in explosions, blackouts, chemical leaks,
contaminated water, destroyed equipment, or loss of life.
Because of this, SIEM design, alert logic, and incident response in ICS environments must
follow a completely different mindset.
This lesson is intentionally deep, operational, and realistic.

Learning Outcomes
After completing this lesson, the student will be able to:
●​
●​
●​
●​
●​
●​
●​
●​
●​

Design an ICS-aware SIEM architecture without disrupting operations
Identify and prioritize critical OT log sources
Normalize industrial telemetry into security-relevant events
Build behavioral baselines for industrial networks and processes
Detect malicious, unsafe, and abnormal control actions
Correlate IT compromise with OT process impact
Perform forensic reconstruction of industrial security incidents
Distinguish false positives from real operational risk
Communicate findings to engineers, SOC analysts, and executive leadership

1. SIEM in ICS Environments

1.1 How ICS Monitoring Differs from IT Monitoring
Aspect

IT Environment

ICS Environment

Primary Risk

Data loss

Physical damage

Protected Assets

Users, servers, databases

PLCs, sensors, actuators

Change Frequency

High

Extremely low

Baseline Stability

Dynamic

Static

Time Sensitivity

Minutes to hours

Seconds

Tolerance for Scanning

High

Often prohibited

Incident Impact

Service degradation

Safety and production loss

Key principle:​
In industrial environments, any change is suspicious until proven legitimate.

1.2 The Role of SIEM in Industrial Defense
SIEM does not replace firewalls, safety PLCs, physical controls, or segmentation.
SIEM provides visibility, correlation, historical context, and forensic timelines.
In ICS environments, SIEM acts as the system of record for security-relevant operational
behavior.

2. SIEM Platforms Used in ICS
2.1 Commonly Deployed Platforms
●​ Splunk​
Strong correlation capabilities and extensive OT ecosystem​
●​ IBM QRadar​
Asset-centric correlation and mature forensic workflows​
●​ Elastic Stack​
Highly flexible and cost-effective, but requires engineering effort​

●​ Microsoft Sentinel​
Strong IT and identity correlation, commonly used in hybrid environments​

2.2 Criteria for Selecting a SIEM for ICS
A SIEM suitable for industrial environments must support:
●​
●​
●​
●​
●​
●​

Industrial protocol visibility
Asset-based correlation
Low-latency ingestion
Long-term forensic retention
Strict access control and auditability
Non-intrusive data collection methods

3. Industrial Log Sources
3.1 OT-Critical Log Sources
PLC and Controller Logs
●​
●​
●​
●​

Program download and upload events
Firmware changes
Force and override actions
Safety logic modifications

These logs are among the highest-value signals in ICS security.

HMI and Operator Interface Logs
●​
●​
●​
●​

Manual control commands
Alarm acknowledgments
Setpoint changes
Mode switches

Operator behavior is a critical signal for both insider threat and compromised credentials.

SCADA and Historian Logs
●​ Tag value changes
●​ Alarm generation

●​ Communication failures
●​ Data integrity errors
These logs help correlate cyber activity with physical process impact.

Network Security Logs
●​ Firewall allow and deny events
●​ Zone boundary crossings
●​ Protocol violations
Segmentation violations are often early indicators of lateral movement.

Network Detection and Protocol Analysis
●​ Zeek industrial protocol logs
●​ IDS alerts
●​ Deep packet inspection events
These logs provide protocol-level visibility without touching endpoints.

Access and Authentication Logs
●​
●​
●​
●​

VPN connections
Jump server access
Windows authentication events
Privileged access usage

These logs bridge IT identity with OT actions.

3.2 Log Collection Methods
Only non-intrusive collection methods are acceptable in ICS environments.
Approved approaches include:
●​
●​
●​
●​

Syslog forwarding from network devices
File-based log collection from servers
API-based ingestion from vendor platforms
Network traffic monitoring via SPAN or TAP

Agents must never be installed on PLCs or safety controllers.

4. ICS-Specific Detection Use Cases
Use Case 1: Unauthorized PLC Program Change
A PLC program download occurs from a workstation that is not part of the approved
engineering environment.
This behavior often indicates malware infection, credential theft, or insider misuse.
Immediate validation of program integrity is required.

Use Case 2: Excessive Control Write Operations
A single host performs an unusually high number of write operations within a short time
window.
This pattern is commonly associated with automation abuse, replay attacks, or protocol
fuzzing.

Use Case 3: Off-Hours OT Access
Remote access to the OT environment occurs outside approved operational windows.
This may indicate stolen credentials, compromised VPN access, or unauthorized
maintenance activity.

Use Case 4: New Device on the OT Network
A previously unseen MAC address or IP address appears in the OT network.
This is often caused by unauthorized laptops, compromised engineering devices, or rogue
wireless bridges.

Use Case 5: Authentication Failure Spikes
Repeated failed authentication attempts occur against SCADA or jump systems.
This behavior frequently precedes successful compromise.

Use Case 6: Safety System Manipulation
Write operations target safety-related registers or logic.
This is one of the highest severity alerts possible in an ICS environment and requires
immediate action.

5. Correlation Logic Examples
Unauthorized PLC Programming Detection
index=ics sourcetype=s7comm function_code IN (0x1B, 0x28)
| where src_ip NOT IN ("10.10.1.100", "10.10.1.101")
| stats count by src_ip, dest_ip, function_code

This rule detects unauthorized PLC program download attempts.

After-Hours OT Access Detection
index=vpn earliest=-1h
| eval hour=strftime(_time, "%H")
| where hour < 8 OR hour > 18
| table _time, user, src_ip, dest_ip

This rule identifies access outside defined operational hours.

IT to OT Attack Chain Correlation
(index=windows EventCode=4624 OR EventCode=4672)
| join user [ search index=ics sourcetype=modbus function="write" ]
| stats count by user, src_ip, dest_ip

This rule correlates privileged IT access with OT control actions.

6. Industrial Incident Investigation

Investigation Objectives
●​
●​
●​
●​
●​

Identify who initiated the action
Determine how access was obtained
Assess whether changes were manual or automated
Confirm physical process impact
Validate safety system integrity

Evidence Sources
●​
●​
●​
●​
●​

SIEM event timelines
PLC backups and logic versions
Network packet captures
Operator action logs
Historian process data

Preservation Rules
●​
●​
●​
●​

Do not reboot controllers unless required for safety
Preserve logs in read-only format
Maintain chain of custody
Coordinate actions with operations and engineering teams

7. Hands-On Labs
1.​ Deploy an ELK stack for OT monitoring
2.​ Ingest Zeek industrial protocol logs
3.​ Build five ICS-specific detection rules
4.​ Correlate a multi-stage IT to OT attack
5.​ Test alerts using simulated industrial attacks

Final Takeaways
●​
●​
●​
●​
●​

SIEM in ICS environments is about process integrity, not just security
Stability is the baseline
Correlation across IT and OT reveals real attack paths
Safety and availability always override automation
SIEM supports decision-making, not autonomous response

