# Exfiltration Over C2 Channel: [T1041](https://attack.mitre.org/techniques/T1041/)

## Detection Explanation

Exfiltration Over C2 Channel involves adversaries using their existing command and control infrastructure to steal data from compromised networks. This technique enables attackers to consolidate their communication channels, simplify their operational security, and leverage already-established covert channels that have evaded detection. By using the same infrastructure for both command execution and data exfiltration, adversaries reduce their network footprint and avoid creating additional suspicious connections that might alert security teams.

Attackers prefer exfiltration over C2 channels because it provides operational efficiency, uses trusted communication paths that have already bypassed security controls, and reduces the complexity of managing multiple exfiltration methods. The C2 channel may use common protocols like HTTP/HTTPS, DNS, or custom protocols, and often employs encryption, encoding, or obfuscation to hide exfiltrated data within normal-appearing C2 traffic. This technique is commonly used throughout the exfiltration phase and may continue for extended periods as attackers systematically steal data.

Successful exfiltration over C2 channels enables attackers to steal sensitive data while maintaining a low profile, using communication paths that security tools have already permitted. This technique is particularly effective because it blends data exfiltration with command and control traffic, making it difficult to distinguish malicious data transfers from normal C2 communications. The impact includes theft of intellectual property, customer data, credentials, financial records, and other sensitive information, with exfiltration often going undetected for extended periods.

Detection requires monitoring for unusual data volumes in C2 communications, identifying changes in C2 traffic patterns, tracking file access and staging activities preceding C2 communications, and correlating outbound traffic characteristics with known C2 indicators. Organizations should establish baselines for expected C2 beacon behavior and alert on anomalies such as increased data transfer volumes, changes in communication frequency, large HTTP POST requests, DNS queries with unusual payloads, or sustained high-bandwidth C2 sessions.

---

## Key Detection Indicators & Areas to Investigate

### Summary of Indicators

1. Increased data volumes in established C2 communication channels
2. HTTP/HTTPS C2 with large POST requests or responses
3. DNS C2 channels with increased query frequency or size
4. Beacon timing changes indicating data exfiltration
5. File staging followed by C2 communication
6. Encrypted or encoded data in C2 traffic
7. Long-duration C2 sessions with high data transfer
8. C2 traffic pattern changes following data collection
9. Outbound data transfer during off-hours via C2
10. Multiple files exfiltrated through established C2

---

### 1. Increased Data Volumes in Established C2 Communication Channels

**Network Logs:**

- Firewall logs - Increased bandwidth usage to known C2 IP addresses
- Netflow/IPFIX - Traffic volume spikes to external hosts
- Proxy logs - Increased HTTP/HTTPS traffic to specific domains
- IDS/IPS - Traffic volume anomalies on C2 connections

**SIEM Correlation:**

- Baseline C2 traffic volume per connection
- Alert on traffic exceeding baseline by >200%
- Track cumulative data transfer to C2 infrastructure
- Monitor for sustained high-bandwidth sessions

**Sysmon:**

- Event ID 3 (Network connection) - Connection duration and frequency
- Correlate with known C2 process indicators

**Focus on:**

- C2 connections transferring significantly more data than baseline
- Sustained bandwidth usage rather than periodic beacons
- Gradual increase in data transfer over time
- Data transfer spikes following file access or collection activity
- Multiple exfiltration sessions to same C2 infrastructure

**Suspicious indicators:**

- C2 beacon traffic increasing from 1-2KB per connection to >100KB
- Sustained connections (>10 minutes) with continuous data transfer to C2 IPs
- Daily data transfer to C2 infrastructure exceeding 10MB (baseline may be <1MB)
- HTTP/HTTPS sessions to known C2 domains with responses >1MB
- Gradual escalation of exfiltration: Day 1 (50KB), Day 2 (500KB), Day 3 (5MB)
- C2 connections during business hours transferring more data than off-hours beacons
- Multiple large data transfers to same C2 IP within 24-hour period
- Process with known C2 behavior showing increased network activity
- C2 traffic volume correlating with archive creation or file staging activity
- Bandwidth usage to external IP matching known malware family C2 infrastructure

---

### 2. HTTP/HTTPS C2 with Large POST Requests or Responses

**Proxy Logs:**

- HTTP POST request sizes to external domains
- HTTP response sizes from known or suspicious external servers
- User-agent strings associated with malware
- URL patterns consistent with C2 communication

**Sysmon:**

- Event ID 3 (Network connection) - HTTP/HTTPS connections with unusual characteristics
- Process making HTTP connections with large data transfers

**Web Server Logs (if C2 is internal web service):**

- POST requests with large content-length headers
- Unusual URL paths or parameters
- Encoded or encrypted POST data

**Network Logs:**

- Firewall logs - HTTP/HTTPS traffic with large payload sizes
- IDS/IPS - HTTP POST patterns matching C2 frameworks
- TLS/SSL inspection - Encrypted POST data patterns

**Focus on:**

- HTTP POST requests >100KB to external domains
- Multiple sequential POST requests to same URI
- POST requests with base64, hex, or encrypted-looking data
- HTTP responses downloading large amounts of data
- POST requests from unexpected processes

**Suspicious indicators:**

- HTTP POST requests >500KB from workstations or servers to external IPs
- Sequential POST requests to same URL within minutes: `/update.php`, `/api/sync`, `/data`
- Content-Type headers: `application/octet-stream`, `application/x-www-form-urlencoded` with large bodies
- POST data containing base64-encoded content or binary data patterns
- User-agents matching known C2 frameworks: PowerShell Empire, Cobalt Strike, Metasploit
- POST requests to paths common in C2: `/submit.php`, `/upload`, `/api/data`, `/gate.php`
- HTTP responses from external servers with `Content-Length` >1MB
- Processes like `powershell.exe`, `rundll32.exe`, or unknown executables making large HTTP POSTs
- POST requests immediately following file staging or archive creation
- Multiple POST requests with incrementing IDs: `?id=1`, `?id=2`, `?id=3` (chunked exfiltration)

---

### 3. DNS C2 Channels with Increased Query Frequency or Size

**DNS Logs:**

- Query frequency to specific domains
- Query name lengths and patterns
- Query types (A, TXT, MX, NULL)
- Response sizes and content
- Number of unique subdomains queried

**Sysmon:**

- Event ID 22 (DNS query) - Query patterns and frequency
- Processes generating high volumes of DNS queries

**Network Logs:**

- Firewall logs - DNS traffic volume (UDP/TCP port 53)
- IDS/IPS - DNS tunneling signatures
- Netflow - DNS query counts and patterns

**Focus on:**

- Increased frequency of DNS queries to specific domain
- Longer DNS query names suggesting encoded data
- TXT record queries returning large responses
- DNS queries from unexpected processes
- Subdomain patterns suggesting data encoding

**Suspicious indicators:**

- DNS query frequency from single host exceeding 100 queries per minute to same domain
- Query names >50 characters with base64 or hex patterns: `ZGF0YWV4ZmlsdHJhdGlvbg==.attacker.com`
- TXT record queries from workstations or servers (not DNS infrastructure)
- DNS responses with TXT records >512 bytes containing encoded data
- Sequential queries with incrementing patterns: `part1.domain.com`, `part2.domain.com`
- DNS queries from processes other than standard applications: `powershell.exe`, custom executables
- Queries to newly registered domains with high entropy subdomain labels
- NULL or ANY record type queries from non-infrastructure systems
- DNS query volume spike correlating with file staging or collection activity
- Queries bypassing internal DNS servers (direct to external resolvers)

---

### 4. Beacon Timing Changes Indicating Data Exfiltration

**SIEM Correlation:**

- Establish baseline beacon intervals (e.g., every 60 seconds)
- Monitor for deviations from regular beacon timing
- Track connection duration changes
- Identify switch from periodic to sustained connections

**Network Logs:**

- Netflow - Connection timing and duration patterns
- Firewall logs - Connection establishment frequency
- IDS/IPS - Beacon pattern analysis

**Sysmon:**

- Event ID 3 (Network connection) - Connection timestamps
- Calculate intervals between connections

**Beacon Pattern Changes:**

- Regular beacons: 60s intervals, 1-2KB data
- Exfiltration mode: Irregular intervals, sustained connections, large data
- Jitter changes: More predictable timing during exfiltration

**Focus on:**

- Changes from periodic short connections to long sessions
- Beacon interval irregularities during exfiltration
- Increased connection frequency during data transfer
- Loss of jitter (randomization) in beacon timing
- Beacon timing correlating with file system activity

**Suspicious indicators:**

- C2 beacon changing from 60-second intervals to sustained 10-minute sessions
- Loss of beacon jitter during high data transfer (beacon becomes predictable)
- Connection frequency increasing from hourly to every 5 minutes
- Beacon timing shift correlating with archive creation or file staging
- Transition from consistent 1KB beacons to variable-size transfers (1KB, 500KB, 2MB)
- Extended connection duration: baseline 5 seconds, exfiltration 5+ minutes
- Beacon callbacks ceasing during large data transfer (malware switches modes)
- Multiple rapid connections replacing single periodic beacon
- Timing patterns matching known exfiltration frameworks (Cobalt Strike data channels)
- Beacon behavior change following credential dumping or privilege escalation

---

### 5. File Staging Followed by C2 Communication

**SIEM Correlation:**

- Correlate file operations with subsequent C2 connections
- Track time delta between staging and exfiltration
- Monitor processes performing both file and network operations

**Sysmon:**

- Event ID 11 (File created) - File staging in temporary locations
- Event ID 3 (Network connection) - C2 communications following staging
- Event ID 23 (File deleted) - Staged file cleanup after exfiltration
- Event ID 1 (Process creation) - Process performing staging and communication

**Windows Event Logs (Security):**

- Event ID 4663 (Access attempted to object) - File read operations
- Event ID 4660 (Object deleted) - File deletion after exfiltration

**Correlation Pattern:**

- File collection/archiving → Brief delay (1-30 minutes) → C2 communication → File deletion

**Focus on:**

- Files created in staging directories then accessed by C2 process
- Archive creation followed by network activity
- File deletion after C2 communication
- Same process performing file operations and network connections
- Temporal correlation between file and network activity

**Suspicious indicators:**

- Archive file created in `%TEMP%` followed within 10 minutes by large HTTP POST to external IP
- File staging (Event ID 11) → Process reading file (Event ID 4663) → Network connection (Event ID 3)
- Staged files in `C:\Users\Public\` accessed by process with known C2 behavior
- Archive creation timestamp closely preceding spike in C2 traffic volume
- File deleted (Event ID 23) within 30 minutes of C2 data transfer completion
- Same process creating archives and establishing network connections to external IPs
- Multiple files staged sequentially, each followed by C2 communication
- Staging directory showing temporary file creation, access, transfer, deletion pattern
- C2 process reading sensitive files before network communication
- File timestamps correlating with C2 traffic volume increases

---

### 6. Encrypted or Encoded Data in C2 Traffic

**Network Logs:**

- Deep packet inspection (DPI) - Payload entropy analysis
- TLS/SSL inspection - Certificate anomalies, cipher suites
- Protocol analysis - Non-standard protocol usage
- IDS/IPS - Encrypted C2 signatures

**Proxy Logs:**

- HTTP POST/GET with base64-encoded parameters or bodies
- Custom encoding schemes in URL parameters
- Encrypted payloads in standard protocols

**Packet Captures:**

- Payload entropy analysis (high entropy suggests encryption)
- Binary data in text-based protocols
- Custom encryption or encoding patterns

**Focus on:**

- High-entropy data in C2 communications
- Base64 or hex-encoded data in HTTP traffic
- TLS connections to suspicious or self-signed certificates
- Encrypted data within legitimate protocols
- Custom encryption implementations

**Suspicious indicators:**

- HTTP POST bodies with entropy >7.0 (scale 0-8, high entropy suggests encryption)
- Base64-encoded data in URL parameters or POST bodies: `data=VGhpcyBpcyBiYXNlNjQgZW5jb2RlZA==`
- TLS connections using self-signed certificates or unusual cipher suites
- Binary data embedded in JSON or XML payloads
- Custom headers containing encrypted data: `X-Data: <encrypted_blob>`
- Unusual character sets in HTTP traffic (binary patterns in text protocol)
- Protocol tunneling: encrypted data within DNS TXT records, ICMP payloads
- Multiple layers of encoding: base64 within hex within HTTP
- XOR-encoded data patterns in network traffic
- Encryption algorithms visible in traffic: AES, RC4, custom ciphers

---

### 7. Long-Duration C2 Sessions with High Data Transfer

**Network Logs:**

- Netflow/IPFIX - Connection duration and byte counts
- Firewall logs - Long-lived connections to external IPs
- Session logging - Connection start/end times and data volumes

**Sysmon:**

- Event ID 3 (Network connection) - Connection establishment
- Correlate with connection termination for duration calculation

**SIEM Correlation:**

- Calculate connection duration from start to end
- Track bytes sent/received per connection
- Identify sustained high-bandwidth sessions
- Compare against baseline connection characteristics

**Focus on:**

- Connections lasting >10 minutes with continuous data transfer
- High byte counts (>10MB) in single session
- Sustained upload activity rather than downloads
- Connections maintained during entire exfiltration period
- Long sessions from unexpected processes

**Suspicious indicators:**

- C2 connections lasting >30 minutes with continuous outbound data transfer
- Single session transferring >50MB of data to external IP
- Connection duration exceeding normal C2 beacon sessions by 10x or more
- Sustained upload bandwidth (>1Mbps) to external host for extended period
- Process maintaining connection for hours while transferring data
- Connection persisting through multiple file staging operations
- Sessions with >90% outbound traffic (upload vs. download ratio)
- Long-duration connections from processes in `%TEMP%`, `%APPDATA%`, or user directories
- Connections maintained during off-hours (00:00-06:00) with active data transfer
- Single TCP session transferring entire database dump or large archive

---

### 8. C2 Traffic Pattern Changes Following Data Collection

**SIEM Correlation:**

- Correlate data collection activities with C2 behavior changes
- Monitor for reconnaissance → collection → exfiltration progression
- Track process behavior evolution over time

**Sysmon:**

- Event ID 1 (Process creation) - Data collection tool execution
- Event ID 11 (File created) - Files collected or staged
- Event ID 3 (Network connection) - C2 communication changes

**Windows Event Logs (Security):**

- Event ID 4663 (Access attempted to object) - Sensitive file access
- Event ID 4688 (Process creation) - Collection tool execution

**Behavioral Timeline:**

- Initial access → Reconnaissance → Credential access → Collection → Exfiltration

**Focus on:**

- C2 traffic changes after file access or collection activity
- Increased C2 volume following credential dumping
- Traffic pattern shifts after database access
- Behavioral changes in C2 process after staging activity
- Timeline correlation between attack stages

**Suspicious indicators:**

- C2 beacon traffic increasing within 1 hour of credential dumping (Mimikatz execution)
- Network data transfer spike following database query activity or backup file access
- C2 process behavior change after accessing sensitive directories: `Documents\`, `Database\`
- Traffic volume increase correlating with execution of collection commands: `dir`, `tree`, `xcopy`
- Beacon interval changes following privilege escalation or lateral movement
- C2 communication spike after accessing SharePoint, file servers, or document repositories
- Process showing minimal network activity suddenly transferring large volumes after file operations
- Timeline showing: reconnaissance (Day 1) → collection (Day 2) → exfiltration (Day 3)
- C2 traffic pattern shift from periodic beacons to bulk transfer mode
- Multiple systems showing C2 activity increase after same credential access event

---

### 9. Outbound Data Transfer During Off-Hours via C2

**Network Logs:**

- Firewall logs - Off-hours traffic to known C2 infrastructure
- Netflow - Data transfer volumes during non-business hours
- Proxy logs - HTTP/HTTPS activity outside normal work hours

**SIEM Correlation:**

- Define business hours per user role and location
- Track data transfers outside normal work schedules
- Correlate user activity with network transfers
- Monitor for after-hours automated exfiltration

**Sysmon:**

- Event ID 3 (Network connection) - Connection timestamps
- Event ID 1 (Process creation) - Process execution times

**Time-Based Indicators:**

- Off-hours: 00:00-06:00 local time
- Weekends when user typically works Monday-Friday
- Holiday periods
- Times when user account should be inactive

**Focus on:**

- C2 communications during off-hours with large data transfers
- Automated exfiltration scheduled during low-activity periods
- Data transfer when associated user account should be inactive
- Weekend or holiday exfiltration activity
- Timing designed to evade detection

**Suspicious indicators:**

- Large C2 data transfers (>100MB) occurring between 02:00-05:00 local time
- Weekend C2 activity from accounts associated with Monday-Friday employees
- Sustained exfiltration sessions starting at midnight and running until 06:00
- C2 process transferring data during holidays or vacation periods
- Automated scheduled tasks initiating C2 exfiltration during off-hours
- Service accounts showing C2 activity during periods of no legitimate use
- Data transfer timing correlating with reduced SOC monitoring coverage
- Multiple systems showing coordinated off-hours exfiltration
- C2 traffic from VDI or remote access sessions during unexpected times
- Exfiltration coinciding with backup windows (attempting to blend with legitimate traffic)

---

### 10. Multiple Files Exfiltrated Through Established C2

**SIEM Correlation:**

- Correlate file access events with C2 communications
- Track multiple distinct exfiltration operations
- Monitor for systematic file-by-file exfiltration

**Sysmon:**

- Event ID 11 (File created) - Multiple staging files
- Event ID 3 (Network connection) - Multiple C2 sessions
- Event ID 23 (File deleted) - Sequential file cleanup

**Windows Event Logs (Security):**

- Event ID 4663 (Access attempted to object) - Multiple file read operations
- Event ID 4660 (Object deleted) - File deletion pattern

**Exfiltration Patterns:**

- Sequential: File1 → Transfer → File2 → Transfer → File3
- Batch: Multiple files → Single large transfer
- Continuous: Ongoing exfiltration over days/weeks

**Focus on:**

- Multiple distinct file transfers via same C2 channel
- Sequential exfiltration pattern (file-by-file)
- Different file types exfiltrated over time
- Systematic directory-by-directory exfiltration
- Persistent exfiltration campaign over extended period

**Suspicious indicators:**

- Multiple archive files created and transferred sequentially via same C2 process
- Pattern: create `file1.zip` → transfer → delete → create `file2.zip` → transfer → delete
- C2 process accessing different directories over multiple days with subsequent transfers
- File types suggesting comprehensive data theft: documents, databases, source code, credentials
- Exfiltration spanning multiple days with consistent C2 infrastructure usage
- Multiple small transfers rather than single large archive (evading size-based detection)
- Sequential transfers from different file servers or databases via same C2 channel
- Progressive exfiltration: Day 1 (HR files), Day 2 (Finance files), Day 3 (Engineering files)
- Same C2 beacon used for both command execution and multiple data exfiltration operations
- File access patterns showing systematic enumeration followed by sequential transfers
---
# Exfiltration Over C2 Channel Investigation Checklist

## 1. Increased C2 Data Volumes

- [ ] Review C2 traffic increasing from baseline 1-2KB to >100KB per connection
- [ ] Check sustained connections (>10 minutes) with continuous data transfer to C2 IPs
- [ ] Monitor daily data transfer to C2 exceeding 10MB (baseline <1MB)
- [ ] Identify HTTP/HTTPS sessions to known C2 domains with responses >1MB
- [ ] Look for gradual escalation: Day 1 (50KB), Day 2 (500KB), Day 3 (5MB)
- [ ] Check C2 traffic volume correlating with archive creation or file staging
- [ ] Review bandwidth usage to external IPs matching known malware C2 infrastructure
- [ ] Monitor multiple large data transfers to same C2 IP within 24 hours

## 2. Large HTTP/HTTPS POST Requests

- [ ] Review HTTP POST requests >500KB from workstations/servers to external IPs
- [ ] Check sequential POSTs to same URL: /update.php, /api/sync, /data
- [ ] Monitor Content-Type: application/octet-stream, application/x-www-form-urlencoded with large bodies
- [ ] Identify POST data with base64-encoded content or binary patterns
- [ ] Look for user-agents matching C2 frameworks: PowerShell Empire, Cobalt Strike, Metasploit
- [ ] Check POST requests to paths: /submit.php, /upload, /api/data, /gate.php
- [ ] Review HTTP responses with Content-Length >1MB from external servers
- [ ] Monitor powershell.exe, rundll32.exe making large HTTP POSTs

## 3. DNS C2 Channel Anomalies

- [ ] Check DNS query frequency >100 queries per minute to same domain from single host
- [ ] Review query names >50 characters with base64/hex patterns
- [ ] Monitor TXT record queries from workstations/servers (not DNS infrastructure)
- [ ] Identify DNS responses with TXT records >512 bytes containing encoded data
- [ ] Look for sequential queries: part1.domain.com, part2.domain.com
- [ ] Check DNS queries from powershell.exe or custom executables
- [ ] Review queries to newly registered domains with high entropy subdomains
- [ ] Monitor DNS query volume spike correlating with file staging

## 4. Beacon Timing Changes

- [ ] Review C2 beacons changing from 60-second intervals to sustained 10-minute sessions
- [ ] Check loss of beacon jitter during high data transfer (becomes predictable)
- [ ] Monitor connection frequency increasing from hourly to every 5 minutes
- [ ] Identify beacon timing shifts correlating with archive creation
- [ ] Look for transition from 1KB beacons to variable-size transfers (500KB, 2MB)
- [ ] Check extended connection duration: baseline 5 seconds, exfiltration 5+ minutes
- [ ] Review timing patterns matching known frameworks (Cobalt Strike data channels)
- [ ] Monitor beacon behavior changes following credential dumping

## 5. File Staging to C2 Correlation

- [ ] Timeline: Archive file in %TEMP% → 10 minutes → Large HTTP POST to external IP
- [ ] Check Sysmon Event ID 11 (staging) → Event ID 4663 (read) → Event ID 3 (network)
- [ ] Review staged files in C:\Users\Public\ accessed by C2 process
- [ ] Monitor file deleted within 30 minutes of C2 data transfer completion
- [ ] Identify same process creating archives and establishing external connections
- [ ] Look for multiple files staged sequentially, each followed by C2 communication
- [ ] Check temporary file pattern: creation → access → transfer → deletion
- [ ] Correlate file timestamps with C2 traffic volume increases

## 6. Encrypted/Encoded C2 Data

- [ ] Check HTTP POST bodies with entropy >7.0 (encryption indicator)
- [ ] Review base64-encoded data in URL parameters or POST bodies
- [ ] Monitor TLS connections using self-signed certificates or unusual cipher suites
- [ ] Identify binary data embedded in JSON or XML payloads
- [ ] Look for custom headers with encrypted data: X-Data: <encrypted_blob>
- [ ] Check protocol tunneling: encrypted data in DNS TXT records, ICMP payloads
- [ ] Review multiple encoding layers: base64 within hex within HTTP
- [ ] Monitor XOR-encoded data patterns in network traffic

## 7. Long-Duration High-Volume Sessions

- [ ] Review C2 connections lasting >30 minutes with continuous outbound transfer
- [ ] Check single session transferring >50MB to external IP
- [ ] Monitor sustained upload bandwidth (>1Mbps) for extended period
- [ ] Identify sessions with >90% outbound traffic (upload vs. download ratio)
- [ ] Look for connections maintained during off-hours (00:00-06:00) with active transfer
- [ ] Check long-duration connections from processes in %TEMP%, %APPDATA%
- [ ] Review single TCP session transferring entire database dump or large archive
- [ ] Monitor connection duration exceeding baseline by 10x or more

## 8. Post-Collection C2 Changes

- [ ] Check C2 traffic increasing within 1 hour of credential dumping (Mimikatz)
- [ ] Review network spike following database query or backup file access
- [ ] Monitor C2 behavior change after accessing Documents, Database\ directories
- [ ] Identify traffic volume increase with collection commands: dir, tree, xcopy
- [ ] Look for beacon interval changes following privilege escalation
- [ ] Check C2 spike after accessing SharePoint, file servers, document repositories
- [ ] Review timeline: reconnaissance (Day 1) → collection (Day 2) → exfiltration (Day 3)
- [ ] Monitor C2 pattern shift from periodic beacons to bulk transfer mode

## 9. Off-Hours C2 Exfiltration

- [ ] Review large C2 transfers (>100MB) between 02:00-05:00 local time
- [ ] Check weekend C2 activity from Monday-Friday employee accounts
- [ ] Monitor sustained exfiltration sessions from midnight to 06:00
- [ ] Identify C2 activity during holidays or vacation periods
- [ ] Look for automated scheduled tasks initiating off-hours exfiltration
- [ ] Check service accounts with C2 activity during no legitimate use periods
- [ ] Review data transfer timing with reduced SOC monitoring coverage
- [ ] Monitor multiple systems with coordinated off-hours exfiltration

## 10. Multiple File Sequential Exfiltration

- [ ] Check pattern: create file1.zip → transfer → delete → create file2.zip → repeat
- [ ] Review C2 process accessing different directories over multiple days
- [ ] Monitor file types: documents, databases, source code, credentials
- [ ] Identify exfiltration spanning days with consistent C2 infrastructure
- [ ] Look for multiple small transfers vs. single large archive (evading detection)
- [ ] Check sequential transfers from different file servers via same C2
- [ ] Review progressive exfiltration: Day 1 (HR), Day 2 (Finance), Day 3 (Engineering)
- [ ] Timeline: File access → Systematic enumeration → Sequential C2 transfers