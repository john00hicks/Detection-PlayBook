# Brute Force [T1110](https://attack.mitre.org/techniques/T1110/)

## Detection Explanation

Brute force attacks involve adversaries attempting to gain access to accounts by systematically trying multiple passwords or credentials until the correct one is found. This technique is commonly used during the initial access phase or when attempting to escalate privileges within a compromised environment. Attackers leverage automated tools to rapidly test credential combinations against authentication endpoints such as RDP, SSH, web applications, or domain controllers.

Adversaries use brute force attacks to obtain valid credentials that enable persistence, lateral movement, and access to sensitive systems. Common variants include password guessing (T1110.001), password cracking (T1110.002), password spraying (T1110.003), and credential stuffing (T1110.004). Password spraying—where a few common passwords are tested across many accounts—is particularly prevalent as it evades traditional account lockout policies by staying below lockout thresholds per account.

Successful brute force attacks grant attackers legitimate credentials, making their subsequent activities blend with normal user behavior. This makes detection critical at the authentication phase, as post-compromise activity may appear authorized. The impact includes unauthorized access to systems, privilege escalation, data exfiltration, and potential lateral movement throughout the network.

Detection requires establishing baselines of normal authentication patterns and monitoring for deviations such as rapid failed login attempts, login attempts from unusual sources, authentication to multiple accounts from single sources, or successful logins following numerous failures. Organizations should correlate authentication logs across multiple systems to identify distributed brute force campaigns.

---

## Key Detection Indicators & Areas to Investigate

### Summary of Indicators

1. Multiple failed authentication attempts from single source
2. Successful logon following multiple failed attempts (T1110)
3. Authentication attempts across multiple accounts from single source (T1110.003)
4. Failed logons with valid usernames but invalid passwords
5. Authentication attempts outside business hours or from unusual geographic locations
6. High-volume authentication requests to specific services (RDP, SSH, web applications)
7. Account lockouts across multiple accounts in short timeframe
8. Authentication attempts to disabled or non-existent accounts
9. Successful authentications from previously failed source IPs
10. Unusual authentication protocols or legacy protocol usage

---

### 1. Multiple Failed Authentication Attempts from Single Source

**Windows Event Logs (Security):**

- Event ID 4625 (Failed logon) - Account logon failures
- Event ID 4771 (Kerberos pre-authentication failed) - Failed domain authentication
- Event ID 4776 (NTLM authentication failed) - Failed NTLM authentication attempts
- Key fields: `TargetUserName`, `WorkstationName`, `IpAddress`, `FailureReason`, `LogonType`

**Linux/Unix Logs:**

- `/var/log/auth.log` or `/var/log/secure` - Failed SSH authentication attempts
- Look for "Failed password" or "authentication failure" entries

**Network Logs:**

- Firewall logs - Connection attempts to authentication ports (3389/RDP, 22/SSH, 445/SMB)
- IDS/IPS - Signatures for brute force patterns
- VPN logs - Failed VPN authentication attempts

**Focus on:**

- More than 5-10 failed attempts within 5-minute window from same source IP
- Failed attempts using different usernames from single source
- Consistent time intervals between attempts (indicating automated tools)
- Failed attempts targeting privileged accounts (Administrator, root, service accounts)

**Suspicious indicators:**

- Source IPs from unexpected geographic regions or known VPS/cloud provider ranges
- Failed attempts using common usernames (`admin`, `administrator`, `test`, `user`)
- FailureReason code `0xC000006A` (incorrect password with valid username)
- Logon Type 3 (network) or Type 10 (remote interactive/RDP) from external sources

---

### 2. Successful Logon Following Multiple Failed Attempts

**Windows Event Logs (Security):**

- Event ID 4624 (Successful logon) - Successful authentication
- Event ID 4768 (Kerberos TGT requested) - Successful Kerberos authentication
- Event ID 4769 (Kerberos service ticket requested) - Service access after authentication
- Correlate with preceding Event ID 4625 failures from same source IP

**Linux/Unix Logs:**

- `/var/log/auth.log` or `/var/log/secure` - "Accepted password" or "session opened" following failures

**Application Logs:**

- Web server logs (IIS, Apache, Nginx) - HTTP 200/302 responses following 401/403 errors
- Database logs - Successful connections following authentication errors
- Email gateway logs - Successful SMTP/IMAP/POP3 authentication after failures

**Focus on:**

- Successful logon within 1-hour window following 5+ failed attempts from same source
- Account that was successfully accessed after failed attempts on multiple accounts
- Time between last failure and successful authentication (rapid success suggests automated tools)
- Successful logon using LogonType 3 or 10 from external/unusual IP

**Suspicious indicators:**

- Account not previously accessed from the successful source IP or location
- Successful logon outside user's normal working hours
- Post-authentication activity deviates from user's baseline behavior
- Multiple accounts successfully accessed from same source IP in short timeframe

---

### 3. Authentication Attempts Across Multiple Accounts from Single Source (Password Spraying)

**Windows Event Logs (Security):**

- Event ID 4625 - Pattern of single/few failures per account across many accounts
- Event ID 4648 (Explicit credential usage) - Attempts to authenticate with different credentials
- Event ID 4771 - Kerberos pre-authentication failures across multiple usernames

**Active Directory Logs:**

- Event ID 4740 (Account lockout) - Multiple accounts locked simultaneously
- Event ID 4767 (Account unlocked) - Pattern of lockouts and unlocks

**Network Logs:**

- Authentication server logs - Login attempts to multiple accounts from single IP
- Load balancer logs - Authentication requests distributed across multiple accounts
- Proxy logs - Authentication attempts through proxy from single source

**Focus on:**

- Single source IP attempting authentication to 10+ different accounts
- Time pattern: 1-2 attempts per account to avoid lockouts, then moving to next account
- Attempts using common weak passwords (`Password123`, `Spring2025`, `Company123`)
- Systematic progression through user list (alphabetical, by department)

**Suspicious indicators:**

- Source IP from cloud/VPS providers, TOR exit nodes, or anonymization services
- Attempts using corporate password patterns (e.g., `CompanyName` + season + year)
- Authentication attempts to accounts across different departments or privilege levels
- Failed attempts with error code `0xC000006A` (valid username, wrong password)
- Attempts occurring over extended period (hours/days) to evade rate limiting

---

### 4. Failed Logons with Valid Usernames but Invalid Passwords

**Windows Event Logs (Security):**

- Event ID 4625 with SubStatus `0xC000006A` - Correct username, incorrect password
- Event ID 4771 with FailureCode `0x18` - Pre-authentication information invalid (wrong password)
- Distinguish from SubStatus `0xC0000064` (username doesn't exist)

**Application-Specific Logs:**

- Web application logs - 401 responses with username in POST data
- Database audit logs - Failed authentication attempts with valid database accounts
- Email server logs (Exchange, Office 365) - Failed OWA/ActiveSync authentication

**SIEM Correlation:**

- Filter for Event ID 4625 where username exists in Active Directory
- Aggregate by source IP and username over time windows
- Track accounts targeted by valid-username failures

**Focus on:**

- Repeated attempts with valid usernames indicates attacker has user enumeration
- Concentration on high-value accounts (executives, IT staff, service accounts)
- Attempts during non-business hours when users unlikely to be authenticating
- Pattern of valid usernames suggests compromised user list or LDAP enumeration

**Suspicious indicators:**

- More than 3 failures per valid username from same source within 15 minutes
- Failures against recently created accounts (attacker using current user list)
- Systematic attempts through organizational hierarchy or department groupings
- Valid username attempts from geographic regions where organization has no presence

---

### 5. Authentication Attempts Outside Business Hours or from Unusual Geographic Locations

**Windows Event Logs (Security):**

- Event ID 4624/4625 with timestamp outside 08:00-18:00 local business hours
- Event ID 4768/4771 for Kerberos attempts during off-hours
- Correlate with user's historical logon patterns

**VPN and Remote Access Logs:**

- VPN concentrator logs - Connection attempts from unexpected countries
- Remote Desktop Gateway logs - RDP connections from unusual geolocations
- Cloud authentication logs (Azure AD, Okta) - Sign-ins from impossible travel scenarios

**Network Geolocation:**

- Firewall logs with GeoIP correlation - Source country/city of authentication attempts
- Web application firewall - HTTP authentication from blacklisted regions
- DNS logs - Authentication attempts correlated with suspicious DNS queries

**Focus on:**

- Authentication attempts during 00:00-05:00 local time (common attack window)
- Source IPs from countries where organization has no offices or remote workers
- "Impossible travel" - Authentication from two distant locations within impossible timeframe
- First-time authentication from new geographic region without VPN

**Suspicious indicators:**

- Failed or successful logons from high-risk countries (based on threat intelligence)
- Weekend/holiday authentication attempts by users who typically only work weekdays
- Authentication from residential ISP IPs when user typically uses corporate VPN
- Time zone mismatch between user's location and authentication source
- Simultaneous authentication attempts from multiple geographic locations

---

### 6. High-Volume Authentication Requests to Specific Services

**Windows Event Logs:**

- Event ID 4625 - Clustered by `LogonType` to identify targeted service
    - LogonType 3: Network (SMB, file shares)
    - LogonType 8: NetworkCleartext (IIS basic auth)
    - LogonType 10: RemoteInteractive (RDP)

**Sysmon:**

- Event ID 3 (Network connection) - High connection volume to ports 3389, 22, 445, 1433, 5432
- Correlate with authentication events to identify brute force targets

**Network Logs:**

- Netflow/IPFIX - High packet/session count to authentication ports from single source
- Firewall logs - Connection attempts exceeding baseline to RDP (3389), SSH (22), or web apps (443)
- Load balancer logs - Unusual request volume to authentication endpoints

**Service-Specific Logs:**

- RDP logs - Event ID 1149 (Terminal Services RemoteConnectionManager operational log)
- SSH daemon logs - High frequency of "Connection from..." entries
- Web server logs - Excessive POST requests to `/login`, `/auth`, or authentication APIs
- Database logs - Repeated connection failures from same source

**Focus on:**

- More than 50 authentication attempts per minute to single service
- Sustained high-volume attempts over 10+ minutes (indicating automated tools)
- Single source targeting multiple services simultaneously
- Authentication attempts to services not commonly used (e.g., RDP to domain controllers from internet)

**Suspicious indicators:**

- Source IP making 100+ connection attempts without successful authentication
- Authentication requests with no user-agent string or suspicious user-agents
- Requests bypassing expected authentication flow (direct API calls)
- Connection attempts continuing after service responds with errors
- High bandwidth consumption on authentication services without corresponding successful sessions

---

### 7. Account Lockouts Across Multiple Accounts in Short Timeframe

**Windows Event Logs (Security):**

- Event ID 4740 (Account locked out) - User account lockouts
- Event ID 4767 (Account unlocked) - Account unlock events
- Event ID 4625 preceding lockouts - Failed attempts leading to lockout
- Key fields: `TargetUserName`, `CallerComputerName`, timestamp

**Active Directory Domain Controller Logs:**

- Event ID 4771 with Result Code `0x12` (account locked) - Kerberos lockouts
- Event ID 644 (older Windows) - Account lockout events
- PDC Emulator logs - Authoritative lockout source

**Help Desk/Ticketing Systems:**

- Tickets for password resets or account unlocks
- Correlate help desk activity with Event ID 4740

**Focus on:**

- 3+ accounts locked within 10-minute window (suggests password spraying)
- Accounts locked that don't typically experience lockouts
- Lockout source from external IP or unusual internal system
- Privileged accounts (administrators, service accounts) experiencing lockouts

**Suspicious indicators:**

- Lockouts during off-hours when users unlikely to mistype passwords
- Pattern of lockouts progressing alphabetically or by department
- Accounts locked from same source system or IP address
- Service accounts locked (indicates automated authentication attempts)
- Lockouts of disabled accounts (shows attacker using outdated user lists)
- Correlation between lockouts and preceding Event ID 4625 spike

---

### 8. Authentication Attempts to Disabled or Non-Existent Accounts

**Windows Event Logs (Security):**

- Event ID 4625 with SubStatus `0xC0000064` - Account does not exist
- Event ID 4625 with SubStatus `0xC0000072` - Account disabled
- Event ID 4625 with SubStatus `0xC0000193` - Account expired
- Event ID 4771 with FailureCode `0x6` - Client principal unknown (user doesn't exist)

**Active Directory Logs:**

- Failed bind attempts in Directory Service logs
- LDAP query logs showing enumeration attempts

**Application Logs:**

- Web application authentication attempts to non-existent usernames
- Database authentication failures for dropped user accounts
- Email authentication attempts to deleted mailboxes

**Focus on:**

- Repeated attempts to same non-existent account (attacker unaware account invalid)
- Systematic attempts through common usernames (`admin`, `test`, `administrator`)
- Attempts to recently disabled accounts (indicates attacker using stale user list)
- Failed attempts to accounts that never existed (random username generation)

**Suspicious indicators:**

- High volume of `0xC0000064` errors from single source IP
- Attempts to default/common account names across multiple systems
- Authentication attempts to admin accounts that were disabled as security measure
- Attempts to accounts disabled within past 30 days (suggests reconnaissance occurred previously)
- Pattern suggesting username enumeration (alphabetical, sequential attempts)
- Attempts to service account naming conventions that don't exist (e.g., `svc_backup`, `svc_sql`)

---

### 9. Successful Authentications from Previously Failed Source IPs

**SIEM Correlation:**

- Cross-reference Event ID 4624 (success) with historical Event ID 4625 (failures) by source IP
- Track source IPs with failed attempts that later show successful authentication
- Monitor time delta between first failure and eventual success

**Network Logs:**

- Firewall logs - Track IPs with both denied and allowed authentication traffic
- IDS/IPS - Correlate brute force signatures with subsequent successful connections
- Threat intelligence - Compare successful authentication IPs with known malicious infrastructure

**Endpoint Detection:**

- EDR logs - Processes spawned following successful authentication from suspicious source
- Event ID 4688 (Process creation) immediately following Event ID 4624 from flagged IP

**Focus on:**

- Source IPs that had 10+ failures over past 24-48 hours now showing success
- Successful authentication using different account than those that failed
- Post-authentication activity indicating malicious intent (reconnaissance, lateral movement)
- Geographic or network indicators suggesting compromised source IP

**Suspicious indicators:**

- Success after extended failure period suggests credential compromise or password cracking
- Successful account differs from failed attempts (attacker switched targets)
- Post-authentication: unusual processes, file access, network connections
- Source IP on threat intelligence feeds or associated with VPN/proxy services
- Successful logon followed by immediate lateral movement attempts
- Authentication source IP has no prior legitimate history in environment

---

### 10. Unusual Authentication Protocols or Legacy Protocol Usage

**Windows Event Logs (Security):**

- Event ID 4624 with LogonType 8 (NetworkCleartext) - Credentials sent in clear text
- Event ID 4776 (NTLM authentication) - Legacy NTLM instead of Kerberos
- Event ID 4768/4769 absence when Event ID 4776 present - Systems not using Kerberos

**Network Traffic Analysis:**

- Packet captures - Clear text protocols (Telnet port 23, FTP port 21)
- Protocol analysis - NTLM authentication traffic patterns
- TLS/SSL inspection - Legacy SSL/TLS versions (SSLv3, TLS 1.0)

**Application Logs:**

- Web server logs - Basic authentication instead of modern OAuth/SAML
- Database logs - Connections without encrypted authentication
- Email logs - POP3/IMAP without SSL/TLS

**Sysmon:**

- Event ID 3 (Network connection) to legacy service ports
- Monitor connections to ports 23 (Telnet), 21 (FTP), 139 (NetBIOS)

**Focus on:**

- NTLM authentication when environment primarily uses Kerberos
- Clear text protocol usage in environments where encrypted alternatives available
- Legacy authentication to modern systems (suggests deliberate downgrade)
- Authentication without MFA when policy requires it

**Suspicious indicators:**

- NTLM authentication attempts after Kerberos pre-auth failures (pass-the-hash attempts)
- Basic authentication to web applications from unusual sources
- Protocol downgrade from secure to insecure (Kerberos to NTLM, HTTPS to HTTP)
- Legacy protocol usage from systems that previously used modern protocols
- Clear text authentication over internet-facing services
- Authentication attempts using deprecated protocols disabled in security policy
---
# Brute Force Attack Investigation Checklist

## 1. Multiple Failed Authentication Attempts

- [ ] Review Event ID 4625 for 5-10+ failed attempts within 5-minute window from same source IP
- [ ] Check Event ID 4771 (Kerberos pre-auth failed) for domain authentication failures
- [ ] Monitor Event ID 4776 for failed NTLM authentication attempts
- [ ] Identify FailureReason code 0xC000006A (incorrect password with valid username)
- [ ] Look for failed attempts using common usernames: admin, administrator, test, user
- [ ] Check Linux /var/log/auth.log for "Failed password" entries
- [ ] Review source IPs from unexpected geographic regions or cloud/VPS providers
- [ ] Monitor LogonType 3 (network) or Type 10 (RDP) from external sources

## 2. Successful Logon After Failed Attempts

- [ ] Correlate Event ID 4624 (success) with preceding Event ID 4625 from same source
- [ ] Check for successful logon within 1-hour following 5+ failed attempts
- [ ] Review Linux /var/log/auth.log for "Accepted password" following failures
- [ ] Identify web server HTTP 200/302 responses following 401/403 errors
- [ ] Look for successful logon outside user's normal working hours
- [ ] Check for account not previously accessed from successful source IP
- [ ] Monitor post-authentication activity for deviations from user baseline
- [ ] Review multiple accounts accessed from same source IP in short timeframe

## 3. Password Spraying Detection

- [ ] Check Event ID 4625 for pattern of 1-2 failures per account across 10+ accounts
- [ ] Review Event ID 4740 for multiple accounts locked simultaneously
- [ ] Identify single source IP attempting authentication to many different accounts
- [ ] Look for common weak passwords: Password123, Spring2025, Company123
- [ ] Monitor source IPs from cloud/VPS providers, TOR exit nodes, anonymization services
- [ ] Check for systematic progression through user list (alphabetical, by department)
- [ ] Review attempts using corporate password patterns: CompanyName + season + year
- [ ] Identify attempts over extended periods (hours/days) to evade rate limiting

## 4. Valid Username, Invalid Password Attempts

- [ ] Filter Event ID 4625 with SubStatus 0xC000006A (correct username, wrong password)
- [ ] Check Event ID 4771 with FailureCode 0x18 (pre-auth invalid - wrong password)
- [ ] Distinguish from SubStatus 0xC0000064 (username doesn't exist)
- [ ] Monitor 3+ failures per valid username from same source within 15 minutes
- [ ] Identify concentration on high-value accounts: executives, IT staff, service accounts
- [ ] Look for failures against recently created accounts
- [ ] Review systematic attempts through organizational hierarchy
- [ ] Check for valid username attempts from regions with no organizational presence

## 5. Off-Hours and Unusual Geographic Access

- [ ] Review Event ID 4624/4625 with timestamps outside business hours (08:00-18:00)
- [ ] Check authentication attempts during 00:00-05:00 local time
- [ ] Monitor VPN logs for connections from unexpected countries
- [ ] Identify "impossible travel" scenarios (authentication from distant locations rapidly)
- [ ] Look for failed/successful logons from high-risk countries
- [ ] Check weekend/holiday authentication by weekday-only users
- [ ] Review authentication from residential ISPs when users typically use corporate VPN
- [ ] Monitor simultaneous authentication from multiple geographic locations

## 6. High-Volume Authentication Requests

- [ ] Check for 50+ authentication attempts per minute to single service
- [ ] Monitor Event ID 4625 clustered by LogonType to identify targeted service
- [ ] Review Sysmon Event ID 3 for high connection volume to ports 3389, 22, 445
- [ ] Identify 100+ connection attempts without successful authentication
- [ ] Look for sustained high-volume attempts over 10+ minutes
- [ ] Check web server POST requests to /login, /auth endpoints
- [ ] Monitor SSH logs for high frequency "Connection from..." entries
- [ ] Review database logs for repeated connection failures from same source

## 7. Account Lockout Patterns

- [ ] Review Event ID 4740 for 3+ accounts locked within 10-minute window
- [ ] Check Event ID 4767 for patterns of lockouts and unlocks
- [ ] Monitor Event ID 4771 with Result Code 0x12 (account locked)
- [ ] Identify lockouts during off-hours when users unlikely to mistype passwords
- [ ] Look for pattern of lockouts progressing alphabetically or by department
- [ ] Check for privileged accounts (administrators, service accounts) experiencing lockouts
- [ ] Review lockouts of disabled accounts (attacker using outdated user lists)
- [ ] Correlate lockouts with preceding Event ID 4625 spikes

## 8. Disabled/Non-Existent Account Attempts

- [ ] Check Event ID 4625 with SubStatus 0xC0000064 (account does not exist)
- [ ] Review Event ID 4625 with SubStatus 0xC0000072 (account disabled)
- [ ] Monitor Event ID 4771 with FailureCode 0x6 (client principal unknown)
- [ ] Identify high volume of 0xC0000064 errors from single source IP
- [ ] Look for attempts to default/common account names: admin, test, administrator
- [ ] Check attempts to recently disabled accounts (within past 30 days)
- [ ] Review systematic attempts through common usernames
- [ ] Monitor attempts to service account naming conventions that don't exist

## 9. Previously Failed IPs with Successful Authentication

- [ ] Correlate Event ID 4624 (success) with historical Event ID 4625 (failures) by source IP
- [ ] Check source IPs with 10+ failures over past 24-48 hours now showing success
- [ ] Review successful authentication using different account than failed attempts
- [ ] Monitor post-authentication activity: unusual processes, file access, network connections
- [ ] Identify source IPs on threat intelligence feeds
- [ ] Look for successful logon followed by immediate lateral movement
- [ ] Check authentication source IP with no prior legitimate history
- [ ] Timeline: Extended failures → Success → Suspicious post-authentication activity

## 10. Legacy Protocol and Authentication Anomalies

- [ ] Check Event ID 4624 with LogonType 8 (NetworkCleartext - credentials in clear text)
- [ ] Review Event ID 4776 (NTLM) when environment primarily uses Kerberos
- [ ] Monitor Sysmon Event ID 3 for connections to legacy ports: 23 (Telnet), 21 (FTP), 139 (NetBIOS)
- [ ] Identify NTLM authentication after Kerberos pre-auth failures (pass-the-hash)
- [ ] Look for protocol downgrade from secure to insecure (Kerberos to NTLM)
- [ ] Check basic authentication to web applications from unusual sources
- [ ] Review clear text authentication over internet-facing services
- [ ] Monitor authentication without MFA when policy requires it