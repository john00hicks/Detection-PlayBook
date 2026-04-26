# Valid Accounts: [T1078](https://attack.mitre.org/techniques/T1078/)

## Detection Explanation

Adversaries may obtain and abuse credentials of existing accounts to gain initial access, persistence, privilege escalation, or defence evasion. This includes compromised user accounts, service accounts, domain accounts, local accounts, cloud accounts, and default accounts. Attackers may obtain credentials through phishing, credential dumping, purchasing credentials on dark web markets, or brute force attacks.

**Key Detection Indicators:**

- Account logins from unusual locations or IP addresses
- Authentication at abnormal times (outside business hours)
- Multiple failed login attempts followed by successful authentication
- Concurrent logins from geographically disparate locations (impossible travel)
- Use of dormant or disabled accounts
- Privileged account usage from non-administrative workstations
- Service account interactive logins
- Spike in authentication attempts against multiple accounts
- Authentication using legacy protocols (NTLM when Kerberos is standard)
- Successful logins after password spray or brute force attempts

**Detection Strategy:** Monitor authentication logs for anomalous patterns including geographic anomalies, temporal anomalies, and behavioral deviations. Correlate failed and successful authentication attempts to identify credential compromise. Track privileged account usage and service account behavior. Implement user and entity behavior analytics (UEBA) to establish baselines and detect deviations.
## Areas to Investigate

### Account logins from unusual locations or IP addresses

**Windows Event Logs:**

- Event ID 4624 (Successful logon) - Check `IpAddress` and `WorkstationName` fields
- Event ID 4625 (Failed logon) - Monitor source IPs attempting authentication
- Event ID 4648 (Logon with explicit credentials) - Track credential usage from different hosts

**Network Logs:**

- VPN authentication logs - Source IP geolocation data
- Firewall logs - Authentication attempts from external IPs
- Proxy logs - User authentication with source IP information
- Cloud provider logs (Azure AD, AWS CloudTrail, Google Workspace) - Sign-in logs with IP geolocation

**Sysmon:**

- Event ID 3 (Network connection) - Correlate with authentication events to track connection sources

---

### Authentication at abnormal times (outside business hours)

**Windows Event Logs:**

- Event ID 4624 (Successful logon) - Filter by timestamp outside 7 AM - 7 PM (or your business hours)
- Event ID 4634 (Account logoff) - Track logon duration and timing
- Event ID 4647 (User initiated logoff) - Verify expected session times

**Network Logs:**

- VPN connection logs - Timestamp analysis for after-hours connections
- Web application access logs - Authentication timestamp review
- Database authentication logs - Query execution times

---

### Multiple failed login attempts followed by successful authentication

**Windows Event Logs:**

- Event ID 4625 (Failed logon) - Count failures per account/IP within time window
- Event ID 4624 (Successful logon) - Correlate success following failures
- Event ID 4771 (Kerberos pre-authentication failed) - Domain controller authentication failures
- Event ID 4776 (Credential validation) - NTLM authentication attempts

**Network Logs:**

- Application authentication logs - Failed login counters
- SSH logs (auth.log on Linux) - Failed authentication attempts
- Web server logs - HTTP 401/403 responses followed by 200
- Load balancer logs - Authentication failure patterns

---

### Concurrent logins from geographically disparate locations (impossible travel)

**Windows Event Logs:**

- Event ID 4624 (Successful logon) - Compare sequential logon locations for same account
- Event ID 4778 (Session reconnected) - Remote Desktop session reconnections
- Event ID 4779 (Session disconnected) - Track session transitions

**Network Logs:**

- VPN logs - Multiple concurrent sessions from different geolocations
- Cloud service logs (Office 365, AWS, Azure AD) - Sign-in activity from different regions
- Proxy logs - User requests originating from multiple geographic locations simultaneously

---

### Use of dormant or disabled accounts

**Windows Event Logs:**

- Event ID 4624 (Successful logon) - Cross-reference with Active Directory last logon timestamps
- Event ID 4720 (User account created) - New account creation followed by immediate use
- Event ID 4722 (User account enabled) - Recently re-enabled accounts with logon activity
- Event ID 4725 (User account disabled) - Attempts to use disabled accounts (should generate 4625)

**Active Directory Logs:**

- Event ID 4738 (User account changed) - Account modifications before logon activity
- Query AD for `lastLogonTimestamp` attribute - Identify accounts inactive for 90+ days

---

### Privileged account usage from non-administrative workstations

**Windows Event Logs:**

- Event ID 4624 (Successful logon) with `LogonType=2` (Interactive) or `LogonType=10` (RemoteInteractive/RDP)
- Event ID 4672 (Special privileges assigned) - Admin rights granted to logon session
- Event ID 4648 (Logon with explicit credentials) - RunAs or PsExec with admin accounts

**Sysmon:**

- Event ID 1 (Process creation) - Processes running with admin privileges from user workstations
- Event ID 10 (Process access) - LSASS access from non-admin systems

---

### Service account interactive logins

**Windows Event Logs:**

- Event ID 4624 with `LogonType=2` (Interactive) or `LogonType=10` (RemoteInteractive) - Service accounts should only use `LogonType=5` (Service)
- Event ID 4624 with `LogonType=3` (Network) - Normal for service accounts, but monitor for unusual patterns
- Event ID 4672 (Special privileges) - Service accounts receiving interactive privileges

**Identify service accounts by naming patterns:**

- Accounts with naming conventions: svc__, service__, __svc, sql_, apache, nginx, tomcat

---

### Spike in authentication attempts against multiple accounts

**Windows Event Logs:**

- Event ID 4625 (Failed logon) - High volume across different usernames from single source
- Event ID 4771 (Kerberos pre-authentication failed) - Password spray detection
- Event ID 4768 (Kerberos TGT requested) - Unusual volume of ticket requests

**Network Logs:**

- Web application logs - Multiple username attempts in authentication endpoints
- VPN logs - Failed authentication across many users
- Firewall logs - Authentication request volume from single IP

---

### Authentication using legacy protocols (NTLM when Kerberos is standard)

**Windows Event Logs:**

- Event ID 4776 (Credential validation) - NTLM authentication events
- Event ID 4624 with `AuthenticationPackageName=NTLM` - Check when Kerberos should be used
- Event ID 4768/4769 (Kerberos ticket operations) - Absence indicates non-Kerberos authentication

**Network Logs:**

- SMB logs - Look for NTLMv1 or NTLMv2 authentication when Kerberos expected
- Packet captures - NTLM authentication traffic on port 445

---

### Successful logins after password spray or brute force attempts

**Windows Event Logs:**

- Event ID 4625 (Failed logon) with `FailureReason=0xC000006A` (Bad password) - Multiple accounts, same password pattern
- Event ID 4625 with `FailureReason=0xC0000064` (User does not exist) - Username enumeration
- Event ID 4740 (Account locked out) - Lockouts indicating brute force
- Event ID 4624 (Successful logon) - Success shortly after spray pattern

**Network Logs:**

- Authentication logs showing failed attempts with common passwords across multiple accounts
- Rate of authentication requests exceeding normal baseline

---

## Additional Investigation Areas

**Active Directory:**

- Event ID 4768 (Kerberos TGT requested) - Unusual ticket requests
- Event ID 4769 (Kerberos service ticket requested) - Service access patterns
- Event ID 4770 (Kerberos service ticket renewed) - Long-running sessions

**Cloud Services:**

- Azure AD Sign-in logs - `resultType`, `location`, `ipAddress`, `clientAppUsed`
- AWS CloudTrail - `ConsoleLogin`, `AssumeRole`, `GetSessionToken` events
- Google Workspace - Admin console audit logs for login activity
- Office 365 Unified Audit Log - `UserLoggedIn`, `UserLoginFailed` events

**Correlation Opportunities:**

- Cross-reference logon events with EDR telemetry for post-authentication behavior
- Correlate authentication logs with data exfiltration or lateral movement indicators
- Compare authentication patterns against user behavior baselines (UEBA)

# Valid Accounts Abuse Investigation Checklist

## 1. Unusual Login Locations

- [ ] Review Event ID 4624 for logins from unexpected IpAddress or WorkstationName fields
- [ ] Check VPN and firewall logs for authentication from external/foreign IP addresses
- [ ] Review cloud service logs (Azure AD, AWS CloudTrail, Google Workspace) for geolocation anomalies
- [ ] Correlate Sysmon Event ID 3 with authentication events to track connection sources
- [ ] Identify logins from IP addresses not associated with corporate networks

## 2. Off-Hours Authentication

- [ ] Filter Event ID 4624 for timestamps outside business hours (e.g., 7 PM - 7 AM)
- [ ] Review VPN connection logs for after-hours or weekend access
- [ ] Check web application access logs for authentication during unusual times
- [ ] Identify patterns of consistent off-hours access by privileged accounts
- [ ] Correlate timing with user's normal work schedule or time zone

## 3. Failed-Then-Successful Login Patterns

- [ ] Count Event ID 4625 failures per account/IP within 30-minute windows
- [ ] Correlate Event ID 4625 with subsequent Event ID 4624 success
- [ ] Review Event ID 4771 (Kerberos pre-auth failed) followed by successful authentication
- [ ] Check Event ID 4776 for NTLM credential validation attempts
- [ ] Look for HTTP 401/403 responses followed by 200 in web server logs

## 4. Impossible Travel Detection

- [ ] Compare sequential Event ID 4624 logins for same account from different geolocations
- [ ] Check for concurrent VPN sessions from geographically disparate locations
- [ ] Review cloud service sign-in logs for simultaneous logins from different regions
- [ ] Calculate time/distance between login locations to identify impossible travel
- [ ] Check Event ID 4778/4779 for RDP session reconnections from different locations

## 5. Dormant and Disabled Accounts

- [ ] Cross-reference Event ID 4624 with AD lastLogonTimestamp (flag accounts inactive 90+ days)
- [ ] Check Event ID 4722 for recently re-enabled accounts with immediate logon activity
- [ ] Review Event ID 4720 for new account creation followed by rapid use
- [ ] Identify Event ID 4738 (account changes) preceding authentication activity
- [ ] Search for Event ID 4625 attempts against disabled accounts

## 6. Privileged Account Misuse

- [ ] Check Event ID 4624 with LogonType=2 or LogonType=10 for admin accounts on user workstations
- [ ] Review Event ID 4672 for admin privileges assigned on non-administrative systems
- [ ] Identify Event ID 4648 (RunAs/PsExec) with privileged credentials from user workstations
- [ ] Monitor Sysmon Event ID 10 for LSASS access from non-admin systems
- [ ] Verify admin account usage aligns with authorized administrative tasks

## 7. Service Account Interactive Logins

- [ ] Search Event ID 4624 with LogonType=2 or LogonType=10 for service account names (svc_, sql_, service_)
- [ ] Review Event ID 4672 showing service accounts receiving interactive privileges
- [ ] Identify service accounts with unexpected LogonType changes
- [ ] Check for service accounts authenticating from workstations vs. servers
- [ ] Verify service account usage matches documented service configurations

## 8. Password Spray and Brute Force

- [ ] Review Event ID 4625 with FailureReason=0xC000006A across multiple accounts from single IP
- [ ] Check Event ID 4740 for account lockouts indicating brute force activity
- [ ] Identify Event ID 4771 volume spikes (Kerberos pre-auth failures)
- [ ] Look for Event ID 4624 success shortly after spray pattern detection
- [ ] Count authentication attempts exceeding normal baseline per IP/account

## 9. Legacy Protocol Authentication

- [ ] Search Event ID 4776 for NTLM authentication in Kerberos-enforced environments
- [ ] Check Event ID 4624 with AuthenticationPackageName=NTLM where Kerberos expected
- [ ] Review SMB logs for NTLMv1 or NTLMv2 usage on modern networks
- [ ] Identify absence of Event ID 4768/4769 (Kerberos tickets) for domain authentications
- [ ] Check for NTLM traffic on port 445 via packet captures or network logs

## 10. Cloud Service Account Abuse

- [ ] Review Azure AD Sign-in logs for suspicious resultType, location, ipAddress, clientAppUsed
- [ ] Check AWS CloudTrail for ConsoleLogin, AssumeRole, GetSessionToken events from unusual sources
- [ ] Monitor Google Workspace admin console for abnormal login activity
- [ ] Review Office 365 Unified Audit Log for UserLoggedIn and UserLoginFailed patterns
- [ ] Correlate cloud authentication with on-premises activity for hybrid environments