# Exfiltration Over Web Service: [T1567](https://attack.mitre.org/techniques/T1567/)

## Detection Explanation

Exfiltration Over Web Service involves adversaries using legitimate external web services to steal data from compromised networks. This technique enables attackers to blend malicious data exfiltration with normal user behavior by leveraging trusted cloud services, file sharing platforms, code repositories, and social media that are often allowed through corporate firewalls and security controls. Web services provide convenient, high-bandwidth channels for data theft while appearing as legitimate business activity.

Attackers use web services for exfiltration because these platforms are widely trusted, rarely blocked by security controls, use encrypted HTTPS connections that prevent content inspection, and provide reliable infrastructure for storing and retrieving stolen data. Common targets include cloud storage services like Dropbox and Google Drive (T1567.002), code repositories like GitHub and Pastebin (T1567.001), social media platforms, file sharing services, and collaboration tools. Adversaries may use legitimate accounts, create new accounts, or abuse public sharing features.

Successful exfiltration over web services enables attackers to steal large volumes of data while bypassing traditional DLP controls, using encrypted channels that prevent content inspection, and leveraging infrastructure maintained by trusted third parties. This technique is particularly effective because security teams must balance detecting malicious exfiltration against allowing legitimate business use of these same services. The impact includes theft of intellectual property, customer data, source code, credentials, financial records, and other sensitive information through channels that appear as normal business activity.

Detection requires monitoring web service usage patterns, tracking uploads to cloud storage platforms, identifying unusual volumes of data transfer to external services, and correlating web service activity with data staging and collection behaviors. Organizations should establish baselines for legitimate web service usage and alert on anomalies such as uploads from servers, large file transfers during off-hours, use of personal accounts from corporate systems, uploads immediately following data collection, or access to web services from unexpected processes.

---

## Key Detection Indicators & Areas to Investigate

### Summary of Indicators

1. Uploads to cloud storage services (Dropbox, Google Drive, OneDrive) (T1567.002)
2. Code repository uploads (GitHub, GitLab, Pastebin) (T1567.001)
3. File sharing service usage (WeTransfer, Mega, FileZilla)
4. Social media platform data exfiltration
5. Web-based email attachments to external accounts
6. Collaboration tool abuse (Slack, Teams, Discord webhooks)
7. Large file uploads from servers or unexpected systems
8. Web service access from non-browser processes
9. Personal account usage from corporate systems
10. Web service uploads during off-hours or by service accounts

---

### 1. Uploads to Cloud Storage Services (Dropbox, Google Drive, OneDrive)

**Proxy Logs:**

- HTTP/HTTPS POST requests to cloud storage domains
- Upload operations to cloud storage APIs
- File upload sizes and frequencies
- User-agent strings and API endpoints

**DNS Logs:**

- Queries to cloud storage domains
- Subdomain patterns indicating API usage
- Query frequency from specific hosts

**Sysmon:**

- Event ID 3 (Network connection) - Connections to cloud storage IPs
- Event ID 22 (DNS query) - Cloud storage domain queries
- Event ID 1 (Process creation) - Cloud sync client execution

**Cloud Storage Domains:**

- Dropbox: `*.dropbox.com`, `*.dropboxapi.com`
- Google Drive: `drive.google.com`, `docs.google.com`, `*.googleapis.com`
- OneDrive: `*.onedrive.com`, `*.sharepoint.com`
- Box: `*.box.com`, `api.box.com`
- iCloud: `*.icloud.com`

**Focus on:**

- Large file uploads to cloud storage from corporate systems
- Cloud storage access from servers or non-user systems
- Uploads immediately following data staging or collection
- Personal cloud accounts accessed from corporate infrastructure
- Uploads during off-hours or by service accounts

**Suspicious indicators:**

- HTTP POST requests >50MB to `content.dropboxapi.com` or `www.googleapis.com/upload/drive`
- Cloud storage uploads from servers, databases, or domain controllers
- Multiple sequential uploads to cloud storage within short timeframe
- Uploads from processes other than browsers: `powershell.exe`, `python.exe`, custom scripts
- Personal Dropbox/Google Drive accounts accessed from corporate systems
- Cloud sync clients (`Dropbox.exe`, `OneDrive.exe`) executed from `%TEMP%` or portable installations
- API-based uploads using access tokens or OAuth credentials
- Uploads occurring between 00:00-06:00 local time from inactive user accounts
- File upload patterns matching staged archive names: `data.zip`, `backup.rar`
- Cloud storage connections from service accounts or system processes

---

### 2. Code Repository Uploads (GitHub, GitLab, Pastebin)

**Proxy Logs:**

- HTTP POST requests to code repository domains
- Git push operations and API calls
- Pastebin or text sharing service uploads
- Content-Type headers indicating file uploads

**DNS Logs:**

- Queries to code repository domains
- Gist and Pastebin service domains
- API endpoint subdomains

**Sysmon:**

- Event ID 3 (Network connection) - Connections to repository services
- Event ID 1 (Process creation) - Git client execution
- Event ID 22 (DNS query) - Repository domain queries

**Code Repository Domains:**

- GitHub: `github.com`, `api.github.com`, `gist.github.com`
- GitLab: `gitlab.com`, `*.gitlab.io`
- Bitbucket: `bitbucket.org`, `api.bitbucket.org`
- Pastebin: `pastebin.com`, `pastebin.pl`
- Paste sites: `paste.ee`, `privatebin.net`, `ghostbin.com`

**Focus on:**

- Repository creation or uploads from non-developer systems
- Pastebin usage for non-code content
- Large binary file uploads to repositories
- Private repository creation with sensitive data
- Git push operations from unexpected users or systems

**Suspicious indicators:**

- Git push operations from servers, workstations, or non-development systems
- Repository creation with names like `backup`, `data`, `files`, `temp`
- Pastebin uploads containing base64-encoded data or non-code content
- HTTP POST to `api.github.com/repos` creating private repositories
- Large files (>10MB) uploaded to GitHub/GitLab from corporate systems
- Gist creation with `.zip`, `.rar`, `.7z` file attachments
- Git commands executed by non-developer accounts: `git init`, `git remote add`, `git push`
- Pastebin uploads from `powershell.exe`, `cmd.exe`, or scripts
- Repository uploads immediately following data collection or archiving
- Personal GitHub accounts accessed from corporate infrastructure for uploads

---

### 3. File Sharing Service Usage (WeTransfer, Mega, Send Anywhere)

**Proxy Logs:**

- HTTP POST requests to file sharing domains
- Upload operation patterns and file sizes
- Download link generation
- Multi-part upload patterns

**DNS Logs:**

- Queries to file sharing service domains
- API and upload subdomain patterns

**Network Logs:**

- Large outbound transfers to file sharing services
- Sustained connections for large file uploads

**Sysmon:**

- Event ID 3 (Network connection) - File sharing service connections
- Event ID 22 (DNS query) - File sharing domain queries

**File Sharing Domains:**

- WeTransfer: `wetransfer.com`, `*.wetransfer.com`
- Mega: `mega.nz`, `mega.io`
- Send Anywhere: `send-anywhere.com`
- MediaFire: `mediafire.com`, `*.mediafire.com`
- Filemail: `filemail.com`
- Firefox Send alternatives: `send.vis.ee`, `send.tresorit.com`

**Focus on:**

- File sharing service usage from corporate systems
- Large file uploads to temporary sharing services
- Uploads from non-user systems or servers
- File sharing during off-hours
- Multiple uploads to same or different sharing services

**Suspicious indicators:**

- Uploads >100MB to WeTransfer or Mega from corporate workstations
- File sharing service usage from servers, databases, or infrastructure systems
- Multiple sequential uploads to file sharing platforms within 1-hour window
- Uploads during off-hours (00:00-06:00) or weekends
- File names suggesting sensitive data: `database_backup.zip`, `customer_data.rar`
- File sharing from service accounts or system processes
- Upload links generated then accessed from external networks immediately
- Browser uploads of recently created archives from staging directories
- Multiple file sharing services used in sequence (evading per-service monitoring)
- Uploads from processes other than browsers: PowerShell with `Invoke-WebRequest`

---

### 4. Social Media Platform Data Exfiltration

**Proxy Logs:**

- HTTP POST requests to social media domains
- File upload operations (images, videos, documents)
- Direct message API calls
- Media upload endpoints

**DNS Logs:**

- Social media domain queries
- API and media upload subdomains

**Sysmon:**

- Event ID 3 (Network connection) - Social media connections
- Event ID 22 (DNS query) - Social media domain queries
- Event ID 1 (Process creation) - Social media API scripts

**Social Media Platforms:**

- Twitter: `twitter.com`, `api.twitter.com`, `upload.twitter.com`
- Facebook: `facebook.com`, `graph.facebook.com`
- Instagram: `instagram.com`, `*.cdninstagram.com`
- LinkedIn: `linkedin.com`, `api.linkedin.com`
- Reddit: `reddit.com`, `api.reddit.com`
- Imgur: `imgur.com`, `api.imgur.com`

**Focus on:**

- Social media uploads from corporate systems during work hours
- Media uploads (images, videos) from non-user systems
- API-based posting or messaging from scripts
- Direct message usage for data transfer
- Image uploads with potential steganography

**Suspicious indicators:**

- Twitter API uploads from `powershell.exe` or Python scripts
- Large image/video uploads to social media from servers or workstations
- Direct message API calls sending files or links to download sites
- Imgur or image hosting uploads from non-browser processes
- Social media posts containing download links or encoded data
- Twitter DMs or Facebook messages with file attachments from corporate systems
- API authentication tokens used for automated posting
- Multiple image uploads to Instagram/Imgur within short timeframe
- Social media activity from service accounts or during off-hours
- Posts containing pastebin links, GitHub gists, or file sharing URLs

---

### 5. Web-Based Email Attachments to External Accounts

**Proxy Logs:**

- HTTP POST requests to webmail services
- Email composition and send operations
- Attachment upload patterns
- SMTP submission via web interfaces

**DNS Logs:**

- Webmail service domain queries
- Email provider API domains

**Sysmon:**

- Event ID 3 (Network connection) - Webmail service connections
- Event ID 22 (DNS query) - Webmail domain queries

**Webmail Services:**

- Gmail: `mail.google.com`, `gmail.com`
- Outlook.com: `outlook.live.com`, `outlook.office365.com`
- Yahoo Mail: `mail.yahoo.com`
- ProtonMail: `protonmail.com`
- Tutanota: `tutanota.com`
- Temporary email: `guerrillamail.com`, `temp-mail.org`

**Focus on:**

- Webmail access from corporate systems
- Large attachments sent to external personal accounts
- Emails to personal accounts from corporate infrastructure
- Webmail usage from servers or non-user systems
- Multiple emails with attachments sent in sequence

**Suspicious indicators:**

- Gmail/Outlook.com accessed from corporate systems sending emails with >10MB attachments
- Multiple emails with attachments sent to same external personal account
- Webmail usage from servers, databases, or infrastructure systems
- Attachments matching staged file names: `backup.zip`, `data.rar`, `export.7z`
- Emails sent during off-hours (00:00-06:00) from corporate systems
- Temporary or anonymous email services accessed from corporate infrastructure
- ProtonMail or encrypted email services used for data transfer
- Sequential emails with attachments within 30-minute window
- Webmail accessed by processes other than browsers
- Email attachments sent immediately after archive creation or file staging

---

### 6. Collaboration Tool Abuse (Slack, Teams, Discord Webhooks)

**Proxy Logs:**

- HTTP POST requests to collaboration platform APIs
- Webhook invocations with data payloads
- File upload operations to chat platforms
- API authentication and usage patterns

**DNS Logs:**

- Collaboration platform domain queries
- Webhook and API subdomain patterns

**Sysmon:**

- Event ID 3 (Network connection) - Collaboration tool connections
- Event ID 22 (DNS query) - Platform domain queries
- Event ID 1 (Process creation) - Scripts invoking webhooks

**Collaboration Platforms:**

- Slack: `slack.com`, `hooks.slack.com`, `files.slack.com`
- Microsoft Teams: `teams.microsoft.com`, `*.sharepoint.com`
- Discord: `discord.com`, `discordapp.com`, `*.discord.com`
- Mattermost: `mattermost.com`
- Rocket.Chat: `rocket.chat`

**Focus on:**

- Webhook usage from servers or automated scripts
- File uploads to collaboration platforms from corporate systems
- API-based messaging with data payloads
- Collaboration tool usage from non-user systems
- Webhooks invoked from unexpected processes

**Suspicious indicators:**

- Discord webhook POST requests: `https://discord.com/api/webhooks/*/` from PowerShell or scripts
- Slack incoming webhook calls with large message payloads or file attachments
- Teams file uploads from servers, databases, or non-user systems
- Webhook invocations containing base64-encoded data or file contents
- Multiple webhook calls within short timeframe from same system
- Collaboration platform API usage from `powershell.exe`, `python.exe`, `curl.exe`
- File uploads to Slack/Discord from staging directories: `%TEMP%`, `C:\Users\Public\`
- Personal Slack workspaces or Discord servers accessed from corporate systems
- Webhook URLs in scripts or scheduled tasks for automated exfiltration
- Collaboration platform usage during off-hours from service accounts

---

### 7. Large File Uploads from Servers or Unexpected Systems

**Network Logs:**

- Netflow/IPFIX - Large outbound transfers from servers
- Firewall logs - High-volume uploads to external web services
- Bandwidth monitoring - Upload spikes from infrastructure systems

**Proxy Logs:**

- Large HTTP POST requests from server IPs
- Upload operations from non-user systems
- File transfer sizes and destinations

**Sysmon:**

- Event ID 3 (Network connection) - Server network connections
- Event ID 11 (File created) - Files staged on servers before upload

**SIEM Correlation:**

- Baseline normal upload behavior per system type
- Alert on servers uploading data to external web services
- Track upload volumes exceeding thresholds

**Focus on:**

- Database servers uploading to web services
- File servers transferring data externally
- Domain controllers with external uploads
- Application servers accessing cloud storage
- Infrastructure systems using personal web services

**Suspicious indicators:**

- SQL Server, Oracle, or MySQL database servers uploading >100MB to external web services
- File servers or NAS devices establishing connections to Dropbox, Google Drive, or file sharing sites
- Domain controllers accessing cloud storage or file sharing platforms
- Web servers (IIS, Apache, Nginx) uploading files to external services
- Exchange servers or mail systems uploading to personal cloud storage
- Backup servers transferring data to non-approved cloud storage
- VMware or Hyper-V hosts accessing external file sharing services
- SCADA or IoT systems establishing connections to public web services
- Upload volumes from servers exceeding 1GB within 24-hour period
- Infrastructure systems accessing web services during maintenance windows

---

### 8. Web Service Access from Non-Browser Processes

**Sysmon:**

- Event ID 3 (Network connection) - Web service connections from unexpected processes
- Event ID 1 (Process creation) - Scripts or tools accessing web services
- Event ID 22 (DNS query) - Web service domains queried by non-browsers

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Command-line tools with web service URLs
- Event ID 5156 (Windows Filtering Platform) - Connections from unexpected processes

**Processes to Monitor:**

- `powershell.exe`, `cmd.exe`
- `python.exe`, `ruby.exe`, `perl.exe`
- `curl.exe`, `wget.exe`
- `certutil.exe`, `bitsadmin.exe`
- Custom executables from `%TEMP%` or `%APPDATA%`

**Focus on:**

- PowerShell scripts uploading to web services
- Command-line tools accessing cloud storage APIs
- Custom executables connecting to file sharing services
- Scripting languages accessing web service endpoints
- Non-browser processes with web service API authentication

**Suspicious indicators:**

- `powershell.exe` with `Invoke-WebRequest` or `Invoke-RestMethod` uploading to Dropbox API
- Python scripts accessing Google Drive API: `from googleapiclient.discovery import build`
- `curl.exe` uploading files to WeTransfer or file sharing services
- `certutil.exe` with URL parameters accessing web services (abuse of legitimate tool)
- Custom executables from `%TEMP%` establishing HTTPS connections to cloud storage
- PowerShell commands with OAuth tokens or API keys for web service authentication
- Scheduled tasks executing scripts that upload to external web services
- Service processes accessing personal cloud storage APIs
- Git client (`git.exe`) from non-developer systems pushing to external repositories
- Background processes establishing connections to Slack webhooks or Discord APIs

---

### 9. Personal Account Usage from Corporate Systems

**Proxy Logs:**

- Authentication to personal accounts from corporate IPs
- User-agent strings indicating personal account sessions
- Cookie analysis showing multiple account usage
- Session tokens for personal vs. corporate accounts

**DNS Logs:**

- Personal email domain queries from corporate systems
- Personal cloud storage account access

**SIEM Correlation:**

- Track account identifiers in web traffic
- Correlate personal account usage with data transfers
- Monitor for account switching patterns

**Authentication Indicators:**

- Login to personal Gmail/Outlook.com accounts
- Personal Dropbox/Drive account authentication
- Personal GitHub account access
- Social media personal accounts from work systems

**Focus on:**

- Personal accounts accessed during work hours
- Account switching from corporate to personal
- File transfers to personal accounts
- Personal account usage from servers or infrastructure
- Data upload timing correlating with personal account authentication

**Suspicious indicators:**

- Personal Gmail account authentication from corporate workstation followed by large email with attachment
- Dropbox personal account login from corporate system with subsequent 500MB upload
- Corporate Google Drive session switching to personal Drive session with file transfers
- GitHub personal account accessed from corporate developer workstation with private repo creation
- Personal OneDrive authenticated from file server or database server
- Multiple account switches within same session: corporate → personal → upload → logout
- Personal cloud storage accounts accessed by employees with access to sensitive data
- Personal account usage during data collection or staging activities
- Service accounts or shared credentials accessing personal external services
- Personal account authentication from systems that should only use corporate accounts

---

### 10. Web Service Uploads During Off-Hours or by Service Accounts

**SIEM Correlation:**

- Correlate upload activity with user work schedules
- Track service account web service usage
- Monitor time-based patterns for automated exfiltration

**Proxy Logs:**

- Web service uploads outside business hours
- Upload timestamps vs. user typical work patterns
- Service account authentication to web services

**Windows Event Logs (Security):**

- Event ID 4624 (Logon) - Service account interactive logons
- Event ID 4688 (Process creation) - Service account process execution

**Sysmon:**

- Event ID 3 (Network connection) - Off-hours web service connections
- Event ID 1 (Process creation) - Processes running under service accounts

**Focus on:**

- Uploads during nights, weekends, holidays
- Service accounts accessing web services
- Automated scheduled uploads
- Upload timing designed to evade detection
- Web service access when users should be inactive

**Suspicious indicators:**

- Cloud storage uploads occurring between 02:00-05:00 local time from user accounts
- Weekend uploads from employees who typically work Monday-Friday
- Service accounts (`svc_*`, `SYSTEM`, `NetworkService`) accessing Dropbox or Google Drive
- Scheduled task executing at 03:00 daily uploading files to file sharing services
- Holiday period uploads when organization is closed
- Web service uploads from VDI sessions during times when user is logged out
- Service account authentication to personal cloud storage or file sharing platforms
- Multiple systems showing coordinated off-hours uploads to same web service
- Upload patterns matching backup schedules but to unauthorized cloud storage
- Web service API calls from service accounts executing PowerShell scripts during off-hours
---
# Exfiltration Over Web Service Investigation Checklist

## 1. Cloud Storage Service Uploads

- [ ] Review proxy logs for HTTP POST >50MB to content.dropboxapi.com, googleapis.com/upload/drive
- [ ] Check cloud storage uploads from servers, databases, or domain controllers
- [ ] Monitor DNS queries to *.dropbox.com, drive.google.com, *.onedrive.com from unexpected systems
- [ ] Identify uploads from powershell.exe, python.exe, custom scripts vs. browsers
- [ ] Look for personal Dropbox/Google Drive accounts accessed from corporate systems
- [ ] Check cloud sync clients executed from %TEMP% or portable installations
- [ ] Review uploads between 00:00-06:00 from inactive user accounts
- [ ] Monitor file patterns: data.zip, backup.rar in upload names

## 2. Code Repository Uploads

- [ ] Check Git push operations from servers, workstations, non-development systems
- [ ] Review repository creation with names: backup, data, files, temp
- [ ] Monitor Pastebin uploads containing base64-encoded data or non-code content
- [ ] Identify HTTP POST to api.github.com/repos creating private repositories
- [ ] Look for large files (>10MB) uploaded to GitHub/GitLab from corporate systems
- [ ] Check Gist creation with .zip, .rar, .7z attachments
- [ ] Review Git commands by non-developer accounts: git init, git remote add, git push
- [ ] Monitor personal GitHub accounts accessed for uploads from corporate infrastructure

## 3. File Sharing Service Usage

- [ ] Review uploads >100MB to WeTransfer, Mega, Send Anywhere from workstations
- [ ] Check file sharing from servers, databases, infrastructure systems
- [ ] Monitor multiple sequential uploads to sharing platforms within 1-hour window
- [ ] Identify uploads during off-hours (00:00-06:00) or weekends
- [ ] Look for file names: database_backup.zip, customer_data.rar
- [ ] Check file sharing from service accounts or system processes
- [ ] Review upload links generated then accessed from external networks immediately
- [ ] Monitor PowerShell Invoke-WebRequest uploads to file sharing services

## 4. Social Media Data Exfiltration

- [ ] Check Twitter API uploads from powershell.exe or Python scripts
- [ ] Review large image/video uploads to social media from servers/workstations
- [ ] Monitor Direct message API calls sending files or download links
- [ ] Identify Imgur or image hosting uploads from non-browser processes
- [ ] Look for social media posts containing pastebin links, GitHub gists, file sharing URLs
- [ ] Check API authentication tokens used for automated posting
- [ ] Review social media activity from service accounts or during off-hours
- [ ] Monitor multiple image uploads to Instagram/Imgur within short timeframe

## 5. Web-Based Email Attachments

- [ ] Review Gmail/Outlook.com accessed from corporate systems sending >10MB attachments
- [ ] Check multiple emails with attachments to same external personal account
- [ ] Monitor webmail from servers, databases, infrastructure systems
- [ ] Identify attachments matching staged files: backup.zip, data.rar, export.7z
- [ ] Look for emails sent during off-hours (00:00-06:00) from corporate systems
- [ ] Check temporary/anonymous email services: guerrillamail.com, temp-mail.org
- [ ] Review ProtonMail or encrypted email for data transfer
- [ ] Monitor sequential emails with attachments within 30-minute window

## 6. Collaboration Tool Abuse

- [ ] Check Discord webhook POST: https://discord.com/api/webhooks/*/ from PowerShell/scripts
- [ ] Review Slack webhook calls with large payloads or file attachments
- [ ] Monitor Teams file uploads from servers, databases, non-user systems
- [ ] Identify webhook invocations with base64-encoded data or file contents
- [ ] Look for multiple webhook calls within short timeframe from same system
- [ ] Check collaboration platform API usage from powershell.exe, python.exe, curl.exe
- [ ] Review file uploads to Slack/Discord from %TEMP%, C:\Users\Public\
- [ ] Monitor webhook URLs in scripts or scheduled tasks

## 7. Server and Infrastructure Uploads

- [ ] Review database servers (SQL, Oracle, MySQL) uploading >100MB to external services
- [ ] Check file servers or NAS accessing Dropbox, Google Drive, file sharing sites
- [ ] Monitor domain controllers accessing cloud storage or file sharing platforms
- [ ] Identify web servers (IIS, Apache, Nginx) uploading to external services
- [ ] Look for Exchange servers uploading to personal cloud storage
- [ ] Check backup servers transferring to non-approved cloud storage
- [ ] Review VMware/Hyper-V hosts accessing external file sharing
- [ ] Monitor upload volumes from servers exceeding 1GB within 24 hours

## 8. Non-Browser Process Web Access

- [ ] Check powershell.exe with Invoke-WebRequest/Invoke-RestMethod to Dropbox API
- [ ] Review Python scripts accessing Google Drive API
- [ ] Monitor curl.exe uploading to WeTransfer or file sharing services
- [ ] Identify certutil.exe with URL parameters accessing web services
- [ ] Look for custom executables from %TEMP% connecting to cloud storage
- [ ] Check PowerShell with OAuth tokens or API keys for web service auth
- [ ] Review scheduled tasks executing upload scripts
- [ ] Monitor git.exe from non-developer systems pushing to external repos

## 9. Personal Account Usage

- [ ] Review personal Gmail authentication followed by large email with attachment
- [ ] Check Dropbox personal account login with subsequent 500MB+ upload
- [ ] Monitor corporate → personal Drive session switches with file transfers
- [ ] Identify GitHub personal account with private repo creation from corporate systems
- [ ] Look for personal OneDrive authenticated from file/database servers
- [ ] Check account switches: corporate → personal → upload → logout
- [ ] Review personal accounts by employees with access to sensitive data
- [ ] Monitor service accounts accessing personal external services

## 10. Off-Hours and Service Account Activity

- [ ] Review cloud storage uploads between 02:00-05:00 local time
- [ ] Check weekend uploads from Monday-Friday only employees
- [ ] Monitor service accounts (svc_*, SYSTEM) accessing Dropbox/Google Drive
- [ ] Identify scheduled tasks at 03:00 uploading to file sharing services
- [ ] Look for holiday period uploads when organization closed
- [ ] Check VDI web service uploads when user logged out
- [ ] Review service account PowerShell scripts uploading during off-hours
- [ ] Timeline: Data staging → Off-hours upload → External web service