# Phishing: [T1566](https://attack.mitre.org/techniques/T1566/)

## Detection Explanation

Adversaries may send phishing messages to gain access to victim systems. Phishing involves sending fraudulent messages designed to trick users into revealing credentials, downloading malware, or performing actions that compromise security. This includes spearphishing attachments (T1566.001), spearphishing links (T1566.002), and spearphishing via service (T1566.003).

## Key Detection Indicators & Areas to Investigate

### Suspicious email characteristics and metadata anomalies

**Email Gateway Logs:**

- Sender Policy Framework (SPF) failures
- DomainKeys Identified Mail (DKIM) validation failures
- Domain-based Message Authentication, Reporting & Conformance (DMARC) failures
- Mismatched sender/reply-to addresses
- Email from newly registered domains (< 30 days old)

**Email headers to analyze:**

- `From:` vs `Reply-To:` discrepancies
- `Return-Path:` domain mismatches
- `Received:` headers showing suspicious routing
- `X-Originating-IP:` from unexpected geolocations
- `Message-ID:` format anomalies

**Content patterns:**

- Domain typosquatting: `micros0ft.com`, `paypa1.com`, `goog1e.com`
- International character substitution (homograph attacks)
- Generic greetings: "Dear Customer", "Dear User"
- Urgency indicators: "Urgent", "Immediate action required", "Account will be suspended"

---

### Malicious attachments and file types

**Suspicious file types:**

- Executables: `.exe`, `.dll`, `.scr`, `.pif`, `.com`, `.bat`, `.cmd`
- Office macros: `.doc`, `.docm`, `.xls`, `.xlsm`, `.ppt`, `.pptm` with macros enabled
- Archives: `.zip`, `.rar`, `.7z`, `.iso`, `.img` (especially password-protected)
- Scripts: `.vbs`, `.js`, `.jse`, `.wsf`, `.hta`
- Shortcuts: `.lnk` files
- Double extensions: `invoice.pdf.exe`, `document.docx.js`

**Windows Event Logs (Post-Delivery):**

- Event ID 4688 (Process creation) - Attachment execution
- Event ID 8003 (Windows Defender) - Malware detected in downloads

**Sysmon:**

- Event ID 11 (File creation) - Attachments saved to disk in temporary folders, downloads, desktop
- Event ID 1 (Process creation) - Office applications spawning unusual child processes

---

### Malicious URLs and link analysis

**URL characteristics:**

- Shortened URLs: `bit.ly`, `tinyurl.com`, `goo.gl`
- Suspicious TLDs: `.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.xyz`
- Domain age (newly registered)
- Misleading anchor text vs actual URL
- URLs with embedded credentials: `http://user:pass@malicious.com`
- Obfuscated URLs: IP addresses, hex encoding, URL encoding

**DNS Logs:**

- Queries to newly registered domains
- Queries to domains with poor reputation
- DGA (Domain Generation Algorithm) patterns

---

### Credential harvesting and fake login pages

**Web Proxy Logs:**

- Access to spoofed login pages
- HTTP POST to non-organizational authentication endpoints
- Form submissions to suspicious domains

**Browser indicators:**

- Missing HTTPS/TLS on login pages
- Certificate warnings or invalid certificates
- URL bar showing non-company domains for company logins

**Behavioral patterns:**

- User accessing corporate login page from external link
- Multiple credential entry attempts on fake pages
- Immediate password change attempts after clicking email link

**Authentication Logs:**

- Failed login attempts following phishing email timestamps
- Successful logins from unusual locations after email interaction
- Account compromise indicators shortly after email delivery

---

### Office macro execution and document exploitation

**Sysmon:**

- Event ID 1 (Process creation) - Office applications spawning child processes

**Suspicious parent-child relationships:**

- `winword.exe` → `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`
- `excel.exe` → `mshta.exe`, `regsvr32.exe`, `rundll32.exe`
- `powerpnt.exe` → Network connections or file downloads
- `outlook.exe` → Suspicious script execution

**Windows Event Logs:**

- Event ID 4688 (Process creation) - Office macro spawning processes
- Event ID 4104 (PowerShell script block logging) - Scripts launched from documents

**Registry:**

- `HKCU\Software\Microsoft\Office\[Version]\[Application]\Security\Trusted Documents` - Tracked documents with macros

---

### Post-click payload delivery and execution

**Sysmon:**

- Event ID 3 (Network connection) - Browser or email client connections to suspicious IPs
- Event ID 11 (File creation) - Downloads to temporary directories, user downloads folder
- Event ID 1 (Process creation) - Execution of downloaded payloads

**Download locations to monitor:**

- `%USERPROFILE%\Downloads\`
- `%USERPROFILE%\AppData\Local\Temp\`
- `%TEMP%\`
- Browser cache directories

**Network Logs:**

- HTTP/HTTPS downloads following email link clicks
- Connections to file-sharing services: Dropbox, Google Drive, OneDrive from email links
- Large file downloads from unknown sources

**Web Gateway Logs:**

- File download type and size
- Download from domains with poor reputation
- Executable downloads

---

### Browser-based attacks and drive-by downloads

**Exploit indicators:**

- Attempts to access known CVE exploitation URLs
- Browser plugin crashes or errors
- Flash, Java, or ActiveX execution attempts

**Sysmon:**

- Event ID 7 (Image/DLL loaded) - Suspicious DLL loads by browser processes
- Event ID 8 (CreateRemoteThread) - Code injection into browser processes

**Windows Event Logs:**

- Event ID 1001 (Application Error) - Browser crashes
- Event ID 1000 (Application Error) - Plugin failures

---

### Spearphishing via collaboration platforms

**Application Logs:**

- Microsoft Teams messages with external links
- Slack direct messages from external users
- LinkedIn InMail with suspicious links
- WhatsApp/Signal messages with links

**SaaS Security Logs:**

- Office 365 audit logs - External sharing events
- Google Workspace logs - Drive file shares with external users
- Collaboration platform API calls

**Focus on:**

- Messages from newly added external contacts
- Links to credential harvesting in chat platforms
- File shares containing malicious documents
- Direct messages with urgency or authority themes

---

### Email forwarding rules and account compromise indicators

**Office 365/Exchange Logs:**

- Mailbox audit logs showing new forwarding rules
- Event: `New-InboxRule`, `Set-InboxRule` PowerShell commands
- Auto-forwarding to external domains

**Suspicious rule characteristics:**

- Forward to external email addresses
- Delete after forwarding (hiding evidence)
- Rules created shortly after credential compromise
- Rules with specific keyword triggers

**Windows Event Logs (Exchange Servers):**

- Event ID 4688 (Process creation) - PowerShell creating mailbox rules

**User behavior:**

- Unusual sent items or deleted items
- Access from new devices/locations after phishing
- Large volumes of email access in short timeframes

---

### QR code phishing (Quishing)

**Email Gateway Logs:**

- Emails containing embedded images with QR codes
- Low text-to-image ratio emails

**Indicators:**

- QR codes in unexpected email contexts
- Emails with only QR code images and minimal text
- QR codes bypassing link scanning

**Mobile device logs:**

- Mobile browser access to suspicious URLs
- Camera app usage followed by browser activity
- Authentication attempts from mobile devices to fake login pages

**Detection approaches:**

- OCR/image analysis of email attachments
- QR code decoding and URL reputation checking
- Correlation of mobile device access with email delivery timing

---

### Vishing (voice phishing) coordination

**Phone System Logs:**

- VoIP call logs with spoofed caller IDs
- High volume of calls to specific users
- International calls claiming to be from local numbers

**Email correlation:**

- Emails referencing phone calls or callbacks
- Phone numbers in email signatures that don't match company directory
- Messages instructing to call specific numbers

**Help Desk Logs:**

- Calls about suspicious voicemails
- Users reporting unexpected authentication requests
- MFA push notification bombing reports

---

### Social engineering and pretexting indicators

**Email content analysis:**

- Authority impersonation: CEO, CFO, IT department
- Business Email Compromise (BEC) patterns
- Invoice fraud attempts
- W-2/tax information requests
- Wire transfer requests

**Contextual red flags:**

- Requests outside normal business processes
- Pressure tactics and urgency
- Requests to bypass security controls
- Appeals to authority or fear

**User reporting:**

- Phishing report button usage in email client
- Help desk tickets about suspicious emails
- Security awareness training simulations triggered

---

### Multi-factor authentication (MFA) bypass attempts

**Authentication Logs:**

- MFA push notification spam (MFA fatigue attacks)
- Multiple MFA denials followed by approval
- MFA enrollment changes after suspicious email

**Indicators:**

- Repeated MFA challenges to same user in short timeframe
- MFA challenges at unusual times
- New device registrations after phishing email
- Password reset followed by MFA re-enrollment

**Azure AD/Okta Logs:**

- Event: User denied MFA prompt (repeated)
- Event: MFA method changed
- Event: New device registered
----

# Phishing Attack Investigation Checklist

## 1. Email Authentication and Metadata

- [ ]  Check email gateway logs for SPF, DKIM, and DMARC failures
- [ ]  Review From: vs Reply-To: discrepancies in email headers
- [ ]  Verify Return-Path: domain matches sender domain
- [ ]  Check X-Originating-IP: for unexpected geolocations
- [ ]  Identify emails from newly registered domains (< 30 days old)
- [ ]  Look for domain typosquatting: micros0ft.com, paypa1.com, goog1e.com

## 2. Malicious Attachments

- [ ]  Search for suspicious file types: .exe, .scr, .pif, .bat, .vbs, .js, .hta, .lnk
- [ ]  Check for Office files with macros: .docm, .xlsm, .pptm
- [ ]  Identify password-protected archives: .zip, .rar, .7z, .iso
- [ ]  Look for double extensions: invoice.pdf.exe, document.docx.js
- [ ]  Review Event ID 8003/Windows Defender logs for malware detections
- [ ]  Check Sysmon Event ID 11 for attachments saved to Downloads, Temp, Desktop

## 3. Malicious URLs and Links

- [ ]  Identify shortened URLs: bit.ly, tinyurl.com, goo.gl
- [ ]  Check for suspicious TLDs: .tk, .ml, .ga, .cf, .gq, .xyz
- [ ]  Review DNS logs for queries to newly registered or poor reputation domains
- [ ]  Look for obfuscated URLs: IP addresses, hex encoding, embedded credentials
- [ ]  Verify anchor text matches actual URL destination
- [ ]  Check web proxy logs for access to spoofed login pages

## 4. Credential Harvesting Indicators

- [ ]  Review web proxy logs for HTTP POST to non-organizational authentication endpoints
- [ ]  Check for form submissions to suspicious domains
- [ ]  Identify missing HTTPS/TLS or invalid certificates on login pages
- [ ]  Correlate failed/successful logins with phishing email timestamps
- [ ]  Look for successful logins from unusual locations after email interaction
- [ ]  Monitor for immediate password change attempts after link clicks

## 5. Office Macro Execution

- [ ]  Check Sysmon Event ID 1 for Office apps spawning child processes
- [ ]  Identify suspicious chains: winword.exe → powershell.exe, cmd.exe, wscript.exe
- [ ]  Review excel.exe → mshta.exe, regsvr32.exe, rundll32.exe patterns
- [ ]  Check Event ID 4688/4104 for Office macro spawning scripts
- [ ]  Review HKCU...\Office...\Security\Trusted Documents registry for macro-enabled files

## 6. Payload Downloads and Execution

- [ ]  Monitor Sysmon Event ID 3 for browser/email client connections to suspicious IPs
- [ ]  Check Sysmon Event ID 11 for files created in %USERPROFILE%\Downloads, %TEMP%\
- [ ]  Review Sysmon Event ID 1 for execution of downloaded payloads
- [ ]  Identify large file downloads from unknown sources in web gateway logs
- [ ]  Check for connections to file-sharing services (Dropbox, Google Drive) from email links

## 7. Collaboration Platform Phishing

- [ ]  Review Microsoft Teams/Slack logs for external messages with links
- [ ]  Check Office 365 audit logs for external file sharing events
- [ ]  Identify messages from newly added external contacts
- [ ]  Look for direct messages with urgency or authority themes
- [ ]  Monitor Google Workspace logs for Drive shares with external users

## 8. Email Forwarding Rules

- [ ]  Check mailbox audit logs for New-InboxRule or Set-InboxRule commands
- [ ]  Identify auto-forwarding rules to external domains
- [ ]  Look for rules that delete after forwarding
- [ ]  Review rules created shortly after credential compromise
- [ ]  Monitor Event ID 4688 for PowerShell creating mailbox rules

## 9. MFA Bypass Attempts

- [ ]  Check authentication logs for MFA push notification spam (multiple rapid attempts)
- [ ]  Identify multiple MFA denials followed by approval
- [ ]  Review MFA enrollment changes after suspicious emails
- [ ]  Look for new device registrations following phishing attempts
- [ ]  Monitor Azure AD/Okta for MFA method changes or repeated denials

## 10. Social Engineering Patterns

- [ ]  Search for authority impersonation: CEO, CFO, IT department in sender names
- [ ]  Identify Business Email Compromise (BEC) patterns: wire transfers, W-2 requests
- [ ]  Look for urgency indicators: "Urgent", "Immediate action", "Account suspended"
- [ ]  Check for generic greetings: "Dear Customer", "Dear User"
- [ ]  Review help desk tickets for phishing reports or suspicious email inquiries

## 11. Post-Compromise Activity

- [ ]  Timeline: Email delivery → Link click → Credential use from attacker IP
- [ ]  Correlate attachment download → Process execution → C2 communication
- [ ]  Check for account compromise indicators shortly after email delivery
- [ ]  Review failed login attempts following phishing email timestamps
- [ ]  Monitor for lateral movement or data access after email interaction