# Archive Collected Data: [T1560](https://attack.mitre.org/techniques/T1560/)

## Detection Explanation

Archive Collected Data involves adversaries compressing or encrypting data before exfiltration to reduce file size, evade detection, or encrypt sensitive information. This technique is commonly used during the collection and exfiltration phases of an attack to package stolen data for efficient transfer and to obfuscate file contents from data loss prevention (DLP) systems and security monitoring tools.

Attackers archive collected data because compression reduces bandwidth requirements and transfer time, while encryption can bypass content-based detection mechanisms that scan for sensitive keywords or patterns. Common methods include using native operating system utilities (T1560.001) like 7-Zip, WinRAR, tar, and zip, as well as built-in utilities like Windows Compress-Archive cmdlet or Linux tar with compression. Adversaries may also use custom or less common archiving tools, password-protected archives, or split archives to evade detection and complicate forensic analysis.

Successful data archiving enables attackers to efficiently exfiltrate large volumes of data while minimizing network footprint, bypass DLP controls that cannot inspect encrypted or password-protected archives, and organize stolen data for systematic exfiltration. This technique often indicates late-stage attack activity where adversaries have already identified and collected target data and are preparing for exfiltration. The impact includes theft of intellectual property, customer data, financial records, credentials, and other sensitive information that can be sold, ransomed, or used for further attacks.

Detection requires monitoring for archiving utility execution, tracking creation of compressed or encrypted files, identifying unusual archive sizes or locations, and correlating archiving activity with data collection and exfiltration behaviors. Organizations should establish baselines for legitimate archive creation patterns and alert on anomalies such as archiving of sensitive directories, large archive creation during off-hours, use of command-line archiving tools by non-administrative users, or archives created immediately before network transfer activity.

---

## Key Detection Indicators & Areas to Investigate

### Summary of Indicators

1. Execution of archive and compression utilities (T1560.001)
2. Creation of compressed archive files in unusual locations (T1560.001)
3. Password-protected or encrypted archive creation
4. PowerShell-based compression and archiving
5. Large archive files created during off-hours
6. Archives created in staging directories before exfiltration
7. Command-line compression with suspicious parameters
8. Archives containing sensitive file types or directories
9. Split or multi-volume archive creation
10. Archive creation followed by network transfer activity

---

### 1. Execution of Archive and Compression Utilities

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Archive utility execution
- Key fields: `NewProcessName`, `CommandLine`, `ParentProcessName`, `SubjectUserName`

**Sysmon:**

- Event ID 1 (Process creation) - Archive tool execution with detailed command lines
- Key fields: `Image`, `CommandLine`, `ParentImage`, `User`, `CurrentDirectory`

**Common Archive Utilities:**

- `7z.exe`, `7za.exe` (7-Zip command line)
- `WinRAR.exe`, `Rar.exe`, `WinRar.exe`
- `zip.exe`, `unzip.exe`
- `tar.exe` (Windows 10/11 built-in)
- `compact.exe` (Windows compression utility)
- `makecab.exe` (Cabinet file creation)
- `expand.exe` (Cabinet extraction)

**Command-Line Patterns:**

- `7z.exe a -p<password> archive.7z C:\SensitiveData\`
- `rar.exe a -hp<password> data.rar C:\Users\*\Documents\`
- `tar.exe -czf archive.tar.gz /path/to/data`
- `powershell Compress-Archive -Path C:\Data -DestinationPath archive.zip`

**Focus on:**

- Archive utilities executed by non-administrative users
- Archiving tools run from temporary or unusual directories
- Command lines targeting sensitive directories (Documents, Desktop, Users)
- Archive creation with password or encryption parameters
- Tools executed during off-hours or by service accounts

**Suspicious indicators:**

- `7z.exe` or `rar.exe` with `-p` parameter (password protection) or `-hp` (encrypt headers)
- Archive utilities executed from `%TEMP%`, `%APPDATA%`, or `C:\Users\Public\`
- Command lines archiving entire user directories: `C:\Users\*`, `%USERPROFILE%\Documents\`
- Archiving system or sensitive directories: `C:\Windows\System32\`, `C:\Program Files\`, registry hives
- Tools executed by user accounts that don't typically perform archiving
- Archive utilities spawned from Office applications, browsers, or script interpreters
- Renamed archive utilities (e.g., `svchost.exe` that's actually 7z.exe)
- Archiving tools with output redirected to network shares or removable media
- Multiple archive operations in rapid succession across different directories
- Archive utilities executed during non-business hours (00:00-06:00)

---

### 2. Creation of Compressed Archive Files in Unusual Locations

**Sysmon:**

- Event ID 11 (File created) - Archive file creation
- Key fields: `TargetFilename`, `Image` (creating process), `User`
- File extensions: `.zip`, `.rar`, `.7z`, `.tar`, `.gz`, `.bz2`, `.cab`, `.tgz`

**Windows Event Logs (Security):**

- Event ID 4663 (Access attempted to object) - File write operations for archives
- Event ID 4656 (Handle to object requested) - File creation handles

**File Paths to Monitor:**

- `C:\Users\Public\` - Publicly accessible staging location
- `%TEMP%` or `%TMP%` - Temporary directories
- `C:\ProgramData\` - Application data staging
- `C:\Windows\Temp\` - System temporary directory
- `C:\Perflogs\` - Often abused staging location
- `C:\Intel\` - Mimics legitimate directory names
- Root of drives: `C:\`, `D:\` - Unusual archive locations

**Focus on:**

- Archive files created in non-standard locations
- Large archive files created rapidly
- Archives with suspicious or generic names
- Multiple archives created in same directory
- Archive creation in web server or database directories

**Suspicious indicators:**

- Archive files created in `C:\Users\Public\`, `C:\ProgramData\`, or `C:\Windows\Temp\`
- Large archives (>100MB) created in temporary directories
- File names suggesting data collection: `data.zip`, `backup.rar`, `files.7z`, `documents.zip`
- Archives with timestamps or date-based names: `2025-01-15.zip`, `backup_20250115.rar`
- Multiple archives with sequential numbering: `part1.zip`, `part2.zip`, `part3.zip`
- Archives created in web server directories: `C:\inetpub\wwwroot\`, `/var/www/html/`
- Archive files in database backup directories created by non-database processes
- Archives created in removable media root directories
- Files with double extensions: `invoice.pdf.zip`, `report.docx.rar`
- Archives created in network share roots or sync folders (Dropbox, OneDrive paths)

---

### 3. Password-Protected or Encrypted Archive Creation

**Sysmon:**

- Event ID 1 (Process creation) - Archive commands with encryption parameters
- Event ID 11 (File created) - Encrypted archive files

**Command-Line Indicators:**

- 7-Zip: `-p<password>`, `-hp<password>`, `-mhe=on` (encrypt headers)
- WinRAR: `-hp<password>`, `-p<password>`
- Zip: `-e`, `-P <password>`
- OpenSSL: `openssl enc -aes-256-cbc -in file.zip -out file.zip.enc`

**PowerShell Patterns:**

- `Compress-Archive` with password protection scripts
- Custom PowerShell encryption before or after archiving
- AES encryption cmdlets combined with compression

**Focus on:**

- Archive utilities executed with password or encryption parameters
- Archives created then encrypted with separate tools
- Use of encryption utilities on archive files
- Password-protected archives that bypass DLP inspection
- Encrypted archives staged before exfiltration

**Suspicious indicators:**

- Command lines containing `-p`, `-hp`, `-password`, or similar encryption flags
- `7z.exe a -p -mhe=on` (encrypts file names and content)
- Archive creation immediately followed by encryption tool execution
- `openssl`, `gpg`, or other encryption tools processing archive files
- PowerShell scripts combining `Compress-Archive` with encryption functions
- Archives with double extensions indicating encryption: `data.zip.aes`, `files.7z.enc`
- Encryption tools executed immediately after archive utility
- Password-protected archives created in staging directories
- Archives encrypted with strong algorithms (AES-256) suggesting data protection
- Archive and encryption operations occurring during off-hours

---

### 4. PowerShell-Based Compression and Archiving

**PowerShell Logs:**

- Event ID 4104 (Script block logging) - PowerShell compression commands
- Event ID 4103 (Module logging) - Compress-Archive cmdlet usage
- Event ID 400 (PowerShell engine state) - PowerShell session activity

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - PowerShell execution with compression

**Sysmon:**

- Event ID 1 (Process creation) - PowerShell with archive-related command lines
- Event ID 11 (File created) - Archives created by PowerShell processes

**PowerShell Cmdlets and Patterns:**

- `Compress-Archive -Path C:\Data -DestinationPath archive.zip`
- `Compress-Archive -Path C:\Users\* -DestinationPath users.zip -CompressionLevel Optimal`
- `[System.IO.Compression.ZipFile]::CreateFromDirectory("C:\Data", "data.zip")`
- Custom compression using .NET classes
- Base64-encoded compression commands

**Focus on:**

- PowerShell compression targeting sensitive directories
- Recursive archiving of user data or system folders
- Compression combined with encryption or obfuscation
- Archives created then immediately moved or transferred
- PowerShell compression in automated scripts or scheduled tasks

**Suspicious indicators:**

- Script blocks containing `Compress-Archive` targeting `C:\Users\`, `Documents`, `Desktop`
- PowerShell archiving entire user profiles or multiple user directories
- `[System.IO.Compression.ZipFile]` .NET methods in scripts
- Base64-encoded PowerShell commands decoding to compression operations
- PowerShell compression with output to network shares or cloud storage paths
- Compress-Archive with `-Force` parameter overwriting existing archives
- PowerShell scripts combining data collection, archiving, and network transfer
- Compression operations in PowerShell run via scheduled tasks or WMI
- Archives created by PowerShell spawned from Office macros or browsers
- PowerShell compression scripts downloaded from external sources then executed

---

### 5. Large Archive Files Created During Off-Hours

**Sysmon:**

- Event ID 11 (File created) - Large archive creation events
- Monitor file size and creation timestamp
- Key fields: `TargetFilename`, `CreationUtcTime`, `User`

**Windows Event Logs (Security):**

- Event ID 4663 (Access attempted to object) - Large file write operations
- Correlate with timestamp and user context

**File Size Thresholds:**

- Archives >100MB - Potentially significant data collection
- Archives >1GB - Large-scale data theft indicators
- Archives >10GB - Massive data exfiltration preparation

**Time-Based Indicators:**

- Off-hours: 00:00-06:00 local time
- Weekends and holidays
- Outside user's typical work schedule

**Focus on:**

- Large archives created when users typically inactive
- Archive creation by accounts during unusual hours
- Rapid creation of multiple large archives
- Archive size inconsistent with user's normal activities
- Large archives in staging directories

**Suspicious indicators:**

- Archives >500MB created between 00:00-06:00 local time
- Multiple large archives (>100MB each) created within 1-hour window
- Archive creation during weekends by Monday-Friday employee accounts
- Large archives created by service accounts or system processes
- File sizes suggesting database dumps, entire directories, or bulk data collection
- Archives created during maintenance windows when monitoring may be reduced
- Large archive creation immediately after credential dumping or privilege escalation
- Sequential large archives suggesting systematic data collection
- Archive sizes corresponding to sensitive data repositories (document servers, databases)
- Large archives created then immediately transferred to external storage

---

### 6. Archives Created in Staging Directories Before Exfiltration

**Sysmon:**

- Event ID 11 (File created) - Archive creation in staging locations
- Event ID 3 (Network connection) - Network activity from staging directories
- Event ID 23 (File deleted) - Archive deletion after exfiltration

**Windows Event Logs (Security):**

- Event ID 5140 (Network share accessed) - Staging archives accessed via SMB
- Event ID 4663 (Access attempted to object) - File access to staged archives

**Common Staging Directories:**

- `C:\Users\Public\`
- `C:\ProgramData\`
- `C:\Windows\Temp\`
- `%TEMP%\` or `%APPDATA%\Temp\`
- `C:\Perflogs\`
- `C:\Intel\`
- Recycle Bin directories
- Hidden directories in user profiles

**Correlation Pattern:**

- Archive creation → Brief delay → Network transfer → Archive deletion

**Focus on:**

- Archives created in typical staging locations
- Time gap between creation and network activity
- Archives deleted shortly after network transfer
- Multiple archives staged in same directory
- Staging combined with encryption or password protection

**Suspicious indicators:**

- Archives created in `C:\Users\Public\` or `C:\ProgramData\` followed by network connections within 5-30 minutes
- Archive creation (Event ID 11) followed by network share access (Event ID 5140) to external systems
- Archives in staging directories accessed by web browsers or FTP clients
- File deletion (Event ID 23) of archives within 1 hour of creation (covering tracks)
- Multiple archives created in staging location then transferred sequentially
- Archives with systematic naming in staging folders: `part1.zip`, `part2.zip`, `backup1.rar`
- Staging directories containing archives only temporarily (created, transferred, deleted)
- Network connections to cloud storage or file sharing services from staging directory locations
- Archives staged in hidden folders: `C:\Users\Public\.hidden\`, `C:\$Recycle.Bin\`
- FTP, SCP, or HTTP POST activity accessing files in staging directories

---

### 7. Command-Line Compression with Suspicious Parameters

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Command-line archive operations
- Key fields: `CommandLine`, `ProcessName`

**Sysmon:**

- Event ID 1 (Process creation) - Detailed command-line parameters
- Key fields: `CommandLine`, `ParentCommandLine`, `Image`

**Suspicious Command-Line Parameters:**

- Recursive archiving: `-r`, `--recursive`
- Update mode: `-u`, `--update`
- Exclude patterns: `-x`, `--exclude`
- Split archives: `-v`, `--volume`
- Compression level: `-mx=9` (maximum compression)
- Silent mode: `-y`, `--yes`, `-q`, `--quiet`

**Command-Line Examples:**

- `7z.exe a -r -mx=9 -p -mhe=on -v100m archive.7z C:\Users\`
- `rar.exe a -r -hp -m5 -v50m data.rar C:\*`
- `tar -czf - /home /var | split -b 100M - backup.tar.gz.`

**Focus on:**

- Recursive archiving of large directory structures
- Maximum compression settings (reduce transfer size)
- Split archives for easier exfiltration
- Silent or automated archive operations
- Exclusion patterns hiding archive activity

**Suspicious indicators:**

- Recursive archiving of sensitive directories: `7z.exe a -r archive.zip C:\Users\`
- Maximum compression level: `-mx=9`, `-m5` (effort to minimize file size)
- Split volume creation: `-v100m`, `-v50m` (splitting for easier transfer or evasion)
- Silent/automated mode: `-y`, `-q` (suppress prompts, hide activity)
- Archiving with exclusion patterns to avoid detection: `-x!*.log`, `-x!antivirus`
- Command lines archiving multiple sensitive locations in single operation
- Archive utilities with output piped to network commands: `7z.exe a -so | curl -T -`
- Compression combined with immediate deletion of source files: `7z.exe a archive.zip files\ && del /q files\*`
- Archive commands in batch scripts or scheduled tasks
- Command lines using variables or obfuscation to hide target paths

---

### 8. Archives Containing Sensitive File Types or Directories

**Sysmon:**

- Event ID 11 (File created) - Archive creation
- Correlate with file system monitoring of source directories

**Windows Event Logs (Security):**

- Event ID 4663 (Access attempted to object) - Access to sensitive files before archiving
- Event ID 4656 (Handle to object requested) - File read operations

**Sensitive Directories:**

- `C:\Users\*\Documents\`
- `C:\Users\*\Desktop\`
- `C:\Users\*\Downloads\`
- Database directories: SQL Server, MySQL, PostgreSQL data folders
- Application configuration directories with credentials
- Source code repositories
- Financial or HR system directories

**Sensitive File Types:**

- Documents: `.docx`, `.xlsx`, `.pdf`, `.pptx`
- Databases: `.mdf`, `.bak`, `.sql`, `.db`
- Configuration files: `.config`, `.ini`, `.xml`, `.json`
- Credentials: `.kdbx`, `.key`, `.pem`, `.pfx`
- Source code: `.cs`, `.java`, `.py`, `.cpp`
- Archives of archives: `.zip.zip`, `.rar` containing other archives

**Focus on:**

- Archiving of entire user document directories
- Database backup files included in archives
- Configuration files with credentials archived
- Source code or intellectual property archived
- Multiple file types suggesting comprehensive data collection

**Suspicious indicators:**

- Archives created from `C:\Users\*\Documents\` or `C:\Users\*\Desktop\`
- Command lines targeting database directories: `7z.exe a backup.7z "C:\Program Files\Microsoft SQL Server\*\Backup\"`
- Archiving configuration files: `*.config`, `web.config`, `app.config`, `settings.json`
- Password manager databases archived: `*.kdbx`, `*.agilekeychain`
- Source code repositories archived: `.git`, `.svn`, `src\`, `source\`
- Archives containing SSL certificates: `.pfx`, `.pem`, `.key`
- Multiple sensitive file types in single archive (documents + databases + configs)
- Archiving of email PST/OST files: `Outlook\*.pst`
- Financial files archived: `*invoice*`, `*payment*`, `*financial*`, `*budget*`
- HR or PII data archived: `*employee*`, `*personnel*`, `*SSN*`, `*salary*`

---

### 9. Split or Multi-Volume Archive Creation

**Sysmon:**

- Event ID 11 (File created) - Multiple archive parts created
- Monitor for sequential file creation: `.001`, `.002`, `.z01`, `.z02`, etc.

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Archive utilities with split parameters
- Event ID 4663 (Access attempted to object) - Multiple archive part writes

**Split Archive Patterns:**

- 7-Zip: `archive.7z.001`, `archive.7z.002`, `archive.7z.003`
- WinRAR: `archive.part1.rar`, `archive.part2.rar`
- Zip: `archive.z01`, `archive.z02`, `archive.zip`
- Tar with split: `archive.tar.gz.aa`, `archive.tar.gz.ab`

**Command-Line Patterns:**

- `7z.exe a -v100m archive.7z data\` (100MB volumes)
- `rar.exe a -v50m data.rar files\` (50MB volumes)
- `split -b 100M archive.tar.gz backup.tar.gz.` (Linux split)

**Focus on:**

- Multiple related archive files created simultaneously
- Volume sizes designed to evade size-based detection
- Sequential archive parts in staging directories
- Split archives transferred separately
- Archive parts with file-sharing service upload patterns

**Suspicious indicators:**

- Multiple files with `.001`, `.002`, `.003` extensions or `.part1.rar`, `.part2.rar` patterns
- Archive volumes sized to evade DLP thresholds (e.g., just under 100MB if policy is 100MB)
- Sequential archive part creation within minutes of each other
- Split archives in staging directories: `C:\Users\Public\`, `%TEMP%\`
- Volume sizes matching cloud storage limits or email attachment limits
- Archive parts transferred separately over time (evading rate-based detection)
- Command lines with volume parameters: `-v`, `--volume`, split utilities
- Archive parts with timestamp-based names: `data_20250115_part1.7z`
- Multiple archive parts uploaded to different file sharing services
- Split archives deleted sequentially after individual transfers

---

### 10. Archive Creation Followed by Network Transfer Activity

**SIEM Correlation:**

- Correlate archive creation (Sysmon Event ID 11) with network activity (Event ID 3)
- Track time delta between archive creation and transfer
- Monitor archive file access before network transfer

**Sysmon:**

- Event ID 11 (File created) - Archive creation timestamp
- Event ID 3 (Network connection) - Outbound connections following archive creation
- Event ID 23 (File deleted) - Archive cleanup after transfer

**Windows Event Logs (Security):**

- Event ID 5140 (Network share accessed) - SMB transfer of archives
- Event ID 4663 (Access attempted to object) - Archive file read before transfer

**Network Logs:**

- Firewall logs - HTTP/HTTPS POST, FTP, SCP connections
- Proxy logs - Uploads to cloud storage, file sharing services
- DNS logs - Domain resolution for exfiltration destinations

**Correlation Timeframe:**

- Archive creation → Network transfer (within 5-60 minutes)
- Archive creation → Upload to cloud storage (within 1-24 hours)
- Archive creation → Deletion (within 1 hour of transfer)

**Focus on:**

- Archives created then immediately transferred externally
- Network connections to cloud storage after archive creation
- HTTP POST or FTP PUT operations with archive files
- Archives accessed by browsers or transfer utilities
- Deletion of archives after successful transfer

**Suspicious indicators:**

- Archive creation (Event ID 11) followed within 10 minutes by network connection (Event ID 3) to external IP
- Archives in staging directory accessed by browsers: `chrome.exe`, `firefox.exe` reading archive files
- HTTP POST requests with `Content-Type: application/zip` or multipart file uploads
- FTP PUT commands or SCP transfers immediately after archive creation
- Network connections to cloud storage domains: `dropbox.com`, `drive.google.com`, `onedrive.com`
- Archives created then accessed by `curl.exe`, `wget.exe`, or file transfer utilities
- SMB connections (Event ID 5140) copying archives to external or removable shares
- Large outbound data transfers matching archive file sizes
- Archive deletion (Event ID 23) within 30-60 minutes of network transfer
- Sequential pattern: create archive → transfer → delete archive → create next archive
---
# Archive Collected Data Investigation Checklist

## 1. Archive Utility Execution

- [ ] Check 7z.exe, rar.exe with -p parameter (password protection) or -hp (encrypt headers)
- [ ] Review archive utilities executed from %TEMP%, %APPDATA%, C:\Users\Public\
- [ ] Monitor command lines archiving user directories: C:\Users*, %USERPROFILE%\Documents\
- [ ] Identify tools executed by users that don't typically perform archiving
- [ ] Look for archive utilities spawned from Office apps, browsers, script interpreters
- [ ] Check renamed archive utilities (e.g., svchost.exe that's actually 7z.exe)
- [ ] Review archiving to network shares or removable media
- [ ] Monitor archive utilities executed during non-business hours (00:00-06:00)

## 2. Archive File Creation in Unusual Locations

- [ ] Review Sysmon Event ID 11 for archives in C:\Users\Public, C:\ProgramData, C:\Windows\Temp\
- [ ] Check large archives (>100MB) created in temporary directories
- [ ] Monitor file names: data.zip, backup.rar, files.7z, documents.zip
- [ ] Identify archives with timestamps: 2025-01-15.zip, backup_20250115.rar
- [ ] Look for sequential numbering: part1.zip, part2.zip, part3.zip
- [ ] Check archives in web server directories: C:\inetpub\wwwroot, /var/www/html/
- [ ] Review archives in database backup directories by non-database processes
- [ ] Monitor double extensions: invoice.pdf.zip, report.docx.rar

## 3. Password-Protected/Encrypted Archives

- [ ] Check command lines with -p, -hp, -password, or encryption flags
- [ ] Review 7z.exe a -p -mhe=on (encrypts file names and content)
- [ ] Monitor archive creation followed by encryption tool execution
- [ ] Identify openssl, gpg, or encryption tools processing archives
- [ ] Look for PowerShell combining Compress-Archive with encryption functions
- [ ] Check archives with double extensions: data.zip.aes, files.7z.enc
- [ ] Review password-protected archives in staging directories
- [ ] Monitor archives encrypted with strong algorithms (AES-256)

## 4. PowerShell Compression

- [ ] Review Event ID 4104 for Compress-Archive targeting C:\Users, Documents, Desktop
- [ ] Check PowerShell archiving entire user profiles or multiple user directories
- [ ] Monitor [System.IO.Compression.ZipFile] .NET methods in scripts
- [ ] Identify Base64-encoded PowerShell commands decoding to compression operations
- [ ] Look for PowerShell compression with output to network shares or cloud paths
- [ ] Check Compress-Archive with -Force parameter overwriting archives
- [ ] Review PowerShell combining data collection, archiving, and network transfer
- [ ] Monitor archives created by PowerShell spawned from Office macros

## 5. Large Archives During Off-Hours

- [ ] Review archives >500MB created between 00:00-06:00 local time
- [ ] Check multiple large archives (>100MB each) within 1-hour window
- [ ] Monitor archive creation during weekends by Monday-Friday employees
- [ ] Identify large archives by service accounts or system processes
- [ ] Look for archive creation during maintenance windows
- [ ] Check large archives created after credential dumping or privilege escalation
- [ ] Review sequential large archives suggesting systematic collection
- [ ] Monitor large archives created then immediately transferred externally

## 6. Staging Directory Archives

- [ ] Timeline: Archives in C:\Users\Public\ or C:\ProgramData\ → Network connections within 5-30 minutes
- [ ] Check Event ID 11 (staging) → Event ID 5140 (share access) to external systems
- [ ] Monitor archives accessed by web browsers or FTP clients
- [ ] Identify file deletion (Event ID 23) within 1 hour of creation
- [ ] Look for multiple archives staged then transferred sequentially
- [ ] Review systematic naming: part1.zip, part2.zip, backup1.rar
- [ ] Check network connections to cloud storage from staging locations
- [ ] Monitor archives in hidden folders: C:\Users\Public.hidden, C:$Recycle.Bin\

## 7. Suspicious Command-Line Parameters

- [ ] Check recursive archiving: 7z.exe a -r archive.zip C:\Users\
- [ ] Review maximum compression: -mx=9, -m5 (minimize file size)
- [ ] Monitor split volume creation: -v100m, -v50m (easier transfer/evasion)
- [ ] Identify silent/automated mode: -y, -q (suppress prompts, hide activity)
- [ ] Look for exclusion patterns: -x!*.log, -x!antivirus
- [ ] Check output piped to network: 7z.exe a -so | curl -T -
- [ ] Review compression with immediate source deletion: && del /q files*
- [ ] Monitor archive commands in batch scripts or scheduled tasks

## 8. Archives with Sensitive Content

- [ ] Review archives from C:\Users*\Documents, C:\Users*\Desktop\
- [ ] Check command lines targeting database directories
- [ ] Monitor archiving configuration files: *.config, web.config, settings.json
- [ ] Identify password manager databases: *.kdbx, *.agilekeychain
- [ ] Look for source code repositories: .git, .svn, src, source\
- [ ] Check archives containing SSL certificates: .pfx, .pem, .key
- [ ] Review email PST/OST files: Outlook*.pst
- [ ] Monitor financial files: _invoice_, _payment_, _financial_, _budget_

## 9. Split/Multi-Volume Archives

- [ ] Check multiple files with .001, .002, .003 or .part1.rar, .part2.rar patterns
- [ ] Review archive volumes sized to evade DLP thresholds (just under 100MB)
- [ ] Monitor sequential archive part creation within minutes
- [ ] Identify split archives in staging: C:\Users\Public, %TEMP%\
- [ ] Look for volume sizes matching cloud storage or email limits
- [ ] Check archive parts transferred separately over time
- [ ] Review command lines with -v, --volume, split utilities
- [ ] Monitor split archives deleted sequentially after transfers

## 10. Archive Creation to Network Transfer

- [ ] Timeline: Archive creation (Event ID 11) → Network connection (Event ID 3) within 10 minutes to external IP
- [ ] Check archives accessed by browsers: chrome.exe, firefox.exe
- [ ] Monitor HTTP POST with Content-Type: application/zip or multipart uploads
- [ ] Identify FTP PUT or SCP transfers after archive creation
- [ ] Look for connections to dropbox.com, drive.google.com, onedrive.com
- [ ] Review archives accessed by curl.exe, wget.exe, transfer utilities
- [ ] Check SMB connections (Event ID 5140) copying to external shares
- [ ] Monitor archive deletion (Event ID 23) within 30-60 minutes of transfer
- [ ] Timeline: Create archive → Transfer → Delete → Create next archive