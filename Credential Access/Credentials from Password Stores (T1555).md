# Credentials from Password Stores: [T1555](https://attack.mitre.org/techniques/T1555/)

## Detection Explanation

Credentials from Password Stores involves adversaries searching for and extracting credentials stored in password managers, web browsers, email clients, and other applications that cache authentication material. This technique enables attackers to gain access to additional accounts and systems by exploiting locally stored credentials that users have saved for convenience.

Attackers target password stores because they often contain credentials for multiple services, applications, and websites in a centralized location. Common targets include web browser password stores (T1555.003), credentials stored in Windows Credential Manager (T1555.004), password manager databases, email client credential caches, and cloud synchronization services. Tools like LaZagne, Mimikatz, NirSoft utilities, and custom scripts are frequently used to extract these credentials.

Successful extraction of credentials from password stores provides attackers with legitimate authentication material for external services, cloud platforms, VPNs, and internal applications. This expands the attacker's access beyond the initially compromised system and can facilitate account takeover, data exfiltration, and further lateral movement. The impact includes unauthorized access to personal and corporate accounts, potential compromise of two-factor authentication recovery codes, and exposure of credentials to third-party services.

Detection requires monitoring file access to password store databases, execution of credential extraction tools, unusual process access to browser and application memory, and suspicious PowerShell or scripting activity targeting credential storage locations. Organizations should establish baselines for legitimate access to credential stores and alert on anomalous access patterns, particularly from unexpected processes or during off-hours.

---

## Key Detection Indicators & Areas to Investigate

### Summary of Indicators

1. Access to web browser credential stores and databases (T1555.003)
2. Extraction from Windows Credential Manager and Vault (T1555.004)
3. Execution of credential harvesting tools (LaZagne, NirSoft utilities)
4. Access to password manager databases and files
5. PowerShell commands targeting credential stores
6. File access to email client credential caches
7. Registry access to stored credentials and authentication tokens
8. Cloud credential and token theft from local storage
9. Memory access to password manager processes
10. Credential export commands and file exfiltration

---

### 1. Access to Web Browser Credential Stores and Databases

**Windows Event Logs (Security):**

- Event ID 4663 (Access attempted to object) - File access to browser credential databases
- Event ID 4656 (Handle to object requested) - Handle requests to browser database files
- Key fields: `ObjectName`, `ProcessName`, `AccessMask`

**Sysmon:**

- Event ID 11 (File created) - Browser database files copied to unusual locations
- Event ID 1 (Process creation) - Processes accessing browser profile directories
- Event ID 23 (File deleted) - Cleanup of copied credential databases

**File Paths to Monitor:**

- Chrome: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data`
- Firefox: `%APPDATA%\Mozilla\Firefox\Profiles\*.default\logins.json`
- Edge: `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data`
- Firefox master keys: `key4.db`, `key3.db`
- Browser cookies: `Cookies`, `cookies.sqlite`

**Focus on:**

- Non-browser processes accessing browser credential database files
- Copying of browser databases to temporary directories or network shares
- Access to multiple browser credential stores in short timeframe
- Database access during off-hours or when user not actively browsing

**Suspicious indicators:**

- `powershell.exe`, `cmd.exe`, `python.exe` accessing `Login Data` or `logins.json` files
- SQLite utilities (`sqlite3.exe`) accessing browser databases from non-browser processes
- File copy operations of browser credential databases to `%TEMP%`, `%APPDATA%`, or network paths
- Processes with command lines containing browser profile paths
- Recently created executables accessing browser credential stores
- Base64 encoding utilities executed after browser database access
- File transfers or uploads of files matching browser database names
- Access from scripts or unsigned executables to browser profile directories

---

### 2. Extraction from Windows Credential Manager and Vault

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Execution of credential management utilities
- Event ID 4663 (Access attempted to object) - File access to Vault and Credential files
- Event ID 4656 (Handle to object requested) - Credential vault object access

**Sysmon:**

- Event ID 1 (Process creation) - `vaultcmd.exe`, `cmdkey.exe` execution
- Event ID 11 (File created) - Credential files copied from Vault directories
- Event ID 12/13 (Registry events) - Registry access to Vault configuration

**Command-Line Patterns:**

- `vaultcmd.exe /list`
- `vaultcmd.exe /listcreds:"Windows Credentials" /all`
- `cmdkey.exe /list`
- `rundll32.exe keymgr.dll,KRShowKeyMgr`

**File Paths to Monitor:**

- `%LOCALAPPDATA%\Microsoft\Vault\*`
- `%APPDATA%\Microsoft\Credentials\*`
- `%APPDATA%\Microsoft\Protect\*`
- `%SYSTEMROOT%\System32\config\systemprofile\AppData\Local\Microsoft\Vault`

**Registry Keys:**

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Vault`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Vault`

**Focus on:**

- Execution of `vaultcmd.exe` or `cmdkey.exe` outside administrative contexts
- File access to credential vault files by non-system processes
- DPAPI (Data Protection API) decryption attempts
- Copying of `.vcrd` or `.vpol` files from Vault directories

**Suspicious indicators:**

- `vaultcmd.exe` executed with output redirection to files
- PowerShell scripts using `[Windows.Security.Credentials.PasswordVault]` class
- Access to `Policy.vpol` and `*.vcrd` files from user-context processes
- Credential files copied to temporary or network locations
- Mimikatz or custom tools accessing Windows Credential Manager programmatically
- Registry queries for vault GUID enumeration
- DPAPI master key access from unusual processes
- Scheduled tasks executing vault enumeration commands
- File access to multiple user credential vaults from single process

---

### 3. Execution of Credential Harvesting Tools

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Credential extraction tool execution
- Key fields: `NewProcessName`, `CommandLine`, `ParentProcessName`

**Sysmon:**

- Event ID 1 (Process creation) - Credential harvesting utilities
- Event ID 3 (Network connection) - Exfiltration of harvested credentials
- Event ID 7 (Image loaded) - DLL loading for credential access

**Known Tool Names:**

- `lazagne.exe`, `LaZagne.py`
- NirSoft utilities: `WebBrowserPassView.exe`, `ChromePass.exe`, `PasswordFox.exe`, `mailpv.exe`
- `credentialfileview.exe`, `VaultPasswordView.exe`
- `webcredentials.exe`, `CredentialsFileView.exe`

**Command-Line Patterns:**

- `lazagne.exe all`
- `python lazagne.py all -oN`
- Tool names with output parameters: `-o`, `-output`, `/stext`

**Focus on:**

- Execution of known credential harvesting tools by name or hash
- Renamed credential tools identified by file hash matching
- Tools executed from temporary directories or user downloads
- Credential tool execution followed by file creation or network activity

**Suspicious indicators:**

- Unsigned executables with names matching credential extraction patterns
- Tools downloaded from GitHub repositories (LaZagne, NirSoft archives)
- Execution from `%TEMP%`, `%APPDATA%`, `Downloads`, `C:\Users\Public`
- Command lines containing "passwords", "credentials", "lazagne", "browsers", "all"
- Output redirection to files: `> passwords.txt`, `> creds.txt`
- Execution via PowerShell `Invoke-WebRequest` or `Start-Process`
- Parent processes: Office applications, web browsers, scripting engines
- Tools executed via scheduled tasks or WMI
- Network connections to file sharing services following tool execution
- Multiple credential tools executed in sequence

---

### 4. Access to Password Manager Databases and Files

**Windows Event Logs (Security):**

- Event ID 4663 (Access attempted to object) - Access to password manager database files
- Event ID 4656 (Handle to object requested) - Handle requests to encrypted databases

**Sysmon:**

- Event ID 11 (File created) - Password manager databases copied
- Event ID 1 (Process creation) - Processes accessing password manager directories
- Event ID 23 (File deleted) - Deletion of copied password databases

**File Paths to Monitor:**

- KeePass: `*.kdbx` files, `%APPDATA%\KeePass\`
- 1Password: `%LOCALAPPDATA%\1Password\`, `*.sqlite` files
- LastPass: `%LOCALAPPDATA%\LastPass\`, browser extension storage
- Bitwarden: `%APPDATA%\Bitwarden\`, `data.json`
- Dashlane: `%APPDATA%\Dashlane\`, `*.db` files
- Password Safe: `*.psafe3` files

**Focus on:**

- File access to password manager databases by non-password-manager processes
- Copying of encrypted password databases to temporary or network locations
- Access to password manager configuration files containing master password hints
- Simultaneous access to database file and master key material

**Suspicious indicators:**

- Non-password-manager processes reading `.kdbx`, `.psafe3`, or encrypted database files
- Database files copied to `%TEMP%`, removable media, or network shares
- PowerShell or scripting engines accessing password manager directories
- File searches for password manager database extensions: `*.kdbx`, `*.agilekeychain`
- Access to password manager databases from Office macro processes
- Database files uploaded or exfiltrated via HTTP/HTTPS POST requests
- Execution of password cracking tools (`hashcat`, `john`) following database access
- Access to password manager auto-type or clipboard history files
- Multiple password manager databases accessed from single system

---

### 5. PowerShell Commands Targeting Credential Stores

**PowerShell Logs:**

- Event ID 4104 (Script block logging) - PowerShell script content
- Event ID 4103 (Module logging) - Module and command execution
- Event ID 400 (PowerShell engine state) - PowerShell session tracking

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - PowerShell with encoded credential access commands

**Script Content to Monitor:**

- `[Windows.Security.Credentials.PasswordVault]`
- `Get-VaultCredential`, `Get-StoredCredential`
- `[System.Runtime.InteropServices.Marshal]::SecureStringToBSTR`
- `Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Vault"`
- Browser database access via PowerShell

**Focus on:**

- PowerShell commands querying Windows Credential Manager
- Scripts accessing browser profile directories
- PowerShell reading encrypted credential files
- Commands converting SecureString to plaintext

**Suspicious indicators:**

- Script blocks containing `PasswordVault`, `SecureString`, or credential-related .NET classes
- PowerShell commands reading browser `Login Data` or `logins.json` files
- Base64-encoded commands decoding to credential access functions
- Scripts copying files from `%LOCALAPPDATA%\Microsoft\Vault`
- PowerShell accessing Windows Data Protection API (DPAPI) for decryption
- Commands enumerating stored credentials: `cmdkey /list` from PowerShell
- Scripts searching for password manager databases: `Get-ChildItem -Recurse -Include *.kdbx`
- PowerShell downloading and executing LaZagne or similar tools
- Commands accessing browser SQLite databases with credential queries
- Script blocks extracting WiFi passwords: `netsh wlan show profiles key=clear`

---

### 6. File Access to Email Client Credential Caches

**Windows Event Logs (Security):**

- Event ID 4663 (Access attempted to object) - File access to email client credential stores
- Event ID 4656 (Handle to object requested) - Handle requests to credential cache files

**Sysmon:**

- Event ID 11 (File created) - Email credential files copied
- Event ID 1 (Process creation) - Processes accessing email client directories

**File Paths to Monitor:**

- Outlook: `%LOCALAPPDATA%\Microsoft\Outlook\*.ost`, `*.pst`
- Outlook credentials: Registry under `HKCU\Software\Microsoft\Office\*\Outlook\Profiles`
- Thunderbird: `%APPDATA%\Thunderbird\Profiles\*\logins.json`, `key4.db`
- Windows Mail: `%LOCALAPPDATA%\Microsoft\Windows Mail\`
- Credential Manager entries for email accounts

**Focus on:**

- Non-email-client processes accessing email credential stores
- Copying of email profile databases or credential caches
- Access to email client protected storage locations
- Registry access to email account credential keys

**Suspicious indicators:**

- Processes other than `outlook.exe`, `thunderbird.exe` accessing email credential files
- PowerShell or scripts reading Outlook profile registry keys
- File copy operations of `.ost`, `.pst`, or email credential databases
- Access to Thunderbird `logins.json` and master key files (`key4.db`)
- Registry queries for `HKCU\Software\Microsoft\Office\*\Outlook\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676`
- Email credential extraction via Windows Credential Manager
- Tools accessing MAPI profiles or Exchange credential caches
- Copying of email databases to temporary or external locations
- Network transfer of email credential files

---

### 7. Registry Access to Stored Credentials and Authentication Tokens

**Windows Event Logs (Security):**

- Event ID 4657 (Registry value modification) - Registry changes to credential storage
- Event ID 4656 (Handle to object requested) - Registry key access requests

**Sysmon:**

- Event ID 12 (Registry object added/deleted) - New credential registry entries
- Event ID 13 (Registry value set) - Credential registry modifications
- Event ID 14 (Registry object renamed) - Registry key changes

**Registry Keys to Monitor:**

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\*`
- `HKCU\Software\Microsoft\Protected Storage System Provider`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\*`
- `HKCU\Software\*\Credentials` (application-specific credential keys)
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Authentication\*`

**Command-Line Patterns:**

- `reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`
- `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"`
- `reg save HKCU\Software\Microsoft\Protected Storage`

**Focus on:**

- Registry queries targeting credential storage locations
- Enumeration of Protected Storage System Provider keys
- Access to AutoLogon credentials in Winlogon registry keys
- Application-specific credential registry access

**Suspicious indicators:**

- `reg.exe` querying credential-related registry keys from user context
- PowerShell accessing Protected Storage registry paths
- Registry queries for saved RDP credentials
- Access to `DefaultPassword` or `AutoAdminLogon` registry values
- Scripts enumerating Internet Explorer/Edge stored passwords
- Registry export of credential-containing keys
- Remote registry access targeting credential storage locations
- Tools reading application-specific password registry entries
- Queries for VPN or wireless network credential registry locations

---

### 8. Cloud Credential and Token Theft from Local Storage

**Windows Event Logs (Security):**

- Event ID 4663 (Access attempted to object) - File access to cloud credential caches
- Event ID 4656 (Handle to object requested) - Handle requests to token files

**Sysmon:**

- Event ID 11 (File created) - Cloud token files copied
- Event ID 1 (Process creation) - Processes accessing cloud service directories

**File Paths to Monitor:**

- AWS: `%USERPROFILE%\.aws\credentials`, `%USERPROFILE%\.aws\config`
- Azure: `%USERPROFILE%\.azure\`, `AzureRmContext.json`, `TokenCache.dat`
- Google Cloud: `%APPDATA%\gcloud\`, `credentials.db`, `access_tokens.db`
- Docker: `%USERPROFILE%\.docker\config.json`
- Kubernetes: `%USERPROFILE%\.kube\config`
- Git: `%USERPROFILE%\.git-credentials`

**Focus on:**

- File access to cloud CLI credential caches by non-cloud-CLI processes
- Copying of cloud authentication tokens to temporary locations
- Access to OAuth tokens and refresh tokens
- Enumeration of multiple cloud credential stores

**Suspicious indicators:**

- PowerShell or scripts reading `.aws\credentials` or `.azure\` directories
- File copy operations of `credentials`, `config`, `TokenCache.dat` files
- Access to cloud credential files from Office macros or web browsers
- Network transfer of cloud credential files via HTTP/HTTPS
- Tools searching for cloud credentials: `Get-ChildItem -Recurse -Include credentials,*.json`
- Access to Docker or Kubernetes config files containing cluster credentials
- Git credential helper access from non-git processes
- Commands reading cloud service principal or service account key files
- Exfiltration of files matching cloud credential naming patterns
- Multiple cloud service credential stores accessed in short timeframe

---

### 9. Memory Access to Password Manager Processes

**Sysmon:**

- Event ID 10 (ProcessAccess) - Process memory access to password managers
- TargetImage: Password manager executables (`KeePass.exe`, `1Password.exe`, etc.)
- Key fields: `SourceImage`, `GrantedAccess`, `CallTrace`

**Windows Event Logs (Security):**

- Event ID 4656 (Handle to object requested) - Process handle requests
- Event ID 4663 (Access attempted to object) - Process memory access

**Endpoint Detection and Response (EDR):**

- Process memory access telemetry for password manager applications
- API call monitoring for `OpenProcess`, `ReadProcessMemory`

**Focus on:**

- Non-legitimate processes accessing password manager process memory
- Memory read access to processes with unlocked password databases
- Injection attempts into password manager processes
- Memory dumps of password manager applications

**Suspicious indicators:**

- `powershell.exe`, `cmd.exe`, or unknown processes accessing password manager memory
- GrantedAccess values indicating full memory read: `0x1FFFFF`, `0x1010`, `0x1438`
- Remote thread creation in password manager processes (Sysmon Event ID 8)
- Memory dumping tools accessing password manager processes
- CallTrace through suspicious or unsigned DLLs
- Access from recently created executables to password manager memory
- Processes requesting `PROCESS_VM_READ` access to KeePass, 1Password, Bitwarden
- Memory access when password database is unlocked (active user session)
- DLL injection into password manager processes
- Debugger attachment to password manager applications

---

### 10. Credential Export Commands and File Exfiltration

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Export commands execution
- Event ID 5140 (Network share accessed) - Credential files copied to network shares
- Event ID 5145 (Network share object accessed) - Specific file access on shares

**Sysmon:**

- Event ID 3 (Network connection) - Outbound connections following credential access
- Event ID 11 (File created) - Creation of credential export files
- Event ID 23 (File deleted) - Cleanup of credential export files

**Network Logs:**

- Firewall logs - HTTP/HTTPS POST requests with credential data
- Proxy logs - File uploads to file sharing services, cloud storage
- DNS logs - Queries to file sharing domains following credential access

**Command-Line Patterns:**

- Export to files: `> passwords.txt`, `> credentials.csv`, `| Out-File`
- Network transfer: `curl -d @credentials.txt`, `Invoke-WebRequest -Method POST`
- Compression before exfil: `Compress-Archive`, `7z.exe`, `zip.exe`

**Focus on:**

- File creation of credential exports in temporary directories
- Network connections immediately following credential access
- Upload of files to cloud storage or file sharing services
- Compression of credential-related files before transfer

**Suspicious indicators:**

- Files created with names: `passwords.txt`, `creds.txt`, `credentials.csv`, `dump.txt`
- HTTP POST requests containing credential data to external IPs
- FTP, SCP, or SFTP connections following credential harvesting
- File uploads to Pastebin, GitHub Gists, or file sharing services
- PowerShell `Invoke-WebRequest` or `Invoke-RestMethod` with credential data
- Email attachments containing credential files sent to external addresses
- Credential files compressed with `7z`, `zip`, `rar` before network transfer
- DNS queries to exfiltration domains following password store access
- Large outbound data transfers following credential harvesting activity
- Files staged in `%TEMP%` or `C:\ProgramData` before network transfer
--- 
# Credentials from Password Stores Investigation Checklist

## 1. Web Browser Credential Store Access

- [ ] Check Event ID 4663 for powershell.exe, cmd.exe, python.exe accessing Login Data or logins.json files
- [ ] Monitor Sysmon Event ID 11 for browser database copies to %TEMP%, %APPDATA%, network paths
- [ ] Review file paths: %LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data
- [ ] Check Firefox: %APPDATA%\Mozilla\Firefox\Profiles*.default\logins.json, key4.db
- [ ] Identify SQLite utilities (sqlite3.exe) accessing browser databases
- [ ] Look for Base64 encoding utilities executed after browser database access
- [ ] Monitor file transfers of files matching browser database names

## 2. Windows Credential Manager and Vault

- [ ] Review vaultcmd.exe, cmdkey.exe execution outside administrative contexts
- [ ] Check Event ID 4663 for file access to %LOCALAPPDATA%\Microsoft\Vault*
- [ ] Monitor PowerShell using [Windows.Security.Credentials.PasswordVault] class
- [ ] Identify access to Policy.vpol and *.vcrd files from user-context processes
- [ ] Look for credential files copied to temporary or network locations
- [ ] Check registry queries: HKCU\Software\Microsoft\Windows\CurrentVersion\Vault
- [ ] Review DPAPI master key access from unusual processes

## 3. Credential Harvesting Tool Execution

- [ ] Search for lazagne.exe, LaZagne.py execution by name or hash
- [ ] Check for NirSoft utilities: WebBrowserPassView.exe, ChromePass.exe, PasswordFox.exe, mailpv.exe
- [ ] Identify credentialfileview.exe, VaultPasswordView.exe usage
- [ ] Monitor tools executed from %TEMP%, %APPDATA%, Downloads, C:\Users\Public
- [ ] Look for command lines with "passwords", "credentials", "lazagne", "browsers", "all"
- [ ] Check for output redirection: > passwords.txt, > creds.txt
- [ ] Review tools executed via Office apps, browsers, scripting engines

## 4. Password Manager Database Access

- [ ] Monitor non-password-manager processes reading .kdbx, .psafe3, encrypted database files
- [ ] Check for database copies to %TEMP%, removable media, network shares
- [ ] Review file paths: %APPDATA%\KeePass, %LOCALAPPDATA%\1Password, %APPDATA%\Bitwarden\
- [ ] Identify PowerShell or scripting engines accessing password manager directories
- [ ] Look for file searches: *.kdbx, *.agilekeychain, *.psafe3
- [ ] Monitor database files uploaded via HTTP/HTTPS POST requests
- [ ] Check for password cracking tools (hashcat, john) executed after database access

## 5. PowerShell Credential Store Access

- [ ] Review Event ID 4104 for [Windows.Security.Credentials.PasswordVault] usage
- [ ] Search for SecureString, PasswordVault, or credential .NET classes in script blocks
- [ ] Check PowerShell reading browser Login Data or logins.json files
- [ ] Identify Base64-encoded commands decoding to credential access functions
- [ ] Monitor scripts copying files from %LOCALAPPDATA%\Microsoft\Vault
- [ ] Look for PowerShell accessing DPAPI for decryption
- [ ] Review scripts searching for password databases: Get-ChildItem -Include *.kdbx

## 6. Email Client Credential Cache Access

- [ ] Check Event ID 4663 for non-email processes accessing .ost, .pst files
- [ ] Monitor PowerShell reading Outlook profile registry keys
- [ ] Review Thunderbird logins.json and key4.db file access
- [ ] Identify registry queries: HKCU\Software\Microsoft\Office*\Outlook\Profiles
- [ ] Look for file copies of email credential databases
- [ ] Check Windows Credential Manager entries for email accounts
- [ ] Monitor network transfers of email credential files

## 7. Registry Credential Access

- [ ] Review reg.exe querying HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings
- [ ] Check PowerShell accessing Protected Storage registry paths
- [ ] Monitor queries for HKCU\Software\Microsoft\Protected Storage System Provider
- [ ] Identify access to DefaultPassword or AutoAdminLogon in Winlogon keys
- [ ] Look for registry exports of credential-containing keys
- [ ] Check remote registry access targeting credential storage locations
- [ ] Review queries for VPN or wireless network credential registry locations

## 8. Cloud Credential and Token Theft

- [ ] Monitor PowerShell or scripts reading .aws\credentials, .azure\ directories
- [ ] Check file copies of credentials, config, TokenCache.dat files
- [ ] Review access to %USERPROFILE%.aws, %USERPROFILE%.azure, %APPDATA%\gcloud\
- [ ] Identify access to Docker: %USERPROFILE%.docker\config.json
- [ ] Look for Kubernetes: %USERPROFILE%.kube\config access
- [ ] Check network transfers of cloud credential files
- [ ] Monitor searches: Get-ChildItem -Recurse -Include credentials,*.json

## 9. Password Manager Memory Access

- [ ] Review Sysmon Event ID 10 for memory access to KeePass.exe, 1Password.exe, Bitwarden.exe
- [ ] Check GrantedAccess values: 0x1FFFFF, 0x1010, 0x1438 (full memory read)
- [ ] Identify powershell.exe, cmd.exe, or unknown processes accessing password manager memory
- [ ] Monitor Sysmon Event ID 8 for remote thread creation in password managers
- [ ] Look for CallTrace through suspicious or unsigned DLLs
- [ ] Check for DLL injection into password manager processes
- [ ] Review memory access when password database is unlocked

## 10. Credential Export and Exfiltration

- [ ] Monitor file creation: passwords.txt, creds.txt, credentials.csv, dump.txt
- [ ] Check HTTP POST requests containing credential data to external IPs
- [ ] Review FTP, SCP, SFTP connections following credential harvesting
- [ ] Identify file uploads to Pastebin, GitHub Gists, file sharing services
- [ ] Look for PowerShell Invoke-WebRequest with credential data
- [ ] Check credential files compressed with 7z, zip, rar before transfer
- [ ] Monitor large outbound data transfers following password store access
- [ ] Timeline: Credential access → File creation → Compression → Network transfer
