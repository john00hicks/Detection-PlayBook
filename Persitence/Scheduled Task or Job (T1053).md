# Scheduled Task/Job: [T1053](https://attack.mitre.org/techniques/T1053/)

## Detection Explanation

Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Utilities such as `at` and `schtasks`, along with the Windows Task Scheduler, can be used to schedule programs or scripts to be executed at a date and time. This technique is commonly used for persistence, privilege escalation, and remote execution. Variants include Scheduled Task (T1053.005), At (T1053.002), Cron (T1053.003), Systemd Timers (T1053.006), and Container Orchestration Jobs (T1053.007).

## Key Detection Indicators & Areas to Investigate

### Scheduled Task Creation and Modification (Windows)

**Windows Event Logs:**

- Event ID 4698 (Scheduled task created) - New task registration
- Event ID 4702 (Scheduled task updated) - Task modification
- Event ID 4699 (Scheduled task deleted) - Task removal
- Event ID 4700 (Scheduled task enabled)
- Event ID 4701 (Scheduled task disabled)

**Task Scheduler Operational Log:**

- Event ID 106 (Task registered)
- Event ID 140 (Task updated)
- Event ID 141 (Task deleted)
- Event ID 200 (Task action started - execution)
- Event ID 201 (Task action completed)
- Event ID 325 (Launch request queued)

**Sysmon:**

- Event ID 1 (Process creation) - `schtasks.exe`, `taskeng.exe`, `taskhostw.exe` execution
- Event ID 11 (File creation) - Task XML files created in `C:\Windows\System32\Tasks\`

**Fields to analyze:**

- Task name and path
- Task author/creator
- Command/executable being scheduled
- Trigger type (time, logon, startup, idle)
- User account task runs as (SYSTEM, administrator, user)
- Task creation timestamp

---

### Suspicious Task Characteristics

**Command-line indicators:**

- Use of `schtasks.exe` with `/create`, `/change`, or `/run` parameters
- PowerShell commands: `Register-ScheduledTask`, `New-ScheduledTask`
- COM object usage: `Schedule.Service` object in scripts

**Suspicious task properties:**

- Tasks running with SYSTEM or elevated privileges
- Tasks executing from unusual locations: `%TEMP%`, `%APPDATA%`, `C:\Users\Public\`
- Hidden tasks (not visible in GUI but exist in `C:\Windows\System32\Tasks\`)
- Tasks with no description or generic names
- Tasks running frequently (every minute, every 5 minutes)
- Tasks with multiple actions or chained commands

**Suspicious executables/actions:**

- `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`
- Encoded PowerShell commands (`-enc`, `-encodedcommand`)
- Obfuscated scripts or commands
- Download cradles: `IEX`, `Invoke-WebRequest`, `wget`, `curl`, `certutil`, `bitsadmin`
- Living-off-the-land binaries: `rundll32.exe`, `regsvr32.exe`, `msiexec.exe`

---

### Task Execution and Process Creation

**Sysmon:**

- Event ID 1 (Process creation) - Tasks executed by Task Scheduler engine

**Parent processes:**

- `taskeng.exe` (Windows 7/Server 2008)
- `taskhostw.exe` (Windows 8+)
- `svchost.exe` with Task Scheduler service

**Windows Event Logs:**

- Event ID 4688 (Process creation) - Scheduled task spawning processes
- Event ID 4104 (PowerShell script block logging) - Script content from scheduled tasks

**Behavioral indicators:**

- Scheduled tasks spawning network connections
- Tasks executing at unusual times (3 AM, weekends)
- Tasks running during off-hours but no interactive user logged in
- Process trees showing task scheduler → malicious binary → lateral movement tools

---

### Task Persistence Patterns

**Common persistence task configurations:**

- Trigger: On startup, on logon, or recurring intervals
- Run whether user is logged on or not
- Run with highest privileges
- Hidden from Task Scheduler UI

**Task XML analysis locations:**

- `C:\Windows\System32\Tasks\` - Primary task definition storage
- `C:\Windows\Tasks\` - Legacy .job files (older Windows versions)

**XML elements to review:**

- `<Command>` - Executable path
- `<Arguments>` - Command-line parameters
- `<WorkingDirectory>` - Execution directory
- `<UserId>` - Account context
- `<LogonType>` - Interactive, password, S4U
- `<RunLevel>` - Highest privileges, least privileges
- `<Triggers>` - Execution conditions
- `<Hidden>` - Task visibility

**PowerShell hunting:**

- `Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft\*"}`
- Review task principals, actions, and triggers
- Check for tasks in non-standard paths

---

### Remote Task Scheduling

**Windows Event Logs:**

- Event ID 4698 (Task created) with network logon type
- Event ID 4624 (Logon) Type 3 (Network) preceding task creation
- Event ID 4672 (Special privileges assigned) for remote task creation

**Sysmon:**

- Event ID 3 (Network connection) - RPC connections to Task Scheduler (port 135, dynamic RPC ports)
- Event ID 1 (Process creation) - `schtasks.exe` with `/s` parameter (remote system)

**Network indicators:**

- RPC traffic to port 135 (endpoint mapper)
- SMB traffic (ports 445, 139) for authentication
- Task Scheduler RPC interface access
- Authentication to IPC$ share

**Command-line patterns:**

- `schtasks /create /s [remote_host] /u [username] /p [password]`
- `at \\[remote_host] [time] [command]` (legacy)
- PowerShell remoting for task creation: `Invoke-Command -ComputerName`

---

### AT Command (Legacy - Windows Server 2008 and earlier)

**Windows Event Logs:**

- Event ID 4698 (Scheduled task created) - Still logged for AT jobs
- Event ID 601 (Task Scheduler) - AT job creation

**Files to monitor:**

- `C:\Windows\Tasks\*.job` - AT command job files

**Sysmon:**

- Event ID 1 (Process creation) - `at.exe` execution
- Event ID 11 (File creation) - .job file creation in `C:\Windows\Tasks\`

**Command-line patterns:**

- `at [time] [command]`
- `at \\[computer] [time] [command]`
- `at [id] /delete`

**Note:** AT command deprecated in modern Windows but may indicate older malware or legacy attack techniques

---

### Cron Jobs (Linux/Unix)

**Log locations:**

- `/var/log/cron` - Cron daemon logs
- `/var/log/syslog` - System logs including cron activity
- `journalctl -u cron` - Systemd journal for cron service

**Crontab file locations:**

- `/etc/crontab` - System-wide crontab
- `/etc/cron.d/` - Additional system cron jobs
- `/var/spool/cron/crontabs/` - User-specific crontabs
- `/etc/cron.daily/`, `/etc/cron.hourly/`, `/etc/cron.weekly/`, `/etc/cron.monthly/` - Periodic scripts

**Monitoring approaches:**

- File integrity monitoring on crontab files
- Process monitoring for `cron` spawning unusual commands
- Audit daemon logs for crontab modifications

**Suspicious indicators:**

- Cron jobs running as root with commands from writable directories
- Reverse shells or network connections in cron jobs
- Download commands: `wget`, `curl`, `nc` in cron entries
- Obfuscated or encoded commands
- Cron jobs created in `/tmp`, `/dev/shm`, or user home directories

---

### Systemd Timers (Linux)

**Systemd timer locations:**

- `/etc/systemd/system/*.timer` - System timer units
- `/usr/lib/systemd/system/*.timer` - Distribution timer units
- `~/.config/systemd/user/*.timer` - User timer units

**Associated service files:**

- `.service` files paired with `.timer` files
- Service unit definitions containing commands to execute

**Journal logs:**

- `journalctl -u [timer_name]` - Timer activation logs
- `journalctl -u [service_name]` - Service execution logs

**Systemd commands for hunting:**

- `systemctl list-timers --all` - List all timers
- `systemctl status [timer_name]` - Timer details
- `systemd-analyze calendar [timer_expression]` - Verify timer schedule

**Suspicious indicators:**

- Timers with no package association
- Service files executing from `/tmp`, `/var/tmp`, or user directories
- Commands downloading or executing scripts from internet
- Timers running with elevated privileges
- Recently created timer/service pairs

---

### Container Orchestration Job Scheduling

**Kubernetes CronJobs:**

- `kubectl get cronjobs --all-namespaces` - List all cron jobs
- Kubernetes API audit logs - CronJob creation/modification events
- Pod creation logs tied to CronJob execution

**Kubernetes indicators:**

- CronJobs in unusual namespaces
- Jobs with privileged security contexts
- Jobs mounting host volumes
- Container images from untrusted registries
- Jobs with network access to sensitive resources

**Docker/Container logs:**

- Container runtime logs showing scheduled container execution
- Docker event logs for container starts from scheduled tasks

---

### Task Scheduler Service Abuse

**Service manipulation:**

- Event ID 7045 (Service installed) - Task Scheduler service modifications
- Event ID 7040 (Service start type changed)

**Registry locations:**

- `HKLM\SYSTEM\CurrentControlSet\Services\Schedule` - Task Scheduler service configuration

**DLL hijacking in Task Scheduler:**

- Sysmon Event ID 7 (Image loaded) - DLLs loaded by Task Scheduler processes
- Unsigned or suspicious DLLs loaded by `taskeng.exe`, `svchost.exe` (Schedule service)

---

### COM Task Scheduler Object Abuse

**Script/Process indicators:**

- PowerShell or VBScript using `Schedule.Service` COM object
- Script content creating tasks via COM API

**Sysmon:**

- Event ID 1 (Process creation) - PowerShell/scripts with Task Scheduler COM usage

**Script patterns:**

- `$schedule = New-Object -ComObject Schedule.Service`
- `$schedule.Connect()`
- `$task = $schedule.NewTask(0)`
- VBScript: `Set objSchedule = CreateObject("Schedule.Service")`

**Detection approaches:**

- PowerShell script block logging (Event ID 4104) containing Schedule.Service
- Process command-line containing COM task creation patterns

---

### Persistence via Task Import/Export

**Task export/import operations:**

- `schtasks /query /xml` - Task definition export
- `schtasks /create /xml [file]` - Task import from XML

**Sysmon:**

- Event ID 11 (File creation) - XML task definition files
- Event ID 1 (Process creation) - schtasks with /xml parameter

**Attack patterns:**

- Exporting legitimate task, modifying XML, re-importing
- Importing task definitions from external sources
- Base64 encoded task XML in command-line

---

### High-Privilege Task Execution

**Privilege escalation indicators:**

- Event ID 4698 (Task created) with `<UserId>` set to SYSTEM, Administrators
- Event ID 4672 (Special privileges assigned) following task execution
- Event ID 4688 (Process creation) showing SYSTEM-level processes from tasks

**UAC bypass via tasks:**

- Tasks configured to run with highest privileges
- Tasks bypassing UAC prompts
- Silent elevation through Task Scheduler

**Credential theft opportunities:**

- Tasks running with stored credentials
- Password in task XML or command-line (rare but occurs)

---

### Lateral Movement via Scheduled Tasks

**Network activity correlation:**

- Event ID 4624 Type 3 (Network logon) → Event ID 4698 (Task created)
- Remote task creation following authentication
- SMB/RPC traffic patterns indicating remote task scheduling

**Tools and techniques:**

- PsExec with `-s` flag using Task Scheduler
- Impacket's `atexec.py` for remote AT command execution
- PowerShell remoting with scheduled task creation
- WMIC remote task creation

**Detection patterns:**

- Task creation on multiple systems in short time window
- Similar or identical tasks across multiple hosts
- Tasks created via administrative shares (ADMIN,C, C ,C)

---

### Task Modification and Deletion for Defense Evasion

**Windows Event Logs:**

- Event ID 4699 (Task deleted) - Evidence removal
- Event ID 4702 (Task updated) - Modification to hide or change behavior
- Event ID 141 (Task deleted from Task Scheduler)

**Evasion techniques:**

- Deleting tasks after execution
- Disabling tasks to avoid repeated execution
- Modifying task triggers to make execution unpredictable
- Clearing Task Scheduler operational logs

**Forensic considerations:**

- Residual XML files even after task deletion
- Event log correlation of creation, execution, and deletion
- File system timestamps on task definitions

---

## Additional Investigation Areas

**Task Scheduler Database:**

- `C:\Windows\System32\Tasks\` directory enumeration
- Compare task database to registry entries
- Identify orphaned or hidden tasks

**Authentication Logs:**

- Correlate task creation with user authentication events
- Track which accounts are creating scheduled tasks
- Identify service accounts used for scheduled task execution

**Network Monitoring:**

- RPC traffic analysis for remote task creation
- Command and control (C2) beaconing aligned with task execution schedules
- Outbound connections immediately following task execution

**PowerShell Logging:**

- Event ID 4103 (Module logging)
- Event ID 4104 (Script block logging)
- Event ID 4105/4106 (Script start/stop)
- Review for Task Scheduler cmdlets and COM object usage

**Baseline Establishment:**

- Inventory all legitimate scheduled tasks
- Document business-critical automation tasks
- Alert on new tasks outside of change management
- Track task creation by user/system accounts

**Correlation Opportunities:**

- Task creation → File download → Process execution → Network beaconing
- User compromise → Task creation with persistence → Credential access
- Lateral movement → Remote task creation → Data exfiltration
- Initial access → Scheduled task for callback → Privilege escalation

--- 
# Scheduled Task/Job Investigation Checklist

## 1. Task Creation and Modification (Windows)

- [ ]  Review Event ID 4698/4702/4699 for task creation, updates, and deletions
- [ ]  Check Task Scheduler Operational log Event ID 106/140/141/200/201
- [ ]  Monitor Sysmon Event ID 1 for schtasks.exe, taskeng.exe, taskhostw.exe execution
- [ ]  Review Sysmon Event ID 11 for task XML files in C:\Windows\System32\Tasks\
- [ ]  Identify task author, creation timestamp, and user account context
- [ ]  Check for PowerShell commands: Register-ScheduledTask, New-ScheduledTask

## 2. Suspicious Task Characteristics

- [ ]  Identify tasks running with SYSTEM or elevated privileges
- [ ]  Check for tasks executing from %TEMP%, %APPDATA%, C:\Users\Public\
- [ ]  Look for hidden tasks not visible in GUI but existing in C:\Windows\System32\Tasks\
- [ ]  Search for tasks with generic names or no description
- [ ]  Review tasks running frequently (every minute/5 minutes)
- [ ]  Identify tasks executing powershell.exe, cmd.exe, wscript.exe, mshta.exe
- [ ]  Check for encoded PowerShell commands: -enc, -encodedcommand

## 3. Task Actions and Commands

- [ ]  Search for download cradles: IEX, Invoke-WebRequest, wget, curl, certutil, bitsadmin
- [ ]  Identify LOLBins: rundll32.exe, regsvr32.exe, msiexec.exe in task actions
- [ ]  Review obfuscated scripts or Base64 encoded commands
- [ ]  Check for tasks with multiple actions or chained commands
- [ ]  Analyze task XML Command, Arguments, and WorkingDirectory elements
- [ ]  Verify RunLevel (highest/least privileges) and Hidden properties

## 4. Task Execution Monitoring

- [ ]  Check Sysmon Event ID 1 for parent processes: taskeng.exe, taskhostw.exe, svchost.exe
- [ ]  Review Event ID 4688/4104 for scheduled task spawning processes or scripts
- [ ]  Identify tasks executing at unusual times (3 AM, weekends, off-hours)
- [ ]  Monitor scheduled tasks spawning network connections
- [ ]  Correlate task execution with no interactive user logged in

## 5. Task Persistence Patterns

- [ ]  Identify tasks with triggers: On startup, on logon, recurring intervals
- [ ]  Check for "Run whether user is logged on or not" configuration
- [ ]  Review PowerShell: `Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft\*"}`
- [ ]  Analyze task principals, actions, triggers, and LogonType settings
- [ ]  Verify tasks in non-standard paths outside \Microsoft\ namespace

## 6. Remote Task Scheduling

- [ ]  Correlate Event ID 4698 (task created) with Event ID 4624 Type 3 (Network logon)
- [ ]  Check Sysmon Event ID 3 for RPC connections to port 135 and dynamic RPC ports
- [ ]  Review schtasks.exe with /s parameter for remote system targeting
- [ ]  Search for command patterns: `schtasks /create /s [remote_host]`
- [ ]  Monitor SMB traffic (ports 445, 139) preceding task creation
- [ ]  Identify PowerShell remoting for task creation: Invoke-Command

## 7. AT Command (Legacy)

- [ ]  Check Event ID 4698/601 for AT job creation
- [ ]  Monitor C:\Windows\Tasks*.job file creation (Sysmon Event ID 11)
- [ ]  Review at.exe execution (Sysmon Event ID 1)
- [ ]  Search for command patterns: `at [time] [command]` or `at \\[computer]`

## 8. Linux Cron Jobs

- [ ]  Review /var/log/cron and /var/log/syslog for cron activity
- [ ]  Check /etc/crontab, /etc/cron.d/, /var/spool/cron/crontabs/ for modifications
- [ ]  Monitor /etc/cron.daily/, cron.hourly/, cron.weekly/, cron.monthly/ directories
- [ ]  Identify cron jobs running as root from writable directories
- [ ]  Search for download commands: wget, curl, nc in cron entries
- [ ]  Look for obfuscated or encoded commands in crontabs

## 9. Linux Systemd Timers

- [ ]  List timers: `systemctl list-timers --all`
- [ ]  Check /etc/systemd/system/_.timer and ~/.config/systemd/user/_.timer
- [ ]  Review associated .service files for command execution
- [ ]  Query journals: `journalctl -u [timer_name]` for activation logs
- [ ]  Identify timers with no package association
- [ ]  Look for service files executing from /tmp, /var/tmp, user directories

## 10. COM Task Scheduler Abuse

- [ ]  Review PowerShell Event ID 4104 for Schedule.Service COM object usage
- [ ]  Search scripts for: `New-Object -ComObject Schedule.Service`
- [ ]  Identify VBScript: `CreateObject("Schedule.Service")`
- [ ]  Monitor process command-lines containing COM task creation patterns

## 11. High-Privilege Task Execution

- [ ]  Check Event ID 4698 with UserId set to SYSTEM or Administrators
- [ ]  Review Event ID 4672 (Special privileges) following task execution
- [ ]  Identify tasks configured to run with highest privileges
- [ ]  Look for UAC bypass via Task Scheduler silent elevation
- [ ]  Check for tasks running with stored credentials

## 12. Lateral Movement Detection

- [ ]  Timeline: Event ID 4624 Type 3 → Event ID 4698 (task creation)
- [ ]  Identify task creation on multiple systems in short time windows
- [ ]  Look for similar or identical tasks across multiple hosts
- [ ]  Monitor PsExec, Impacket atexec.py, or WMIC remote task patterns
- [ ]  Check for tasks created via administrative shares (ADMIN,C, C ,C)

## 13. Task Modification and Evasion

- [ ]  Review Event ID 4699/141 for task deletion (evidence removal)
- [ ]  Check Event ID 4702 for task modifications to hide behavior
- [ ]  Identify tasks deleted immediately after execution
- [ ]  Look for disabled tasks or modified triggers
- [ ]  Check for Task Scheduler operational log clearing

## 14. Container Orchestration (Kubernetes/Docker)

- [ ]  List Kubernetes CronJobs: `kubectl get cronjobs --all-namespaces`
- [ ]  Review Kubernetes API audit logs for CronJob creation/modification
- [ ]  Identify CronJobs in unusual namespaces or with privileged contexts
- [ ]  Check for jobs mounting host volumes or using untrusted container images
- [ ]  Monitor Docker event logs for scheduled container execution

## 15. Correlation and Timeline

- [ ]  Timeline: Task creation → File download → Process execution → Network beaconing
- [ ]  Correlate: User compromise → Task creation → Credential access
- [ ]  Track: Lateral movement → Remote task → Data exfiltration
- [ ]  Compare task database to registry entries for orphaned/hidden tasks
- [ ]  Establish baseline of legitimate tasks and alert on deviations