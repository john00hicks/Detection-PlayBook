Instruction Summary for Creating Detection Playbook Guides
Format Structure
Each technique guide should follow this standardized format:

1. Header
# Technique Name: [Technique Code](weblink to MITRE ATT&CK page)
```

### 2. Detection Explanation Section
Provide a comprehensive overview including:
- **What the technique is**: Clear description of the adversary behavior
- **Why it's used**: Attacker objectives (persistence, privilege escalation, lateral movement, etc.)
- **Common variants**: Any sub-techniques or related methods
- **Attack context**: Where this typically fits in the attack lifecycle
- **Impact**: What successful execution means for the organization

Keep this section **2-4 paragraphs**, focusing on actionable intelligence rather than theoretical knowledge.

---

## 3. Key Detection Indicators & Areas to Investigate

This is the **core investigative section**. Structure each indicator as follows:

### Indicator Format:
```
### [Specific Detection Indicator Description]

**[Log Source Category]:**
- Specific event IDs, log types, or data sources
- Key fields to examine
- Where to find the data

**[Additional Log Source]:**
- Related event IDs or log entries
- Correlation opportunities

**Look for / Focus on / Indicators:**
- Specific suspicious patterns
- Baseline vs anomalous behaviour
- Red flags that warrant investigation

**Suspicious indicators / patterns / characteristics:**
- Concrete examples of malicious activity
- Command-line patterns
- File paths, registry keys, or network indicators
- Behavioural patterns

---
```

### Content Guidelines for Detection Indicators:

#### **A. Be Specific and Actionable**
- Provide exact event IDs, not just "check security logs"
- List specific registry paths, file locations, or process names
- Include concrete examples of suspicious patterns
- Focus on what an analyst can immediately search for

#### **B. Organize by Log Source Type**
Each indicator should cover relevant sources:
- **Windows Event Logs** (Security, System, Application)
- **Sysmon** (with specific event IDs)
- **Network Logs** (firewall, proxy, DNS, IDS/IPS, flow data)
- **PowerShell Logs** (script block logging, module logging)
- **Application-Specific Logs** (web server, database, EDR, email gateway)
- **File System/Registry** monitoring points

#### **C. Include Detection Context**
For each indicator, explain:
- **What to look for**: Specific patterns, values, or anomalies
- **Where to look**: Exact log locations, event IDs, or data sources
- **Why it matters**: What this indicator tells you about the attack
- **Baseline considerations**: What's normal vs suspicious
- **False positive warnings**: Legitimate uses that might trigger alerts

#### **D. Provide Granular Detail**
Examples of good vs poor guidance:

**Poor**: "Check for suspicious registry changes"

**Good**: 
```
**Registry locations to monitor:**
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

**Sysmon:**
- Event ID 13 (Registry value set)

**Suspicious indicators:**
- Executables in unusual locations: `%TEMP%`, `%APPDATA%`
- Commands using `cmd.exe`, `powershell.exe` with `-enc` parameter
- Recently created executables without digital signatures
```

#### **E. Focus on Investigative Value**
Prioritize indicators that:
- Have high detection fidelity
- Provide clear evidence of malicious activity
- Help establish attack timeline
- Enable scope determination
- Support lateral movement tracking
- Identify compromised credentials

---

## 4. Number of Indicators to Include

**Aim for 5-10 key detection indicators** per technique, organized by:
- Most common/high-fidelity indicators first
- Supporting or correlating indicators next
- Advanced or edge-case indicators last

Quality over quantity - each indicator should provide distinct investigative value.

---

Writing Style Guidelines
Tone and Language

Direct and actionable: Write for an analyst actively investigating
Present tense: "Monitor for...", "Check...", "Review..."
Imperative when appropriate: "Focus on...", "Look for..."
Avoid speculation: State what to look for, not what might happen
Be precise: Use technical terms correctly

Formatting Standards

Use bold for log source categories and subsection headers
Use code formatting for:

Event IDs (Event ID 4624)
File paths (C:\Windows\System32\)
Registry keys (HKLM\Software\...)
Command-line examples
Process names (svchost.exe)

Number each key indicator
Use bullet points for lists of items
Use numbered lists only for sequential procedures
Use horizontal rules (---) to separate major indicator sections

Technical Accuracy

Verify all event IDs, registry paths, and technical details
Ensure log source names are correct (Sysmon vs Windows Security vs Application)
Distinguish between Windows versions when behavior differs
Note deprecated features (like AT command)
Include both legacy and modern detection methods when relevant


Structure Template
Use this as a template for consistency:
markdown# Technique Name: [TXXXX](https://attack.mitre.org/techniques/TXXXX/)

## Detection Explanation

[2-4 paragraphs explaining the technique, its use, variants, and impact]

## Key Detection Indicators & Areas to Investigate

### Summary of indicators

1. First indicator
2. Second indicator (Potential mitre code it relates to)
etc

---

### [Indicator 1. Name/Description]
**Windows Event Logs:**
- Event ID XXXX - Description
- Key fields to check

**Sysmon:**
- Event ID XX - What it captures

**Network Logs:**
- Log types and what to look for

**Focus on:**
- Specific patterns
- Suspicious indicators
- Behavioral anomalies

---

### [Indicator 2. Name/Description]
[Same structure...]

---

[Continue for 5-10 indicators]

---


## Quality Checklist

Before considering a guide complete, verify:

- [ ] Technique accurately described with context
- [ ] 5-10 distinct detection indicators provided
- [ ] Summary list of indicators
- [ ] Each indicator has specific log sources with event IDs
- [ ] Concrete examples of suspicious activity included
- [ ] File paths, registry keys, process names are accurate
- [ ] Both common and advanced indicators covered
- [ ] False positive considerations mentioned where relevant
- [ ] Correlation opportunities identified
- [ ] Formatting is consistent with other guides
- [ ] All technical details verified for accuracy
- [ ] Actionable for an analyst with no prior context
- [ ] Links to MITRE ATT&CK are correct

---

## Key Principles

1. **Investigative Focus**: Every indicator should answer "What should I look for RIGHT NOW?"
2. **No Assumptions**: Don't assume analyst knows the environment or has context
3. **Specific Over General**: "Event ID 4688" beats "process logs"
4. **Evidence-Based**: Focus on concrete artifacts, not theories
5. **Scope Awareness**: Help analyst determine breadth of compromise
6. **Practical Detection**: Prioritize what's actually detectable in real environments

---

## Examples of Good Indicator Descriptions

### Example 1: Registry Monitoring
```
### Registry Run Keys and Startup Keys (T1547.001)
**Registry locations to monitor:**
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`

**Windows Event Logs:**
- Event ID 4657 (Registry value modification) - Run key modifications

**Sysmon:**
- Event ID 12 (Registry object added/deleted)
- Event ID 13 (Registry value set)
- Event ID 14 (Registry object renamed)

**Suspicious indicators:**
- Executables in unusual locations: `%TEMP%`, `%APPDATA%`, user profile directories
- Commands using `cmd.exe`, `powershell.exe`, `mshta.exe`, `regsvr32.exe`
- Encoded or obfuscated commands
- Executables without digital signatures
- Recently created executables referenced in Run keys
```

### Example 2: Network Behavior
```
### Unexpected outbound connections from web servers following suspicious requests
**Windows Event Logs:**
- Event ID 5156 (Windows Filtering Platform connection) - Outbound connections from web server processes

**Sysmon:**
- Event ID 3 (Network connection) - Network connections from IIS, Apache, Tomcat processes

**Network Logs:**
- Firewall logs - Outbound connections from DMZ web servers to internet
- Netflow/IPFIX - Unusual destination IPs, ports from web server subnets
- Proxy logs - Web server making HTTP/HTTPS requests to external sites

**Focus on:**
- Connections to non-standard ports (not 80/443)
- Long-duration connections (potential C2 channels)
- Connections to known malicious IPs or suspicious domains
- Data exfiltration indicators (large upload volumes)

Common Mistakes to Avoid
❌ Too vague: "Check logs for suspicious activity"
✅ Specific: "Review Event ID 4688 for cmd.exe spawning from w3wp.exe"
❌ Too theoretical: "Attackers might use PowerShell"
✅ Actionable: "Monitor Event ID 4104 for script blocks containing 'Invoke-Mimikatz'"
❌ No context: "Event ID 4624 indicates a logon"
✅ With context: "Event ID 4624 with LogonType 3 from external IP following failed attempts"
❌ Missing location: "Check for malicious files"
✅ Specific location: "Review Sysmon Event ID 11 for .exe creation in %TEMP% or %APPDATA%"
❌ Generic advice: "Monitor network traffic"
✅ Targeted: "Review firewall logs for outbound connections to port 445 from non-server systems"