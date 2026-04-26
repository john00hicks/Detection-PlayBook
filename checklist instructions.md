# Instructions: Converting Detection Playbooks to Investigation Checklists

## Overview

These instructions guide the conversion of detailed threat detection playbooks into streamlined, actionable investigation checklists. The goal is to transform comprehensive detection guidance into practical checkbox lists that security analysts can use during active incident response.

---

## Conversion Principles

### 1. Consolidation Over Repetition

- **Merge similar detection methods** - If multiple event IDs detect the same behavior, list them together in one checkbox
- **Remove redundant checks** - Eliminate tasks that cover identical ground through different means
- **Combine correlated activities** - Group related indicators that would be investigated together

**Example:**

```
❌ Before (Redundant):
- [ ] Check Event ID 4688 for process creation
- [ ] Review Sysmon Event ID 1 for process creation
- [ ] Monitor process creation logs

✅ After (Consolidated):
- [ ] Review Event ID 4688/Sysmon Event ID 1 for suspicious process creation
```

### 2. Prioritize High-Fidelity Indicators

- **Focus on indicators with low false positive rates**
- **Emphasize detection methods that catch actual attacks**
- **Remove "nice to have" checks in favor of "must have" checks**

**Keep:**

- Specific command patterns (e.g., "procdump -ma lsass")
- Unusual process relationships (Office apps spawning cmd.exe)
- Known malicious file names or registry keys

**Remove:**

- Generic monitoring suggestions without specific thresholds
- Low-value contextual information
- Verbose explanations of normal vs. abnormal behavior

### 3. Simplify Language

- **Use action verbs**: "Check", "Review", "Search", "Verify", "Identify"
- **Be specific**: Include exact event IDs, registry paths, file names
- **Remove verbose descriptions**: Get straight to what needs to be checked
- **Use concise bullet points**: Not paragraphs

**Example:**

```
❌ Before (Verbose):
- [ ] Review Windows Security Event Logs, specifically focusing on Event ID 4688 which captures process creation events, and examine the CommandLine field to identify any instances where procdump.exe has been executed with the -ma parameter targeting the lsass.exe process, which is a strong indicator of credential dumping activity

✅ After (Concise):
- [ ] Search Event ID 4688 for "procdump -ma lsass" in command lines
```

### 4. Maintain Investigative Flow

- **Order checks logically**: Start with detection, move to analysis, end with correlation
- **Group related tasks**: Keep all registry checks together, all process checks together
- **Include correlation points**: Timeline analysis, cross-system checks

---

## Step-by-Step Conversion Process

### Step 1: Identify Major Detection Categories

Read through the playbook and identify distinct detection areas (typically 5-15 categories).

**Example categories:**

- Process execution patterns
- File system modifications
- Registry changes
- Network activity
- Authentication events

### Step 2: Extract Core Indicators per Category

For each category, identify the 3-7 most critical indicators that must be checked.

**Criteria for "critical":**

- High detection accuracy
- Commonly observed in real attacks
- Specific and actionable
- Can be checked with available tools

### Step 3: Consolidate Detection Methods

Combine multiple event sources that detect the same thing.

**Pattern:**

```
If playbook says:
- Windows Event ID X shows behavior Y
- Sysmon Event ID Z shows behavior Y
- Tool A logs behavior Y

Convert to:
- [ ] Check Event ID X/Sysmon Event ID Z for behavior Y
```

### Step 4: Remove Redundancy

Eliminate duplicate checks across categories.

**Check for:**

- Same event ID listed multiple times
- Same file path monitored in different sections
- Same command pattern repeated
- Similar behavioral patterns described differently

### Step 5: Simplify Task Descriptions

Rewrite each task to be clear, specific, and actionable.

**Template:**

```
[Action Verb] + [Specific Log/Tool] + [What to Look For] + [Key Indicator]
```

**Examples:**

- [ ] Check Sysmon Event ID 11 for .exe files on drives D:\ through H:\
- [ ] Review Event ID 4688 for processes with Image paths starting with USB drive letters
- [ ] Search PowerShell Event ID 4104 for "Invoke-Mimikatz" in script blocks

### Step 6: Add Correlation Tasks

Include 1-2 correlation checks that tie indicators together.

**Examples:**

- [ ] Timeline: USB insertion → Process execution → Network activity
- [ ] Correlate shadow copy creation with NTDS.dit access
- [ ] Match file hashes across multiple systems

### Step 7: Optimize for Usability

Final polish to ensure checklist is scannable and practical.

**Checklist should:**

- Fit on 1-3 pages when printed
- Have 5-10 major sections
- Contain 50-70 total checkboxes maximum
- Be completable in 30-60 minutes for skilled analysts

---

## Quality Checks

### Before Finalizing, Verify:

**✅ Completeness**

- [ ] All critical detection methods from playbook are included
- [ ] No major attack patterns are missed
- [ ] Each indicator category has actionable checks

**✅ Clarity**

- [ ] Each checkbox is self-explanatory
- [ ] Specific event IDs, paths, and patterns are included
- [ ] No ambiguous or vague tasks

**✅ Efficiency**

- [ ] No redundant checks
- [ ] Similar tasks are consolidated
- [ ] Focus is on high-value indicators

**✅ Actionability**

- [ ] Each task can be completed with available tools
- [ ] Tasks include specific things to search for
- [ ] Results can be clearly identified as suspicious or benign

---

## Output Format

### Checklist Structure:

```markdown
# [Attack Technique] Investigation Checklist

## 1. [Category Name]

- [ ] [Specific actionable check with event ID/log source]
- [ ] [Specific actionable check with event ID/log source]
- [ ] [Specific actionable check with event ID/log source]

## 2. [Category Name]

- [ ] [Specific actionable check with event ID/log source]
...
```

### Formatting Rules:

- Use H1 (#) for main title
- Use H2 (##) for category sections (numbered 1-10)
- Use checkbox lists (- [ ]) for all investigation tasks
- Include specific event IDs, registry paths, file patterns in each checkbox
- Keep descriptions to one line when possible
- Use inline code formatting (`) for commands, files, registry keys

---

## Example Conversion

### Original Playbook Section:

```
**PowerShell Logs:**
- Event ID 4104 (Script block logging) - PowerShell credential dumping scripts
- Event ID 4103 (Module logging) - Loading of credential access modules

**Script Content to Monitor:**
- Invoke-Mimikatz, Invoke-TokenManipulation, Invoke-CredentialInjection
- Get-Process lsass | Out-Minidump
- sekurlsa::, kerberos::, lsadump::

**Focus on:**
- PowerShell commands accessing credential-related Windows APIs
- Downloading and executing remote PowerShell scripts
- Reflective PE injection techniques
```

### Converted Checklist:

```markdown
## 7. PowerShell Credential Access

- [ ] Review Event ID 4104 for: Invoke-Mimikatz, sekurlsa::, lsadump::
- [ ] Check for downloads from GitHub (PowerSploit, Empire, Covenant repos)
- [ ] Decode -EncodedCommand parameters for credential functions
- [ ] Search for "Get-Process lsass" followed by memory manipulation
```

---

## Common Mistakes to Avoid

❌ **Too Many Checkboxes** - Keep total under 70 ❌ **Vague Tasks** - Always include specific indicators ❌ **Missing Event IDs** - Include exact log sources ❌ **Duplicate Checks** - Consolidate similar detection methods ❌ **No Prioritization** - Most critical checks should come first ❌ **Too Much Explanation** - Let the checkbox speak for itself ❌ **Missing Correlation** - Include at least one timeline/correlation task per category

---

## Success Criteria

A good investigation checklist should:

✅ **Be completable in under 60 minutes** by a skilled analyst ✅ **Contain only high-fidelity indicators** with low false positive rates ✅ **Include specific, searchable patterns** (commands, file names, registry keys) ✅ **Have no redundant or duplicate checks** ✅ **Be organized logically** by detection category ✅ **Include correlation opportunities** for building attack timelines ✅ **Use clear, action-oriented language** with specific log sources