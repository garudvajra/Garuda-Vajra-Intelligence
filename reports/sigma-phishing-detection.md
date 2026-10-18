# GARUDA–VAJRA INTELLIGENCE

**Independent Cyber Threat & Strategic Research Initiative**

## Research Report 003

**Title:** Building a Defensive Phishing-Detection Rule Using Sigma

**Publication date:** 2026-10-18

**Research type:** Defensive Detection Engineering

**Platform:** Windows process-creation logs

**Framework:** Sigma

**Related MITRE ATT&CK technique:** T1566 — Phishing

---

### 1. Executive Summary

This report develops a Sigma detection rule for suspicious processes launched by Microsoft Office applications. Such process activity can occur after a user interacts with a malicious document, although it can also occur during legitimate business activity.

The objective is to demonstrate how a behaviour-based detection can be described in a vendor-neutral format and tested against synthetic events.

The proposed rule identifies selected scripting or command-interpreter processes whose recorded parent process is Microsoft Word, Excel or PowerPoint. It does not prove that a phishing email was received, that a document is malicious, or that a system has been compromised.

The rule is an experimental starting point. It requires validation against the organisation's actual log fields, baseline activity and security tooling before operational deployment.

### 2. Research Objectives

- Explain the role of Sigma in defensive detection engineering.
- Create a sample rule for suspicious Office child processes.
- Explain each part of the detection logic.
- Define positive and negative test cases.
- Describe safe validation procedures and known limitations.

### 3. What Is Sigma?

Sigma is an open, vendor-neutral format for writing detection rules in YAML. Compatible tooling can translate these rules into queries for supported security monitoring platforms.

A typical Sigma rule includes:

- **Metadata:** Name, author, status, references and severity.
- **Log source:** The operating system and type of events to inspect.
- **Detection:** The event fields and values to match.
- **Condition:** The logical relationship between the detection selections.
- **False positives:** Legitimate activity that might trigger an alert.

Sigma describes the detection logic; the logging platform and its configuration determine whether the relevant events are collected and searchable.

### 4. Detection Scenario

**Scenario:** A Windows endpoint records a Microsoft Office application launching a scripting engine or command interpreter.

Examples of parent processes include:

- `WINWORD.EXE`
- `EXCEL.EXE`
- `POWERPNT.EXE`

Examples of child processes include:

- `powershell.exe`
- `wscript.exe`
- `cscript.exe`
- `mshta.exe`
- `cmd.exe`

This behaviour can be relevant to an investigation when it follows the opening of an unexpected document. However, legitimate automation, macros and business workflows may produce similar events.

**Detection objective:** Identify the process relationship for review, rather than automatically declaring a phishing incident.

### 5. Sample Sigma Rule

**Suggested filename:** `detections/windows_office_suspicious_child_process.yml`

Save the following YAML as a separate rule file.

```yaml
title: Office Application Spawning Suspicious Child Process
id: 8c2d7a61-1f54-4a7c-9b30-2e7d8f61c405
status: experimental
description: |
    Detects selected scripting engines and command interpreters
    launched directly by Microsoft Office applications.
    This behaviour may be suspicious in a phishing investigation
    but can also occur during legitimate activity.
author: GARUDA-VAJRA INTELLIGENCE
date: 2026-10-18
references:
    - https://attack.mitre.org/techniques/T1566/
    - https://sigmahq.io/docs/basics/rules.html
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\WINWORD.EXE'
            - '\EXCEL.EXE'
            - '\POWERPNT.EXE'
    selection_child:
        Image|endswith:
            - '\powershell.exe'
            - '\wscript.exe'
            - '\cscript.exe'
            - '\mshta.exe'
            - '\cmd.exe'
    condition: selection_parent and selection_child
falsepositives:
    - Legitimate Office macros or approved automation
    - Business workflows that invoke command-line tools
    - Administrative or software deployment activity
level: medium
tags:
    - attack.initial_access
    - attack.t1566
fields:
    - ParentImage
    - Image
    - CommandLine
    - User
    - ProcessId
    - ParentProcessId
```

**Important:** This is an original illustrative rule, not a rule certified or endorsed by SigmaHQ. The rule has not been tested against your environment. The field names must match the event schema used by your logging source.

### 6. How the Detection Logic Works

#### A. Log source

```yaml
logsource:
    category: process_creation
    product: windows
```

This tells compatible Sigma tooling that the rule targets Windows process-creation events.

The underlying system must actually collect those events. For example, Sysmon Event ID 1 records process creation when Sysmon is installed and configured appropriately.

#### B. Parent-process selection

```yaml
selection_parent:
    ParentImage|endswith:
        - '\WINWORD.EXE'
        - '\EXCEL.EXE'
        - '\POWERPNT.EXE'
```

The rule checks whether the recorded parent image ends with one of the specified Office executable names.

The `endswith` modifier allows different installation paths while checking the executable-name suffix.

#### C. Child-process selection

```yaml
selection_child:
    Image|endswith:
        - '\powershell.exe'
        - '\wscript.exe'
        - '\cscript.exe'
        - '\mshta.exe'
        - '\cmd.exe'
```

This selection checks whether the child process is one of the listed interpreters or command-line tools.

These programs are legitimate Windows components. Their presence alone is not evidence of malicious activity.

#### D. Condition

```yaml
condition: selection_parent and selection_child
```

The event must satisfy **both** selections:

1. The parent process matches a listed Office application.
2. The child process matches a listed interpreter or command-line tool.

If either selection fails, this rule should not match that event.

#### E. Severity and false positives

The `medium` level indicates that a match should be reviewed rather than treated as conclusive evidence of compromise.

The rule is marked `experimental` because its performance and false-positive rate have not yet been measured against a representative event dataset.

### 7. Safe Testing Plan

Use synthetic log records and a validation tool. Do not send real phishing emails, execute suspicious attachments or download malware to test the rule.

#### Test case A — Expected match

Synthetic event:

```json
{
  "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
  "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "CommandLine": "powershell.exe -NoProfile",
  "User": "LAB\\analyst",
  "ProcessId": 4100,
  "ParentProcessId": 3000
}
```

**Expected result:** Match.

**Reason:** The parent image ends with `\WINWORD.EXE`, and the child image ends with `\powershell.exe`.

This is synthetic data. It does not execute PowerShell.

#### Test case B — Expected match

Synthetic event:

```json
{
  "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
  "Image": "C:\\Windows\\System32\\cmd.exe",
  "CommandLine": "cmd.exe",
  "User": "LAB\\analyst",
  "ProcessId": 4200,
  "ParentProcessId": 3100
}
```

**Expected result:** Match.

**Reason:** Both the parent and child selections match the rule.

#### Test case C — Expected no match

Synthetic event:

```json
{
  "ParentImage": "C:\\Windows\\explorer.exe",
  "Image": "C:\\Windows\\System32\\cmd.exe",
  "CommandLine": "cmd.exe",
  "User": "LAB\\analyst",
  "ProcessId": 4300,
  "ParentProcessId": 3200
}
```

**Expected result:** No match.

**Reason:** The parent image is Windows Explorer, not one of the listed Office applications.

#### Test case D — Expected no match

Synthetic event:

```json
{
  "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
  "Image": "C:\\Program Files\\Example\\ApprovedHelper.exe",
  "CommandLine": "ApprovedHelper.exe",
  "User": "LAB\\analyst",
  "ProcessId": 4400,
  "ParentProcessId": 3300
}
```

**Expected result:** No match.

**Reason:** The child executable is not in the configured list.

These expected outcomes are based on the rule's stated matching logic. They are not results from a completed live SIEM test.

### 8. Validation Procedure

#### Option 1 — Browser-based validation and conversion

1. Open the Sigma documentation: https://sigmahq.io/docs/guide/getting-started.html
2. Review the rule syntax and required fields.
3. Use a compatible Sigma rule converter, such as https://sigconverter.io/, to convert the YAML to a query for a supported backend.
4. Resolve any syntax or backend-mapping errors.
5. Confirm that the generated query checks the intended parent and child process fields.

A successful conversion checks that the rule can be interpreted by that tool; it does not prove that the rule detects real incidents accurately.

#### Option 2 — Validate locally

If Python is already installed in your authorised lab, install Sigma CLI in a suitable Python environment:

```bash
python -m pip install sigma-cli
```

Check the installed version:

```bash
sigma version
```

List supported conversion targets:

```bash
sigma list targets
```

To validate a rule, use the Sigma CLI's available checking functionality and consult its current help output:

```bash
sigma check --help
```

For a backend conversion, replace `TARGET` with a target listed by your installation:

```bash
sigma convert -t TARGET detections/windows_office_suspicious_child_process.yml
```

Conversion may require an appropriate backend plugin. Follow the official Sigma CLI documentation if your installation reports that a target is unavailable.

Official reference: https://github.com/SigmaHQ/sigma-cli

### 9. Test Results Record

Do not mark the rule as validated until you have actually run the tests. Record the results in your repository using a table like this:

| Test | Expected | Actual | Status |
|---|---|---|---|
| A — Word to PowerShell | Match | Pending | Not tested |
| B — Excel to CMD | Match | Pending | Not tested |
| C — Explorer to CMD | No match | Pending | Not tested |
| D — Word to approved helper | No match | Pending | Not tested |
| YAML parsing/conversion | No errors | Pending | Not tested |

After testing, replace “Pending” with the observed outcome and record the tool and version used.

### 10. Limitations and Improvements

The current rule has several limitations:

1. **Not a phishing detector by itself:** It detects a process relationship that may occur after phishing or during legitimate work.
2. **Potential false positives:** Approved macros and enterprise automation may trigger the rule.
3. **Potential blind spots:** Other applications, renamed executables, indirect process chains or uncollected events may not match.
4. **Log-source dependency:** The rule depends on compatible process-creation data and correct field mapping.
5. **No measured effectiveness:** Precision, recall and false-positive rate have not been calculated.

Potential future improvements include correlating suspicious process activity with email-security alerts, unusual authentication events and endpoint telemetry. Any additional logic should be tested against both suspicious and benign data before deployment.

### 11. Confidence Assessment

**Confidence in the intended matching logic:** High, subject to correct field mapping and Sigma interpretation.

**Confidence in detection of phishing incidents:** Low until validated against representative data.

**Confidence in operational readiness:** Not established.

The rule is a starting point for defensive engineering, not a production-ready control or proof of malicious activity.

### 12. Sources

**Source 1 — MITRE ATT&CK**

- Technique: Phishing (T1566)
- URL: https://attack.mitre.org/techniques/T1566/
- Use: Context for the phishing technique.

**Source 2 — Sigma Detection Format**

- Documentation: Rules
- URL: https://sigmahq.io/docs/basics/rules.html
- Use: Rule structure, metadata, log sources and detection logic.

**Source 3 — Sigma CLI**

- Repository: SigmaHQ/sigma-cli
- URL: https://github.com/SigmaHQ/sigma-cli
- Use: Local rule conversion and tooling guidance.

### 13. Independence and Ethics

This research uses public documentation and synthetic events for defensive learning. It does not claim access to classified intelligence, private incident records or any organisation's internal telemetry.

GARUDA–VAJRA INTELLIGENCE is an independent initiative and is not affiliated with or representing any government, military or intelligence agency.

---

**GARUDA–VAJRA INTELLIGENCE**

*Observe. Analyse. Anticipate.*

Independent · Evidence-led · India-focused
