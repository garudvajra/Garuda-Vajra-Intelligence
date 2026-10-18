# GARUDA–VAJRA INTELLIGENCE

**Independent Cyber Threat & Strategic Research Initiative**

## Research Report 002

**Title:** Phishing Threat Analysis: MITRE ATT&CK Mapping and Defensive Detection

**Publication date:** 2026-10-18

**Research type:** Open-Source Cyber Threat Intelligence (OSINT)

**Focus:** Phishing · Initial Access · Detection · Defensive Security

---

### 1. Executive Summary

Phishing is a social-engineering technique used to persuade people to interact with malicious messages, links, attachments or impersonated services. It can be used to obtain credentials, deliver malware or establish unauthorised access to systems.

MITRE ATT&CK documents phishing as technique **T1566**, within the Initial Access tactic. Its documented sub-techniques include spearphishing attachments, spearphishing links, phishing through services and voice phishing.

This report maps the technique to defensive controls and potential detection opportunities. It is a general technical assessment, not a claim that a specific phishing campaign has targeted an Indian organisation.

### 2. Research Objectives

- Document the phishing technique using MITRE ATT&CK.
- Identify the principal delivery methods covered by the framework.
- Outline practical defensive controls.
- Describe telemetry that security teams can correlate when investigating suspected phishing.
- Record the limitations of the available evidence.

### 3. Sources and Methodology

This report uses publicly accessible technical documentation from MITRE ATT&CK and the US Cybersecurity and Infrastructure Security Agency (CISA).

The method is a source-based review:
1. Review the documented phishing technique and sub-techniques.
2. Extract defensive mitigations and detection concepts.
3. Translate those concepts into a general defensive checklist.
4. Separate documented facts from analytical recommendations.

No victim systems were accessed, no live phishing infrastructure was tested, and no specific campaign was independently attributed.

### 4. Technical Findings

#### Finding 1: Phishing has multiple delivery methods

**Evidence:** MITRE ATT&CK identifies technique T1566 and the following sub-techniques:

- T1566.001 — Spearphishing Attachment
- T1566.002 — Spearphishing Link
- T1566.003 — Spearphishing via Service
- T1566.004 — Spearphishing Voice

**Assessment:** Organisations should not limit phishing defences to email attachments. Security awareness, reporting and detection processes should also consider malicious links, collaboration platforms and voice-based social engineering.

**Limitation:** The framework describes known adversary techniques. It does not establish how frequently each method is used against Indian organisations.

#### Finding 2: Phishing can be associated with suspicious activity after message delivery

**Evidence:** MITRE's phishing detection guidance describes correlating suspicious email activity with file creation, unusual process execution, browser activity and outbound network connections.

**Assessment:** Reviewing an email in isolation may miss later stages of an intrusion. Where telemetry is available, defenders should correlate mail, endpoint, identity and network records.

**Defensive detection ideas:**
- An unusual attachment followed by unexpected file execution.
- A suspicious email link followed by navigation to a lookalike domain.
- An office or document application spawning an unexpected command interpreter.
- An unusual sign-in or account activity following a suspected phishing event.

These are investigation leads, not proof of compromise on their own.

#### Finding 3: Multifactor authentication strengthens account protection

**Evidence:** CISA recommends enabling multifactor authentication and prioritising stronger, phishing-resistant methods where supported.

**Assessment:** MFA can reduce the risk of account compromise from stolen passwords. However, some MFA methods remain vulnerable to phishing or social-engineering attacks.

**Recommendation:** Prioritise phishing-resistant authentication for administrator accounts, remote access and other high-impact systems where practical.

### 5. Defensive Recommendations

Organisations should consider the following measures:

1. Enable MFA, prioritising phishing-resistant methods where supported.
2. Configure email security controls and sender-domain authentication appropriately.
3. Use filtering and endpoint protection to help identify suspicious messages and attachments.
4. Train staff to verify unusual requests through a separate, trusted channel.
5. Provide a simple process for reporting suspicious messages.
6. Monitor identity-provider logs for unusual sign-ins and unexpected authentication events.
7. Correlate email, endpoint and network telemetry during investigations.
8. Preserve relevant message headers, timestamps, logs and files according to incident-response procedures.
9. Review access permissions and promptly revoke suspicious sessions or credentials when compromise is confirmed.
10. Exercise incident-response procedures using authorised simulations.

### 6. MITRE ATT&CK Mapping

| Field | Mapping |
|---|---|
| Framework | MITRE ATT&CK Enterprise |
| Technique | T1566 — Phishing |
| Tactic | Initial Access |
| Relevant sub-techniques | T1566.001, T1566.002, T1566.003, T1566.004 |
| Defensive objective | Reduce successful delivery and detect suspicious follow-on activity |

This mapping describes a recognised technique. It does not attribute activity to a particular threat actor.

### 7. Confidence Assessment

**Confidence in the description of T1566:** High.

**Confidence in the general defensive recommendations:** High as a summary of the cited guidance.

**Confidence in claims about prevalence or targeting within India:** Insufficient evidence.

**Rationale:** The report relies on established public technical references. It does not include an Indian incident dataset, independently verified campaign evidence or measurements of control effectiveness.

### 8. Sources

**Source 1 — MITRE ATT&CK**

- Title: Phishing, Technique T1566
- URL: https://attack.mitre.org/techniques/T1566/
- Use: Technique description, sub-techniques, mitigations and detection concepts.

**Source 2 — MITRE ATT&CK**

- Title: Spearphishing Link, Technique T1566.002
- URL: https://attack.mitre.org/techniques/T1566/002/
- Use: Link-based phishing and associated defensive detection concepts.

**Source 3 — CISA**

- Title: Require Multifactor Authentication
- URL: https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/require-multifactor-authentication
- Use: Defensive guidance on MFA and stronger authentication methods.

### 9. Limitations

This is a framework-based assessment, not an investigation of a specific incident. It does not establish campaign attribution, victim identities, incident frequency or the effectiveness of any particular security product.

The recommendations should be adapted to an organisation's environment and validated through authorised security testing.

### 10. Independence and Ethics

This report is intended for defensive cybersecurity research and public-interest awareness. It relies on publicly available sources and does not claim access to classified or confidential intelligence.

GARUDA–VAJRA INTELLIGENCE is an independent initiative and is not affiliated with or representing any government, military or intelligence agency.

---

**GARUDA–VAJRA INTELLIGENCE**

*Observe. Analyse. Anticipate.*

Independent · Evidence-led · India-focused
