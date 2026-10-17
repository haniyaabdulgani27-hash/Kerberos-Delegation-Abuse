# Kerberos-Delegation-Abuse
# GRAYSENTINEL CYBER DEFENCE LAB

## Defensive Security Operations Unit (DSOU)

# SOC Investigation Report

## Kerberos Delegation Abuse — Resource-Based Constrained Delegation (RBCD)

**Investigation Date:** 16 October 2026
**Environment:** Active Directory / Windows Domain
**Primary System:** DC-01-PRD
**Associated Machine Account:** WS-512$
**Severity:** High — Investigation Required
**Investigation Status:** Open — Pending Evidence Validation

---

## 1. Executive Summary

The Defensive Security Operations Unit (DSOU) received multiple security alerts from the Domain Controller, DC-01-PRD, indicating potential Resource-Based Constrained Delegation (RBCD) abuse within the Active Directory environment.

The reported activity includes modification of the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute, Kerberos ticket requests, network logon activity associated with the WS-512 machine, assignment of special privileges, and execution of an unsigned binary from a temporary directory.

The combination of these events raises concerns about unauthorized delegation changes, potential identity impersonation, privilege escalation, and lateral movement.

Although the Domain Controller is reported as patched and antivirus has returned a “No Threat Found” result, these findings do not independently exclude identity-based attacks or malicious activity involving legitimate Windows authentication mechanisms.

**Initial assessment:** The activity warrants a high-priority investigation. Successful RBCD abuse, privileged access, and domain-wide compromise remain unconfirmed until supporting evidence is collected and correlated.

## 2. Incident Overview

### 2.1 Reported Security Events

| Event ID / Source | Reported activity                                | Investigative significance                                                        |
| ----------------- | ------------------------------------------------ | --------------------------------------------------------------------------------- |
| 5136              | Delegation-related directory attribute modified  | Identify the changed object, responsible identity and modification details        |
| 4769              | Kerberos service-ticket request                  | Investigate unusual service-ticket activity and delegation-related authentication |
| 4768              | TGT request associated with WS-512$              | Establish machine-account authentication context                                  |
| 4624              | Network logon associated with WS-512             | Identify logon context, source and destination                                    |
| 4672              | Special privileges assigned to WS-512$           | Validate the security context and privileges associated with the logon            |
| Sysmon Event 1    | Unsigned binary executed from `C:\Windows\Temp\` | Investigate process origin, parent process, command line and associated activity  |

Event records must be validated against the original Windows logs. The reported alerts are investigative leads and should not be treated as independent proof of malicious activity.

### 2.2 Initial Risk Assessment

The incident presents potential risks to:

- Active Directory identity and delegation integrity.
- Authentication to sensitive servers.
- Privileged account security.
- Domain-wide lateral movement.
- Persistence through unauthorized directory or system changes.

The actual impact depends on the modified target object, effective delegation permissions, account privileges, and evidence of subsequent access.

---

## 3. Mission 01 — Asset Discovery and Environment Assessment

The objective is to establish the affected assets, their operational importance, and the identity responsible for the reported configuration change.

| Investigation area           | Required validation                                                                                    |
| ---------------------------- | ------------------------------------------------------------------------------------------------------ |
| DC-01-PRD                    | Confirm Domain Controller role, FSMO roles, business criticality and security controls                 |
| WS-512$                      | Verify machine-account ownership, authentication history and legitimate purpose                        |
| Modified directory object    | Identify the target server whose delegation attribute changed                                          |
| Target server classification | Determine whether the target is a file server, SQL server, Domain Controller or another critical asset |
| Wazuh agent                  | Validate connectivity, agent version, event collection and ingestion health                            |
| Patch and endpoint security  | Review patch history, EDR status and security-policy compliance                                        |
| Directory permissions        | Identify principals with effective rights to modify the affected attribute                             |
| Delegation history           | Review delegation changes during the preceding seven days                                              |
| Authentication history       | Correlate WS-512$ logons with the reported alert window                                                |
| Network activity             | Review relevant inbound and outbound connections involving WS-512                                      |

### Expected Deliverable

An asset map identifying the affected systems, their roles, relevant identities, trust relationships and dependencies.

**Current limitation:** The supplied scenario does not identify the exact target object or the principal that modified it. These details must be obtained from the original directory audit records.

---

## 4. Mission 02 — Threat-Hunting Hypotheses

### Hypothesis H1: Unauthorized RBCD Configuration for User Impersonation

**Hypothesis statement:** An unauthorized modification to the target server's RBCD configuration may have enabled a compromised machine account to request Kerberos service tickets on behalf of other users.

**Evidence required:**

- Event 5136 identifying the affected directory object and attribute.
- The modifying account and relevant directory permissions.
- Previous and resulting attribute values, where available.
- Subsequent Kerberos service-ticket requests.
- Evidence of access to the target service.

**Data sources:** Windows Security logs, Active Directory auditing, Kerberos logs and Wazuh.

**Expected indicators:**

- An unexpected delegation configuration change.
- A modifying identity without a valid business justification.
- Unusual authentication involving the configured machine account.
- Subsequent access to a sensitive service inconsistent with normal activity.

**Potential false positives:**

- Approved server migrations.
- Legitimate delegation configuration changes.
- Authorized infrastructure maintenance.

**Investigation conclusion:** Confirm only when the unauthorized configuration change is established and supporting evidence demonstrates its relationship to suspicious authentication or access.

### Hypothesis H2: Compromise of an Identity with Active Directory Write Permissions

**Hypothesis statement:** An account with effective directory write permissions may have been compromised and used to modify delegation settings for unauthorized access or privilege escalation.

**Evidence required:**

- Identification of the account that performed the directory modification.
- Effective permissions over the affected object and attribute.
- Authentication and logon history around the modification.
- Associated endpoint and network activity.
- Evidence linking the identity to the suspicious process or other malicious activity.

**Data sources:** Active Directory audit logs, Windows Security events, Sysmon, Wazuh and endpoint telemetry.

**Expected indicators:**

- Unexpected changes performed by a privileged or service identity.
- Unusual source hosts or logon patterns.
- Suspicious process execution near the change.
- Additional unauthorized directory modifications.

**Potential false positives:**

- Legitimate automation accounts.
- Approved administrative tools.
- Scheduled infrastructure changes.

**Investigation conclusion:** Determine whether the modifying identity was legitimately used, compromised, or misconfigured. Avoid attributing the activity to a compromised account without supporting evidence.

### Hypothesis H3: RBCD Abuse as a Precursor to Lateral Movement or Persistence

**Hypothesis statement:** The delegation change may be part of a broader intrusion intended to access additional systems, obtain privileged access or establish persistence.

**Evidence required:**

- Related Kerberos ticket activity.
- Authentication to unexpected servers.
- Changes to privileged group memberships.
- Directory replication permission changes.
- Suspicious scheduled tasks, services or executable activity.
- Evidence of unauthorized access to other Domain Controllers.

**Data sources:** Windows Security logs, Sysmon, Wazuh, Active Directory auditing and network telemetry.

**Expected indicators:**

- Authentication activity inconsistent with the machine account's normal role.
- Unauthorized privilege or directory permission changes.
- Suspicious activity across multiple systems.
- Additional persistence mechanisms.

**Potential false positives:**

- Authorized administrative activity.
- Legitimate service-to-service authentication.
- Approved maintenance and deployment operations.

**Investigation conclusion:** Domain-wide compromise must remain unconfirmed unless additional evidence establishes lateral movement, unauthorized privileged access or persistence.

---

## 5. Mission 03 — Detection Engineering

### 5.1 Detection Specification

**Detection Name:** Suspicious RBCD Modification with Correlated Kerberos Activity

**Objective:** Detect potentially unauthorized RBCD configuration changes and prioritize investigation when subsequent authentication activity supports the same incident.

**Telemetry requirements:**

- Windows Security Event 5136.
- Windows Security Events 4768 and 4769.
- Windows Security Events 4624 and 4672.
- Sysmon process-creation telemetry.
- Wazuh agent and event-ingestion health.

**Relevant fields:**

- Event timestamp and originating system.
- Subject account and security identifier.
- Directory object distinguished name.
- Modified attribute name.
- Previous and resulting attribute values, if available.
- Kerberos account, service and ticket-related fields.
- Source network address and logon details.
- Process image, parent process and command line.

### 5.2 Sigma-Like Detection Logic

```text
RULE: Suspicious_RBCD_Change

WHEN:
    EventID = 5136
    AND AttributeName =
        "msDS-AllowedToActOnBehalfOfOtherIdentity"

THEN:
    Record the affected object
    Record the modifying identity
    Preserve available change details
    Check whether the change was authorized

CORRELATE:
    Subsequent unusual EventID 4769 activity
    AND relevant authentication events
    AND suspicious endpoint or network activity

PRIORITIZE:
    Unauthorized directory change
    + correlated suspicious authentication
    + evidence of unexpected target access

ACTION:
    Generate an investigation alert
    Preserve supporting events
    Initiate incident response when warranted
```

This is conceptual detection logic, not a validated Sigma rule or directly executable Wazuh configuration. Implementation requires mapping the fields to the actual event schema and testing the correlation against authorized activity.

### 5.3 Severity and Alert Handling

**Initial severity:** High priority for investigation, based on the combination of reported signals.

Escalate severity when an unauthorized delegation change is corroborated by suspicious authentication, privileged access or malicious process activity.

Potential false positives include authorized delegation changes, infrastructure automation and legitimate service-account authentication.

### 5.4 Analyst Response

1. Validate the directory modification against approved change records.
2. Identify the responsible account and its effective permissions.
3. Correlate Kerberos requests with the relevant identities and target services.
4. Investigate the unsigned binary, including its origin and execution context.
5. Determine whether the activity is authorized, suspicious or confirmed malicious.
6. Preserve evidence and initiate containment through the approved incident-response process when required.

---

## 6. Mission 04 — Identity, Delegation and Persistence Investigation

The investigation must extend beyond the initial attribute modification to determine whether additional changes or persistence mechanisms are present.

### 6.1 Investigation Checklist

- [ ] Review all relevant `msDS-AllowedToActOnBehalfOfOtherIdentity` modifications.
- [ ] Identify unexpected machine-account creation.
- [ ] Investigate unusual Kerberos service-ticket requests and delegation-related authentication.
- [ ] Review changes to unconstrained and constrained delegation settings.
- [ ] Audit Domain Admins and Enterprise Admins membership changes.
- [ ] Investigate changes to directory replication permissions.
- [ ] Review evidence of possible Golden Ticket activity.
- [ ] Verify the history of `krbtgt` password resets and relevant domain recovery actions.
- [ ] Investigate suspicious scheduled tasks and services on DC-01-PRD.
- [ ] Review related executable and process activity.
- [ ] Investigate authentication and lateral movement involving other Domain Controllers.

### 6.2 Evidence Preservation Before Remediation

Before removing a suspected unauthorized delegation relationship, the analyst should preserve:

- The current attribute value and relevant directory-object details.
- Available audit records identifying the change and modifying principal.
- Relevant Kerberos, logon and endpoint events.
- The associated incident timeline and approved change records.

The analyst should also determine whether the configuration supports a legitimate business function.

If active exploitation is suspected, containment must follow the incident-response plan. Evidence preservation should not unnecessarily delay urgent containment.

### 6.3 Credential and Domain Recovery Considerations

If WS-512$ is confirmed or reasonably suspected to be compromised, its machine-account credentials should be handled according to the incident-response plan and Active Directory dependencies.

If evidence establishes broader credential compromise, the response must extend to the affected identities and systems.

A `krbtgt` password reset should not be initiated solely because an RBCD alert occurred. It is a separate domain-recovery action that requires evidence and careful planning. When Golden Ticket compromise is established, the recovery plan must account for the required password-reset sequence, replication and operational impact.

---

## 7. Mission 05 — Incident Response and Closure

### 7.1 Containment

- [ ] Verify the containment status of DC-01-PRD.
- [ ] Determine whether WS-512 requires isolation or other containment.
- [ ] Preserve Windows Security, Sysmon, Wazuh and relevant directory evidence.
- [ ] Assess whether other identities or systems require containment.
- [ ] Coordinate response actions with the authorized Active Directory owner.

### 7.2 Investigation and Remediation

- [ ] Review Events 5136, 4769, 4768, 4624 and 4672.
- [ ] Identify the affected directory object and modifying account.
- [ ] Verify whether the delegation change was authorized.
- [ ] Audit effective delegation permissions.
- [ ] Review privileged group membership and replication permissions.
- [ ] Investigate suspicious processes, services and scheduled tasks.
- [ ] Review possible lateral movement to other servers and Domain Controllers.
- [ ] Remove unauthorized delegation configuration after preserving evidence and validating dependencies.
- [ ] Rotate affected credentials where justified by the investigation.
- [ ] Validate remediation and monitor for recurring suspicious activity.

### 7.3 Evidence and Recovery

- [ ] Preserve original event records and supporting forensic evidence.
- [ ] Document evidence sources, collection times and chain of custody.
- [ ] Calculate cryptographic hashes for collected evidence where appropriate.
- [ ] Confirm Wazuh agent health and log-ingestion continuity.
- [ ] Validate detection rules against known-good and suspicious test cases.
- [ ] Inform the relevant business and Active Directory owners.
- [ ] Document residual risks, recovery actions and monitoring requirements.

### 7.4 Closure Criteria

The incident should be closed only when:

1. The reported activity has been investigated and classified.
2. The affected identities, objects and systems have been identified to the extent supported by evidence.
3. Required containment and remediation have been verified.
4. Relevant persistence and lateral-movement hypotheses have been addressed.
5. Evidence is preserved and the investigation is documented.
6. Outstanding risks and monitoring requirements have been formally recorded.

If these conditions cannot be established, the case should remain open or be transferred with documented outstanding actions.

---

## 8. Senior SOC Assessment: Alert Volume Versus Detection Health

**Question:** Which is more dangerous: 10,000 Kerberos delegation alerts or zero alerts over 48 hours?

My assessment is that zero alerts may represent the greater risk if the Domain Controller is expected to produce relevant telemetry but the detection pipeline has silently failed.

However, zero alerts alone do not demonstrate compromise. The analyst must distinguish between genuinely low activity and missing or ineffective detection.

The investigation should verify:

- Windows Security audit configuration.
- Wazuh agent connectivity and health.
- Event ingestion and parsing.
- Detection-rule status and coverage.
- Expected event arrival rates.
- Controlled validation of the detection pipeline.

Conversely, 10,000 alerts may indicate excessive noise, a misconfigured rule or a genuine incident. High alert volume can also create analyst fatigue and delay response to critical events.

**Detection engineering conclusion:** Detection quality depends on reliable telemetry, validated logic, adequate coverage and actionable alerts—not merely the number of alerts generated.

---

## 9. Final Assessment

The reported combination of an RBCD-related directory modification, unusual Kerberos activity, network logons, special-privilege assignment and unsigned process execution represents a potentially serious Active Directory security incident.

The available scenario supports prioritizing the case for investigation, but does not independently establish successful impersonation, Domain Admin compromise or domain-wide persistence.

The investigation should focus on identifying the modified object, validating the responsible identity, correlating authentication and endpoint evidence, and determining whether the changes were authorized.

The primary lesson is that security alerts must be interpreted in context. A reliable SOC conclusion requires evidence connecting the configuration change to suspicious authentication and, where applicable, unauthorized access or persistence.


