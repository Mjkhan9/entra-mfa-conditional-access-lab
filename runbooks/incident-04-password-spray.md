# Incident Runbook: Password Spray

**Detection:** `password_spray` | **Severity:** HIGH, CRITICAL when a sprayed account then signs in | **MITRE ATT&CK:** T1110.003 Brute Force: Password Spraying  
**Auto-Remediation:** No (containment is an analyst decision)

---

## Overview

An attacker tries one or two common passwords against many accounts from the same source, staying under each account's lockout threshold. Each attempt fails with sign-in error **50126** (*invalid username or password*). Microsoft reports that more than 99 percent of password spray attacks use legacy authentication protocols, which is why the Conditional Access posture check flags an unenforced legacy-auth block (CA-04).

## Detection Signal

| Field | Pattern |
|---|---|
| `ResultType` | 50126 |
| `IPAddress` | same source |
| `UserPrincipalName` | 5+ distinct accounts inside 30 minutes |
| Escalation | a `ResultType` 0 sign-in from the same IP for one of the sprayed accounts -> CRITICAL |

Engine: `detect_password_spray()` in [`functions/detections.py`](../functions/detections.py). Hunting query: [`queries/password-spray.kql`](../queries/password-spray.kql).

## Investigation

1. **Scope.** Which accounts were tried, which client app (`ClientAppUsed`), first and last attempt.
2. **Hits.** Any successful sign-in from the spraying IP? The incident's `detection_signal.compromised_accounts` lists them.
3. **Source.** Is the IP a known VPN / hosting range? Is it also in ID Protection risk detections?
4. **Lockouts.** Smart lockout (50053) incidents for the same accounts in the window.

```kusto
SigninLogs
| where TimeGenerated > ago(24h) and IPAddress == "<spraying-ip>"
| summarize attempts = count(), successes = countif(ResultType == "0") by UserPrincipalName, ClientAppUsed
| order by successes desc, attempts desc
```

## Response (playbook steps attached to the incident)

| Step | Microsoft Graph | Graph PowerShell |
|---|---|---|
| Block the source with a named location + block policy | `POST /identity/conditionalAccess/namedLocations` | `New-MgIdentityConditionalAccessNamedLocation` |
| For each compromised account: force password change | `PATCH /users/{id}` `passwordProfile.forceChangePasswordNextSignIn` | `Update-MgUser -PasswordProfile` |
| Revoke sessions | `POST /users/{id}/revokeSignInSessions` | `Revoke-MgUserSignInSession` |
| Confirm compromised (P2) | `POST /identityProtection/riskyUsers/confirmCompromised` | `Confirm-MgRiskyUserCompromised` |
| Close the gap | run the posture check: CA-02 (MFA for all), CA-04 (block legacy auth) | |

Nothing is executed automatically: blocking an IP range or resetting accounts affects real users.

## Escalation

Escalate immediately when the severity is CRITICAL (a sprayed account signed in), when a sprayed account holds an admin role, or when the same source appears across several days.
