# Incident Runbook: Emergency Access (Break-Glass) Account Used

**Detection:** `break_glass_sign_in` | **Severity:** CRITICAL | **MITRE ATT&CK:** T1078.004 Valid Accounts: Cloud Accounts  
**Auto-Remediation:** No

---

## Overview

Emergency access accounts hold Global Administrator and are excluded from Conditional Access so an administrator can recover the tenant if every other admin is locked out. Because they bypass Conditional Access by design, Microsoft recommends monitoring every sign-in to them. Any sign-in or attempt, successful or not, is an incident: either a declared emergency or someone targeting the most powerful account in the tenant.

## Detection Signal

| Field | Pattern |
|---|---|
| `UserPrincipalName` | one of `break_glass_upns` |
| `ResultType` | any (a failed attempt is still CRITICAL; `detection_signal.succeeded` says which) |

Engine: `detect_break_glass()`. Hunting query: [`queries/break-glass.kql`](../queries/break-glass.kql). The posture check complements it: CA-05 flags every enabled policy that does **not** exclude the emergency account (lockout risk).

## Investigation

1. Is there a declared emergency? Check with the owner of the break-glass procedure.
2. Succeeded or failed? From which IP and app?
3. If it succeeded: every directory change made by the account since.

```kusto
AuditLogs
| where TimeGenerated > ago(24h)
| where tostring(InitiatedBy.user.userPrincipalName) =~ "<break-glass-upn>"
| project TimeGenerated, OperationName, Result, TargetResources
```

## Response

| Step | Microsoft Graph | Graph PowerShell |
|---|---|---|
| Confirm against the emergency procedure | `GET /auditLogs/signIns?$filter=userPrincipalName eq '{upn}'` | `Get-MgAuditLogSignIn` |
| If unplanned: rotate the credential (or FIDO2 key) and revoke sessions | `POST /users/{id}/revokeSignInSessions` | `Revoke-MgUserSignInSession` |
| Review changes made by the account | `GET /auditLogs/directoryAudits?$filter=initiatedBy/user/userPrincipalName eq '{upn}'` | `Get-MgAuditLogDirectoryAudit` |
