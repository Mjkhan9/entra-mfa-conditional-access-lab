# Incident Runbook: Successful Legacy Authentication

**Detection:** `legacy_auth_sign_in` | **Severity:** HIGH | **MITRE ATT&CK:** T1078.004 Valid Accounts: Cloud Accounts  
**Auto-Remediation:** No

---

## Overview

Legacy protocols (IMAP, POP3, SMTP AUTH, Exchange ActiveSync with basic auth, anything logged as "Other clients") send a username and password and **cannot do MFA**. A successful legacy sign-in therefore bypasses every MFA policy in the tenant. Sometimes it is an old device or a scanner; sometimes it is an attacker using a sprayed password.

## Detection Signal

| Field | Pattern |
|---|---|
| `ResultType` | 0 (success) |
| `ClientAppUsed` | anything other than `Browser` or `Mobile Apps and Desktop clients` |

One incident per user and client app. Engine: `detect_legacy_auth()`. Hunting query: [`queries/legacy-auth.kql`](../queries/legacy-auth.kql) (also the inventory to run before enforcing a block).

## Investigation

1. Which client and app (`ClientAppUsed`, `AppDisplayName`), from which IP?
2. Is it a known device (multifunction printer scanning to email, an old mail client) or unexpected?
3. Was the same IP part of a password spray incident? Then treat it as a compromise.

## Response

| Step | Microsoft Graph | Graph PowerShell |
|---|---|---|
| Find every account still using that client | `GET /auditLogs/signIns?$filter=clientAppUsed eq '{client}'` | `Get-MgAuditLogSignIn -Filter` |
| Enforce the Block legacy authentication policy | `PATCH /identity/conditionalAccess/policies/{id}` `state: enabled` | `Update-MgIdentityConditionalAccessPolicy` |
| Revoke sessions if the sign-in was not expected | `POST /users/{id}/revokeSignInSessions` | `Revoke-MgUserSignInSession` |

The posture check reports the same gap from the policy side (CA-04), including a block policy left in report-only.
