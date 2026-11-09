# Incident Runbook: Admin Signed In With a Password Only

**Detection:** `privileged_single_factor` · **Severity:** HIGH · **MITRE ATT&CK:** T1078.004 Valid Accounts: Cloud Accounts  
**Auto-Remediation:** No

---

## Overview

A holder of one of the 14 roles Microsoft says must be protected with (phishing-resistant) MFA signed in successfully with `AuthenticationRequirement = singleFactorAuthentication`. Either no Conditional Access policy covers that role for that app, or the policy is excluded, report-only or disabled. Whoever has that password has an admin session.

## Detection Signal

| Field | Pattern |
|---|---|
| `ResultType` | 0 |
| `AuthenticationRequirement` | `singleFactorAuthentication` |
| `UserPrincipalName` | holds an admin role |

Who is an admin comes from Microsoft Graph at detection time: `GET /roleManagement/directory/roleAssignments?$expand=principal`, filtered to Microsoft's 14 recommended roles (application permission `RoleManagement.Read.Directory`, read-only). Extra accounts can be listed in `privileged_upns`. Engine: `detect_privileged_single_factor()`. Hunting query: [`queries/privileged-single-factor.kql`](../queries/privileged-single-factor.kql).

## Investigation

1. Was it the admin? Confirm out of band.
2. Which app, IP and client? Admin portals from an unknown IP are the worst case.
3. Run the posture check: CA-03 names the admin roles with no enabled MFA policy.
4. Is the role assignment permanent or PIM-eligible? Standing assignments widen the window.

## Response

| Step | Microsoft Graph | Graph PowerShell |
|---|---|---|
| List the admin's role assignments | `GET /roleManagement/directory/roleAssignments?$filter=principalId eq '{id}'` | `Get-MgRoleManagementDirectoryRoleAssignment` |
| Require phishing-resistant MFA for all 14 roles | `GET /identity/conditionalAccess/policies` (posture check CA-03) | `Get-MgIdentityConditionalAccessPolicy` |
| Revoke sessions if not the admin | `POST /users/{id}/revokeSignInSessions` | `Revoke-MgUserSignInSession` |

## Interview Talking Point

> "I don't hardcode who the admins are. The function reads role assignments from Microsoft Graph with a read-only permission, so the detection follows the tenant: assign someone Security Administrator and their next password-only sign-in raises an incident."

---

*Last Updated: November 2026*
