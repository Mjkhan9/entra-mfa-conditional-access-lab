# Incident Runbook: Admin Signed In With a Password Only

**Detection:** `privileged_single_factor` | **Severity:** HIGH | **MITRE ATT&CK:** T1078.004 Valid Accounts: Cloud Accounts  
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

Admin accounts are listed in `privileged_upns` (terraform.tfvars). I first looked them up from Graph role assignments at detection time, but in Azure that lookup came back empty without an error, so nothing ever fired. A configured list is simpler and easy to check. One incident per admin per day, since a single browser session produces many sign-in rows. Code: `detect_privileged_single_factor()`. Hunting query: [`queries/privileged-single-factor.kql`](../queries/privileged-single-factor.kql).

## Seen in the lab

First real (not simulated) incident, 2026-11-09: my own Global Admin account signed in 21 times in a day with a password only (OfficeHome, SharePoint, a Copilot extension). The lab tenant has no Conditional Access policies and security defaults are off, and the posture check says the same thing (CA-01, CA-03).

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
