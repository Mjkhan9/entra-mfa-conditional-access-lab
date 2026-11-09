# Incident Runbook: Policy Mismatch (MFA Satisfied but Access Blocked)

**Scenario:** User satisfies MFA but a Conditional Access policy blocks access  
**Severity:** MEDIUM  
**Auto-Remediation:** No (admin intervention required)

---

## Overview

User authenticates successfully with MFA, but the sign-in ends with **53003** (*BlockedByConditionalAccess*) or a related grant failure (**53000** DeviceNotCompliant, **53001** DeviceNotDomainJoined). A Conditional Access policy has a grant control that isn't satisfied even though MFA was.

Common causes:
- Policy grant set to **Require all the selected controls** (MFA *and* compliant device) when **Require one of** was intended
- **Sign-in frequency** session control forcing reauthentication on an older session
- **Authentication strength** requiring phishing-resistant MFA while the user registered Authenticator push or SMS
- Policy scoped to the wrong group, or the user missing from an exclusion group

---

## Detection Signal

### Sign-in Log Record Pattern

```json
{
  "category": "SignInLogs",
  "resultType": "53003",
  "resultDescription": "Access has been blocked by Conditional Access policies. The access policy does not allow token issuance.",
  "properties": {
    "userPrincipalName": "<affected-user>",
    "appDisplayName": "Azure portal",
    "resourceDisplayName": "Windows Azure Service Management API",
    "authenticationRequirement": "multiFactorAuthentication",
    "conditionalAccessStatus": "failure",
    "appliedConditionalAccessPolicies": [
      {
        "displayName": "Require compliant device for Azure management",
        "result": "failure",
        "enforcedGrantControls": [ "Mfa", "RequireCompliantDevice" ]
      }
    ],
    "authenticationDetails": [
      { "authenticationStepRequirement": "Multi-factor authentication", "succeeded": true,
        "authenticationStepResultDetail": "MFA requirement satisfied by claim in the token" }
    ]
  }
}
```

### KQL Query (Log Analytics)

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType in ("53003", "53000", "53001")
| where ConditionalAccessStatus == "failure"
| where AuthenticationRequirement == "multiFactorAuthentication"
| mv-expand policy = ConditionalAccessPolicies
| where policy.result == "failure"
| project TimeGenerated, UserPrincipalName, AppDisplayName, ResultType,
          Policy = tostring(policy.displayName), GrantControls = tostring(policy.enforcedGrantControls)
| order by TimeGenerated desc
| take 50
```

---

## Investigation Steps

### Step 1: Confirm MFA was satisfied on the blocked sign-in

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where UserPrincipalName == "<affected-user>"
| where ConditionalAccessStatus == "failure"
| mv-expand step = AuthenticationDetails
| where step.authenticationStepRequirement == "Multi-factor authentication"
| project TimeGenerated, AppDisplayName, ResultType, Succeeded = tobool(step.succeeded),
          Detail = tostring(step.authenticationStepResultDetail)
| order by TimeGenerated desc
| take 20
```

If the MFA step shows `Succeeded = true` but the sign-in was blocked, this is a policy mismatch.

### Step 2: Identify the denying policy

Open the sign-in in the Entra admin center > **Conditional Access** tab: the policy with result **Failure** is the one. Then reproduce it with the **What If** tool (Entra admin center > Protection > Conditional Access > What If) using the same user, app, device platform and location.

```powershell
# Same check from Graph: list policies and the grant controls they enforce
Connect-MgGraph -Scopes "Policy.Read.All"
Get-MgIdentityConditionalAccessPolicy |
  Select-Object DisplayName, State,
    @{n='Operator';e={$_.GrantControls.Operator}},
    @{n='Controls';e={$_.GrantControls.BuiltInControls -join ','}}
```

Expected output shows which policy carries the failing control and whether its operator is `AND` or `OR`.

### Step 3: Retrieve and analyze the policy

```powershell
# Full policy document
Get-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId <policy-id> | ConvertTo-Json -Depth 10
```

```bash
# Same thing with Azure CLI
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/<policy-id>"
```

### Step 4: Check for common grant control mistakes

**Common Issue 1: AND vs OR**
```json
// WRONG - requires MFA *and* a compliant device; an MFA user on an unmanaged device is blocked
"grantControls": {
  "operator": "AND",
  "builtInControls": [ "mfa", "compliantDevice" ]
}

// CORRECT - either control satisfies the policy
"grantControls": {
  "operator": "OR",
  "builtInControls": [ "mfa", "compliantDevice" ]
}
```

**Common Issue 2: Session Age**
```json
// This forces reauthentication when the session is older than 1 hour
"sessionControls": {
  "signInFrequency": {
    "isEnabled": true,
    "type": "hours",
    "value": 1
  }
}
```

---

## Resolution

### Fix the Conditional Access Policy

1. **Identify the incorrect grant control or operator**
2. **Switch the policy to Report-only, update it, and read the report-only results**
3. **Verify with the What If tool**

```powershell
# Correct the operator (requires Conditional Access Administrator)
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"
Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId <policy-id> -BodyParameter @{
  grantControls = @{
    operator         = "OR"
    builtInControls  = @("mfa", "compliantDevice")
  }
}
```

### Corrected Policy Example

```json
{
  "displayName": "Require compliant device for Azure management",
  "state": "enabled",
  "conditions": {
    "users": { "includeGroups": [ "<azure-admins-group-id>" ] },
    "applications": { "includeApplications": [ "797f4846-ba00-4fd7-ba43-dac1f8f63013" ] }
  },
  "grantControls": {
    "operator": "OR",
    "builtInControls": [ "mfa", "compliantDevice" ]
  }
}
```

### Verification

```text
Entra admin center > Protection > Conditional Access > What If
  User:          <affected-user>
  Cloud app:     Windows Azure Service Management API
  Device:        <platform the user signs in from>

Expected: the policy is listed under "Policies that will apply" with grant controls
"Require multifactor authentication OR Require device to be marked as compliant",
and the next sign-in shows ConditionalAccessStatus = success.
```

---

## Escalation Criteria

Escalate to Identity / Cloud Security team if:
- [ ] Policy change requires CAB approval
- [ ] Multiple users affected by same policy
- [ ] Unclear which policy is causing the block
- [ ] The block comes from a Microsoft-managed policy or security defaults

---

## Post-Incident

### Documentation

- [ ] Record incident in Cosmos DB
- [ ] Document which policy was incorrect
- [ ] Note the fix applied
- [ ] Update any IaC (Terraform `azuread_conditional_access_policy`) to prevent regression

### Prevention

- Manage Conditional Access policies as code (Terraform azuread provider)
- Roll out every policy change in Report-only mode first and read the Conditional Access insights and reporting workbook
- Keep a break-glass account excluded from all policies
- Document MFA and device requirements per app in runbooks

---

## Portal Evidence

| Evidence | Location |
|----------|----------|
| Incident records with policy mismatch details | `screenshots/cosmos-incidents.png` |
| Sign-in log Conditional Access tab showing the failing policy | `screenshots/signin-conditional-access.png` |

Each policy mismatch incident in Cosmos DB includes the `detection_signal` with:
- `failed_policies` - The policy names and the grant controls they enforced
- `condition_evaluated` - The operator that failed (`AND` where `OR` was intended)
- `resource` - The target app or resource

---

## Interview Talking Point

> "Policy mismatch is one of the trickiest MFA issues because the user did everything right. They completed MFA, but a grant control in Conditional Access still isn't satisfied. I've seen it with 'Require all the selected controls' where 'Require one' was intended, and with sign-in frequency forcing reauthentication. The fix is straightforward once you identify it, but the investigation requires reading the Conditional Access tab on the sign-in and understanding how grant controls combine. I use What If and Report-only mode to verify before and after the change."

---

*Last Updated: November 2026*
