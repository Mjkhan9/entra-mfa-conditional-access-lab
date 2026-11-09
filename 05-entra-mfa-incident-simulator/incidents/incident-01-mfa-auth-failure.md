# Incident Runbook: MFA Authentication Failure

**Scenario:** MFA authentication failure consistent with an expired or mistyped verification code  
**Severity:** MEDIUM  
**Auto-Remediation:** No (user action required)

---

## Overview

User signs in with the correct password but the MFA step fails. Entra ID logs this as sign-in error **500121** (*Authentication failed during strong authentication request*). This pattern is consistent with:
- TOTP code expired (30-second window passed before the user submitted it)
- Clock drift between the Authenticator app and the service
- User entered an incorrect code
- Push notification timed out or was never answered

---

## Detection Signal

### Sign-in Log Record Pattern

```json
{
  "category": "SignInLogs",
  "resultType": "500121",
  "resultDescription": "Authentication failed during strong authentication request.",
  "properties": {
    "userPrincipalName": "<affected-user>",
    "ipAddress": "<user-ip>",
    "appDisplayName": "Azure portal",
    "authenticationRequirement": "multiFactorAuthentication",
    "status": {
      "errorCode": 500121,
      "failureReason": "Authentication failed during strong authentication request.",
      "additionalDetails": "The user didn't complete the MFA prompt. They may have decided not to authenticate, timed out while doing other work, or has an issue with their authentication setup."
    },
    "authenticationDetails": [
      { "authenticationStepRequirement": "Primary authentication", "authenticationMethod": "Password", "succeeded": true },
      { "authenticationStepRequirement": "Multi-factor authentication", "authenticationMethod": "OATH verification code", "succeeded": false,
        "authenticationStepResultDetail": "MFA denied; invalid mobile app verification code" }
    ]
  }
}
```

### KQL Query (Log Analytics)

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType in ("500121", "50074", "50076")
| where AuthenticationRequirement == "multiFactorAuthentication"
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ResultType, ResultDescription,
          AdditionalDetails = tostring(Status.additionalDetails), AuthenticationDetails
| order by TimeGenerated desc
| take 50
```

---

## Investigation Steps

### Step 1: Confirm the failure pattern

```bash
# Query recent MFA failures from the workspace
az monitor log-analytics query \
  --workspace "<workspace-id>" \
  --timespan PT1H \
  --analytics-query 'SigninLogs
    | where ResultType in ("500121", "50074", "50076")
    | project TimeGenerated, UserPrincipalName, IPAddress, ResultDescription, tostring(Status.additionalDetails)
    | order by TimeGenerated desc
    | take 20'
```

### Step 2: Check for a prior successful MFA sign-in

If the user completed MFA within the last 15 minutes, this suggests an expired code mid-session rather than a persistent problem.

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where UserPrincipalName == "<affected-user>"
| project TimeGenerated, ResultType, ResultDescription, AuthenticationRequirement, MfaDetail
| order by TimeGenerated desc
| take 10
```

### Step 3: Verify the user's registered authentication methods

```powershell
Connect-MgGraph -Scopes "UserAuthenticationMethod.Read.All"
Get-MgUserAuthenticationMethod -UserId <affected-user> | Format-List Id, AdditionalProperties
```

Expected output:
```text
Id                   : 28c10230-6103-485e-b985-444c60001490
AdditionalProperties : {[@odata.type, #microsoft.graph.passwordAuthenticationMethod], ...}

Id                   : 3a9b4c7e-1d2f-4e5a-9b8c-7d6e5f4a3b2c
AdditionalProperties : {[@odata.type, #microsoft.graph.microsoftAuthenticatorAuthenticationMethod],
                        [displayName, Pixel 8], [deviceTag, SoftwareTokenActivated], ...}
```

The **Authentication details** tab of the sign-in in the Entra admin center shows the same thing per attempt: which method was used and the "MFA denied; ..." reason.

---

## Resolution

### Immediate Action

**User self-service:**
1. Wait for a new code in Microsoft Authenticator (codes rotate every 30 seconds)
2. If codes keep failing, sync the app clock: Authenticator > Settings > Sync (Android) or let the phone correct its time automatically
3. Sign in again with a fresh code or approve the push notification

**If persistent failures:**
1. User re-registers the method at `https://aka.ms/mysecurityinfo`
2. Admin can require re-registration or remove a stale method if needed

### Admin intervention

```powershell
# Remove the stale Authenticator registration (requires Authentication Administrator)
Connect-MgGraph -Scopes "UserAuthenticationMethod.ReadWrite.All"
Remove-MgUserAuthenticationMicrosoftAuthenticatorMethod `
  -UserId <affected-user> `
  -MicrosoftAuthenticatorAuthenticationMethodId <method-id>

# User must then register MFA again at aka.ms/mysecurityinfo
# Portal equivalent: Entra admin center > Users > <user> > Authentication methods > Require re-register multifactor authentication
```

⚠️ **Caution:** Removing a method takes away a security control. Only do this after verifying the user's identity, and prefer a Temporary Access Pass over leaving the account without strong authentication.

---

## Post-Incident

### Documentation

- [ ] Record incident in Cosmos DB via simulator
- [ ] Note resolution time
- [ ] Update user if recurring issue

### Prevention

- Keep Authenticator number matching on (default) so pushes are not approved by accident
- Consider passkeys (FIDO2) for sensitive accounts
- Make sure users register a second method so one broken method does not lock them out

---

## Portal Evidence

Detection evidence is captured in Cosmos DB with full event context:

| Evidence | Location |
|----------|----------|
| Incident records with detection signals | `screenshots/cosmos-incidents.png` |
| Event hub and diagnostic setting for real-time detection | `screenshots/eventhub-signin-logs.png` |
| Function app processing records | `screenshots/function-app.png` |

Each Cosmos DB record contains the `detection_signal` field with sign-in log details including `result_type`, `failure_reason`, `additional_details` and the per-step `authentication_details`.

---

## Interview Talking Point

> "When investigating MFA auth failures in Entra ID, I look for the specific pattern: error 500121 with the authentication requirement set to multi-factor, then the Authentication details step that says why MFA was denied. Entra doesn't log 'code expired' as such, so I read the pattern and corroborate it with the user's recent successful sign-ins. If they completed MFA minutes before, that's consistent with an expired code. The resolution is user self-service. I don't touch their authentication methods unless I have to, and if I do, a Temporary Access Pass beats leaving the account without MFA."

---

*Last Updated: November 2026*
