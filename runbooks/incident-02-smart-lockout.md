# Incident Runbook: Smart Lockout / Account Lockout

**Scenario:** Multiple failed sign-in attempts trigger Entra smart lockout  
**Detection:** `smart_lockout` · **Severity:** HIGH · **MITRE ATT&CK:** T1110.001 Brute Force: Password Guessing  
**Auto-Remediation:** Yes (assisted - state update after cooldown)

---

## Overview

Repeated failed sign-in attempts against the same account trigger Microsoft Entra smart lockout. The service returns sign-in error **50053** (*IdsLocked*) until the lockout clears. This is a security control working as intended, but it requires operational response.

Common causes:
- User repeatedly entering a wrong password or MFA code
- Automated tool or mobile mail client with a stale password
- Potential brute force or password spray attempt (investigate source IP)

Precision note: smart lockout counts bad **passwords** (it tracks the last three bad password hashes, so the same wrong password re-entered does not count again). Default threshold is 10 attempts, default lockout 60 seconds, increasing on repeat. Wrong MFA codes are throttled separately ("MFA denied; entered incorrect code too many times"). The scenario models the burst of failures and the lockout event that follows.

---

## Detection Signal

### Pattern Definition

- 5+ failed sign-in events (`ResultType` 50126 or 500121)
- Within 60-second rolling window
- Same `UserPrincipalName`
- Same `IPAddress`
- Followed by `ResultType` 50053 (lockout engaged)

### Sign-in Log Record Pattern

```json
{
  "category": "SignInLogs",
  "resultType": "50053",
  "resultDescription": "The account is locked because the user tried to sign in too many times with an incorrect user ID or password.",
  "properties": {
    "userPrincipalName": "<affected-user>",
    "ipAddress": "<user-ip>",
    "createdDateTime": "<timestamp>",
    "status": {
      "errorCode": 50053,
      "failureReason": "The account is locked because the user tried to sign in too many times with an incorrect user ID or password."
    }
  }
}
```

### KQL Query (Log Analytics)

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType in ("50126", "500121", "50053")
| summarize failure_count = count(), lockouts = countif(ResultType == "50053")
          by UserPrincipalName, IPAddress, bin(TimeGenerated, 5m)
| where failure_count >= 5
| order by failure_count desc
```

---

## Investigation Steps

### Step 1: Quantify the failure pattern

```bash
# Count failures by user and IP in the last hour
az monitor log-analytics query \
  --workspace "<workspace-id>" \
  --timespan PT1H \
  --analytics-query 'SigninLogs
    | where ResultType in ("50126", "500121", "50053")
    | summarize failures = count() by UserPrincipalName, IPAddress
    | where failures >= 3
    | order by failures desc'
```

### Step 2: Analyze source IP

Determine if this is legitimate user error or a potential attack.

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where UserPrincipalName == "<affected-user>"
| where ResultType != "0"
| project TimeGenerated, IPAddress, UserAgent, AppDisplayName, ClientAppUsed,
          Country = tostring(LocationDetails.countryOrRegion), RiskLevelDuringSignIn
| order by TimeGenerated desc
| take 20
```

Check:
- [ ] Is the source IP in a named location (corporate range)?
- [ ] Is the user agent / client app consistent with the user's device?
- [ ] Geographic location reasonable?
- [ ] Does Entra ID Protection show sign-in risk for the attempts?

### Step 3: Check for successful sign-ins after the failures

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where UserPrincipalName == "<affected-user>"
| where ResultType == "0"
| project TimeGenerated, IPAddress, AppDisplayName, AuthenticationRequirement
| order by TimeGenerated desc
| take 5
```

---

## Resolution

### Assisted Remediation (Automated)

The responder handles this scenario. It runs at the start of every `simulate` / `detect` call and on `POST /api/respond`, so no timer keeps the app running while idle:

1. Detects incident is past cooldown period (5 minutes default)
2. Updates incident status in Cosmos DB to `RESOLVED`
3. Writes a resolution record to the `resolutions` container; its creation fires the `incident-resolved` metric alert -> action group email
4. Logs resolution time for metrics

**What it does NOT do:**
- Does not modify the Entra user or their authentication methods
- Does not unlock the account (smart lockout clears on its own; the user can also reset the counter with self-service password reset)
- Does not reset passwords or revoke sessions

### Manual Steps (If Automated Response Fails)

```bash
# Verify incident status in Cosmos DB (Data Explorer query)
SELECT c.incident_id, c.status, c.created_at, c.resolved_at, c.resolution_time_seconds
FROM c WHERE c.incident_id = "<incident-id>"

# Check responder logs
az webapp log tail --resource-group <resource-group> --name <function-app-name>
```

```kusto
// Or from Application Insights
traces
| where operation_Name == "respond"
| where timestamp > ago(30m)
| order by timestamp desc
```

### User Communication

```
Subject: Sign-in Lockout Resolved

Your account was temporarily locked after multiple failed sign-in attempts.
The lockout has cleared. Please wait for a fresh code in Microsoft Authenticator
before signing in again.

If you did not attempt these sign-ins, please contact IT Security immediately.
```

---

## Escalation Criteria

Escalate to Security team if:
- [ ] Source IP is from unexpected geography
- [ ] Multiple users affected simultaneously (password spray pattern)
- [ ] Entra ID Protection flags the sign-ins as risky
- [ ] User denies making the sign-in attempts

---

## Post-Incident

### Metrics Captured

| Metric | Value |
|--------|-------|
| Incident ID | `<from-cosmos-db>` |
| Created At | `<timestamp>` |
| Resolved At | `<timestamp>` |
| Resolution Time | `<seconds>` |
| Remediation Type | `assisted_auto` |

### Workbook Update

Resolution time is emitted to Application Insights (`ResolutionTimeSeconds` event); resolved incidents appear in the workbook's severity tile under "Resolved".

---

## Portal Evidence

| Evidence | Location |
|----------|----------|
| Incident records (including RESOLVED status) | `screenshots/cosmos-incidents.png` |
| Action group and alert rules | `screenshots/alert-rules.png` |
| Workbook with resolution metrics | `screenshots/workbook.png` |

The Cosmos DB container shows both OPEN and RESOLVED incidents, with `resolution_time_seconds` populated for resolved smart lockout events.

---

## Interview Talking Point

> "For smart lockout, I implemented assisted remediation rather than full automation. After the cooldown period, the system updates the incident state, sends a notification, and logs the resolution time, but it doesn't touch the user object. That's intentional. Smart lockout clears on its own, and in production you'd need safeguards around blast radius and remediation loops before doing anything to accounts. I wanted to show the workflow without overclaiming capabilities."

---

*Last Updated: November 2026*
