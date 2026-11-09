# Incident Runbook: MFA Fatigue (Push Bombing)

**Detection:** `mfa_fatigue` · **Severity:** HIGH · **MITRE ATT&CK:** T1621 Multi-Factor Authentication Request Generation  
**Auto-Remediation:** No

---

## Overview

The attacker already has the password and keeps triggering push notifications, hoping the user approves one to make them stop. Each denied or unanswered prompt is a sign-in error **500121** whose details read *MFA denied; user declined the authentication* or *user did not respond to mobile app notification*. A single prompt reported as fraud is enough on its own.

The password step **succeeded** on every one of these sign-ins, so the response always includes a password reset.

## Detection Signal

| Field | Pattern |
|---|---|
| `ResultType` | 500121 |
| `Status.additionalDetails` / authentication step detail | contains "declined", "did not respond" or "fraud" |
| `UserPrincipalName` | 3+ prompts inside 10 minutes, or one fraud report |

The engine suppresses the LOW `mfa_auth_failure` incident for any user in a fatigue incident, so the analyst sees one incident, not five. Engine: `detect_mfa_fatigue()`. Hunting query: [`queries/mfa-fatigue.kql`](../queries/mfa-fatigue.kql).

## Investigation

1. Where are the prompts coming from (`IPAddress`, location, app)? Not the user's usual device and city → attacker.
2. Did any prompt get **approved** afterwards (a `ResultType` 0 with MFA from the same IP)? That is a compromise.
3. Ask the user, through a channel other than email, whether they were signing in.
4. Check `GET /users/{id}/authentication/methods` for a method the user did not register.

## Response

| Step | Microsoft Graph | Graph PowerShell |
|---|---|---|
| Force a password change | `PATCH /users/{id}` `passwordProfile.forceChangePasswordNextSignIn` | `Update-MgUser -PasswordProfile` |
| Revoke sessions | `POST /users/{id}/revokeSignInSessions` | `Revoke-MgUserSignInSession` |
| Review registered methods | `GET /users/{id}/authentication/methods` | `Get-MgUserAuthenticationMethod` |
| Confirm number matching is on | `GET /policies/authenticationMethodsPolicy/authenticationMethodConfigurations/microsoftAuthenticator` | `Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration` |
| Confirm compromised (P2) | `POST /identityProtection/riskyUsers/confirmCompromised` | `Confirm-MgRiskyUserCompromised` |

Long-term: phishing-resistant methods (passkeys, FIDO2) for high-value accounts remove push approval entirely.

## Interview Talking Point

> "MFA fatigue tells you the password is already known, so treating it as an MFA problem misses the point. The detection groups denied or unanswered pushes per user in a short window, folds the individual 500121s into one incident, and the response starts with a password reset and session revocation, not a re-registration."

---

*Last Updated: November 2026*
