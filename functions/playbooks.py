"""
Response playbooks: what an IAM analyst does for each detection.

Every step is a recommendation with the exact Microsoft Graph call and Graph PowerShell cmdlet.
Nothing here is executed by the function app: containment actions on identities (revoking sessions,
disabling accounts, resetting credentials) stay a human decision. The only automated response in this
project is the smart lockout responder, which updates incident state and never touches the account.
"""

from typing import Any, Dict, List

TRIAGE = {
    'step': 'Scope the sign-ins',
    'why': 'Confirm who, from where, which app and whether any attempt succeeded before acting',
    'graph': "GET /auditLogs/signIns?$filter=userPrincipalName eq '{user}'&$top=50",
    'powershell': "Get-MgAuditLogSignIn -Filter \"userPrincipalName eq '{user}'\" -Top 50",
}

REVOKE = {
    'step': 'Revoke refresh tokens and sessions',
    'why': 'Forces re-authentication everywhere; stolen tokens stop working',
    'graph': 'POST /users/{user}/revokeSignInSessions',
    'powershell': 'Revoke-MgUserSignInSession -UserId {user}',
}

FORCE_PASSWORD_CHANGE = {
    'step': 'Force a password change at next sign-in',
    'why': 'The password is known to the attacker',
    'graph': 'PATCH /users/{user}  {"passwordProfile": {"forceChangePasswordNextSignIn": true}}',
    'powershell': 'Update-MgUser -UserId {user} -PasswordProfile @{ForceChangePasswordNextSignIn = $true}',
}

CONFIRM_COMPROMISED = {
    'step': 'Mark the user as compromised in ID Protection (Entra ID P2)',
    'why': 'Raises user risk to high so risk-based Conditional Access applies and the signal trains detections',
    'graph': 'POST /identityProtection/riskyUsers/confirmCompromised  {"userIds": ["{user-object-id}"]}',
    'powershell': 'Confirm-MgRiskyUserCompromised -UserIds {user-object-id}',
}

REVIEW_METHODS = {
    'step': 'Review registered authentication methods',
    'why': 'An attacker who got in may have registered their own phone or passkey',
    'graph': 'GET /users/{user}/authentication/methods',
    'powershell': 'Get-MgUserAuthenticationMethod -UserId {user}',
}

PLAYBOOKS: Dict[str, List[Dict[str, Any]]] = {
    'password_spray': [
        TRIAGE,
        {'step': 'Block the source IP range with a named location and a block policy',
         'why': 'Stops the spray while accounts are checked',
         'graph': 'POST /identity/conditionalAccess/namedLocations  '
                  '{"@odata.type": "#microsoft.graph.ipNamedLocation", ...}',
         'powershell': 'New-MgIdentityConditionalAccessNamedLocation -BodyParameter $ipRange'},
        {'step': 'For every sprayed account that signed in: reset, revoke, confirm compromised',
         'why': 'A spray that hit is an account takeover',
         'graph': 'see FORCE_PASSWORD_CHANGE, REVOKE, CONFIRM_COMPROMISED',
         'powershell': 'see the three steps below'},
        FORCE_PASSWORD_CHANGE, REVOKE, CONFIRM_COMPROMISED,
        {'step': 'Close the gap: block legacy authentication, require MFA for all users',
         'why': 'Most spray traffic uses legacy protocols that cannot do MFA',
         'graph': 'GET /identity/conditionalAccess/policies  (run the CA posture check)',
         'powershell': 'Get-MgIdentityConditionalAccessPolicy'},
    ],
    'mfa_fatigue': [
        TRIAGE,
        FORCE_PASSWORD_CHANGE, REVOKE, REVIEW_METHODS,
        {'step': 'Confirm number matching and additional context are on for Microsoft Authenticator',
         'why': 'Number matching defeats blind push approval',
         'graph': 'GET /policies/authenticationMethodsPolicy/authenticationMethodConfigurations/microsoftAuthenticator',
         'powershell': 'Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration '
                       '-AuthenticationMethodConfigurationId MicrosoftAuthenticator'},
        CONFIRM_COMPROMISED,
    ],
    'smart_lockout': [
        TRIAGE,
        {'step': 'Let the lockout expire (assisted: the responder resolves the incident after the cooldown)',
         'why': 'Smart lockout clears itself; unlocking early helps an attacker',
         'graph': 'none - no account change', 'powershell': 'none'},
        {'step': 'If the failures were not the user: force a password change and check other accounts from that IP',
         'why': 'Lockout means someone is guessing',
         'graph': FORCE_PASSWORD_CHANGE['graph'], 'powershell': FORCE_PASSWORD_CHANGE['powershell']},
    ],
    'legacy_auth_sign_in': [
        TRIAGE,
        {'step': 'Find the client and move it to modern authentication',
         'why': 'Legacy protocols (IMAP, POP, SMTP AUTH, EAS basic) cannot do MFA',
         'graph': "GET /auditLogs/signIns?$filter=clientAppUsed eq '{client}'",
         'powershell': "Get-MgAuditLogSignIn -Filter \"clientAppUsed eq '{client}'\""},
        {'step': 'Enforce the Block legacy authentication Conditional Access policy',
         'why': 'Closes the MFA bypass for every account',
         'graph': 'PATCH /identity/conditionalAccess/policies/{id}  {"state": "enabled"}',
         'powershell': 'Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId {id} -State enabled'},
        REVOKE,
    ],
    'privileged_single_factor': [
        TRIAGE,
        {'step': 'Confirm with the admin that the sign-in was theirs',
         'why': 'A password-only admin sign-in is the highest-value takeover path',
         'graph': 'GET /roleManagement/directory/roleAssignments?$filter=principalId eq \'{user-object-id}\'',
         'powershell': 'Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq \'{user-object-id}\'"'},
        {'step': 'Require phishing-resistant MFA for all 14 admin roles; prefer PIM eligible assignments',
         'why': 'No standing admin should be reachable with a password',
         'graph': 'GET /identity/conditionalAccess/policies  (CA posture check CA-03)',
         'powershell': 'Get-MgIdentityConditionalAccessPolicy'},
        REVOKE,
    ],
    'break_glass_sign_in': [
        {'step': 'Confirm the sign-in matches a declared emergency',
         'why': 'Emergency access accounts are never used day to day',
         'graph': TRIAGE['graph'], 'powershell': TRIAGE['powershell']},
        {'step': 'If unplanned: rotate the credential (or the FIDO2 key) and revoke sessions',
         'why': 'The account bypasses Conditional Access by design',
         'graph': REVOKE['graph'], 'powershell': REVOKE['powershell']},
        {'step': 'Review directory audit logs for changes made by the account',
         'why': 'It holds Global Administrator',
         'graph': "GET /auditLogs/directoryAudits?$filter=initiatedBy/user/userPrincipalName eq '{user}'",
         'powershell': "Get-MgAuditLogDirectoryAudit -Filter \"initiatedBy/user/userPrincipalName eq '{user}'\""},
    ],
    'policy_mismatch': [
        {'step': 'Run What If for the user, app and device',
         'why': 'Shows which grant control failed after MFA succeeded',
         'graph': 'GET /identity/conditionalAccess/policies/{id}',
         'powershell': 'Get-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId {id}'},
        {'step': 'Fix the operator (require one of / require all) or the device state; test in Report-only first',
         'why': 'Design error, not an attack',
         'graph': 'PATCH /identity/conditionalAccess/policies/{id}  {"state": "enabledForReportingButNotEnforced"}',
         'powershell': 'Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId {id} '
                       '-State enabledForReportingButNotEnforced'},
    ],
    'mfa_auth_failure': [
        TRIAGE,
        {'step': 'User signs in again with a fresh code; re-register the method only if it keeps failing',
         'why': 'A single failure is almost always an expired or mistyped code',
         'graph': REVIEW_METHODS['graph'], 'powershell': REVIEW_METHODS['powershell']},
    ],
}


def for_incident(incident: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Playbook steps for an incident, with the user filled in. automated is always False."""
    user = incident.get('user', '{user}')
    client = (incident.get('detection_signal') or {}).get('client_app', '{client}')
    steps = []
    for s in PLAYBOOKS.get(incident.get('scenario', ''), []):
        steps.append({k: (v.replace('{user}', user).replace('{client}', client) if isinstance(v, str) else v)
                      for k, v in s.items()} | {'automated': False})
    return steps
