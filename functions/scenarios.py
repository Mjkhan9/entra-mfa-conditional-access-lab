"""
Synthetic Microsoft Entra sign-in records for each attack scenario.

The simulator does not fabricate incidents: it builds sign-in records in the same shape Entra
diagnostic settings produce and runs them through the detection engine, so every demo also
exercises the real detection logic. Addresses come from the documentation ranges (RFC 5737)
and accounts use the contoso.com documentation domain.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

DOMAIN = 'contoso.com'
DEMO_ADMIN = f'it.admin@{DOMAIN}'
DEMO_BREAK_GLASS = f'emergency.access@{DOMAIN}'

SCENARIOS = [
    'password_spray', 'mfa_fatigue', 'smart_lockout', 'legacy_auth_sign_in',
    'privileged_single_factor', 'break_glass_sign_in', 'policy_mismatch', 'mfa_auth_failure',
]


def record(user: str, result: str, when: datetime, ip: str, *, client: str = 'Browser',
           app: str = 'Office 365 Exchange Online', requirement: str = 'singleFactorAuthentication',
           failure: str = '', details: str = '', steps: Optional[List[Dict[str, Any]]] = None,
           ca_status: str = 'notApplied', policies: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    stamp = when.isoformat()
    return {
        'category': 'SignInLogs',
        'time': stamp,
        'resultType': result,
        'resultDescription': failure,
        'properties': {
            'id': str(uuid.uuid4()),
            'createdDateTime': stamp,
            'userPrincipalName': user,
            'ipAddress': ip,
            'clientAppUsed': client,
            'appDisplayName': app,
            'authenticationRequirement': requirement,
            'status': {'errorCode': int(result), 'failureReason': failure, 'additionalDetails': details},
            'authenticationDetails': steps or [],
            'conditionalAccessStatus': ca_status,
            'appliedConditionalAccessPolicies': policies or [],
            'correlationId': str(uuid.uuid4()),
        },
    }


def password_spray(user: str, now: datetime) -> List[Dict[str, Any]]:
    """One IP tries one common password against 8 accounts; one of them works."""
    ip = '203.0.113.77'
    targets = [f'{n}@{DOMAIN}' for n in ('a.lopez', 'b.nguyen', 'c.okafor', 'd.smith', 'e.khan', 'f.rossi', 'g.chen')]
    recs = [record(t, '50126', now + timedelta(seconds=40 * i), ip, client='Other clients',
                   failure='Invalid username or password or Invalid on-premise username or password.')
            for i, t in enumerate(targets)]
    recs.append(record(user, '0', now + timedelta(minutes=6), ip))  # the guessed password works
    recs.append(record(user, '50126', now + timedelta(minutes=5), ip, client='Other clients',
                       failure='Invalid username or password or Invalid on-premise username or password.'))
    return recs


def mfa_fatigue(user: str, now: datetime) -> List[Dict[str, Any]]:
    """Correct password, then a burst of push prompts the user denies or ignores."""
    ip = '198.51.100.23'
    details = ['MFA denied; user did not respond to mobile app notification'] * 3 + \
              ['MFA denied; user declined the authentication'] * 2
    return [record(user, '500121', now + timedelta(seconds=75 * i), ip, client='Mobile Apps and Desktop clients',
                   requirement='multiFactorAuthentication',
                   failure='Authentication failed during strong authentication request.', details=d,
                   steps=[{'authenticationStepRequirement': 'Primary authentication',
                           'authenticationMethod': 'Password', 'succeeded': True},
                          {'authenticationStepRequirement': 'Multi-factor authentication',
                           'authenticationMethod': 'Mobile app notification', 'succeeded': False,
                           'authenticationStepResultDetail': d}])
            for i, d in enumerate(details)]


def smart_lockout(user: str, now: datetime) -> List[Dict[str, Any]]:
    ip = '198.51.100.15'
    recs = [record(user, '50126', now + timedelta(seconds=5 * i), ip,
                   failure='Invalid username or password or Invalid on-premise username or password.')
            for i in range(10)]
    recs.append(record(user, '50053', now + timedelta(seconds=55), ip,
                       failure='Account is locked because user tried to sign in too many times with an incorrect '
                               'user ID or password.'))
    return recs


def legacy_auth_sign_in(user: str, now: datetime) -> List[Dict[str, Any]]:
    return [record(user, '0', now, '192.0.2.44', client='IMAP4', app='Office 365 Exchange Online')]


def privileged_single_factor(user: str, now: datetime) -> List[Dict[str, Any]]:
    return [record(DEMO_ADMIN, '0', now, '192.0.2.10', app='Azure Portal',
                   steps=[{'authenticationStepRequirement': 'Primary authentication',
                           'authenticationMethod': 'Password', 'succeeded': True}])]


def break_glass_sign_in(user: str, now: datetime) -> List[Dict[str, Any]]:
    return [record(DEMO_BREAK_GLASS, '0', now, '192.0.2.200', app='Microsoft Entra admin center',
                   requirement='multiFactorAuthentication',
                   steps=[{'authenticationStepRequirement': 'Primary authentication',
                           'authenticationMethod': 'FIDO2 security key', 'succeeded': True}])]


def policy_mismatch(user: str, now: datetime) -> List[Dict[str, Any]]:
    return [record(user, '53003', now, '192.0.2.61', app='Azure Portal', requirement='multiFactorAuthentication',
                   failure='Access has been blocked by Conditional Access policies.',
                   steps=[{'authenticationStepRequirement': 'Primary authentication',
                           'authenticationMethod': 'Password', 'succeeded': True},
                          {'authenticationStepRequirement': 'Multi-factor authentication',
                           'authenticationMethod': 'Mobile app notification', 'succeeded': True}],
                   ca_status='failure',
                   policies=[{'displayName': 'CA003 Require compliant device for Azure management',
                              'result': 'failure', 'enforcedGrantControls': ['Mfa', 'RequireCompliantDevice']}])]


def mfa_auth_failure(user: str, now: datetime) -> List[Dict[str, Any]]:
    d = 'MFA denied; invalid mobile app verification code'
    return [record(user, '500121', now, '192.0.2.33', requirement='multiFactorAuthentication',
                   failure='Authentication failed during strong authentication request.', details=d,
                   steps=[{'authenticationStepRequirement': 'Primary authentication',
                           'authenticationMethod': 'Password', 'succeeded': True},
                          {'authenticationStepRequirement': 'Multi-factor authentication',
                           'authenticationMethod': 'OATH verification code', 'succeeded': False,
                           'authenticationStepResultDetail': d}])]


BUILDERS = {name: globals()[name] for name in SCENARIOS}

# One account per scenario, so 'all' produces one incident per detection
DEFAULT_USERS = {
    'password_spray': 'h.patel', 'mfa_fatigue': 'j.miller', 'smart_lockout': 'k.davis',
    'legacy_auth_sign_in': 'l.garcia', 'privileged_single_factor': 'it.admin',
    'break_glass_sign_in': 'emergency.access', 'policy_mismatch': 'm.brown', 'mfa_auth_failure': 'n.wilson',
}


def build(scenario: str, user: Optional[str] = None) -> List[Dict[str, Any]]:
    """Sign-in records for one scenario ('all' = every scenario, each with its own account)."""
    now = datetime.now(timezone.utc)
    if scenario == 'all':
        return [r for s in SCENARIOS for r in BUILDERS[s](f'{DEFAULT_USERS[s]}@{DOMAIN}', now)]
    return BUILDERS[scenario](user or f'{DEFAULT_USERS[scenario]}@{DOMAIN}', now)
