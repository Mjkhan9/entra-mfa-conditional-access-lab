"""
Identity threat detections over Microsoft Entra sign-in logs.

Pure Python, no Azure imports: the same engine runs inside the function app (real sign-ins
pulled from Log Analytics, or simulator records) and in the tests.

Input: sign-in records in the diagnostic-settings shape
    {"category": "SignInLogs", "time": ..., "resultType": "50126",
     "properties": {"id", "userPrincipalName", "ipAddress", "clientAppUsed", "status",
                    "authenticationRequirement", "authenticationDetails",
                    "conditionalAccessStatus", "appliedConditionalAccessPolicies", ...}}
Output: incident dicts (see make_incident), one per detected attack or misconfiguration.

Detections (MITRE ATT&CK where an attack technique applies):
    password_spray            T1110.003  one IP, many accounts, bad passwords (50126)
    mfa_fatigue               T1621      repeated push denials / no-responses for one user (500121)
    smart_lockout             T1110.001  account locked after repeated failures (50053)
    legacy_auth_sign_in       T1078.004  successful sign-in over a legacy protocol (no MFA possible)
    privileged_single_factor  T1078.004  admin role holder signed in with password only
    break_glass_sign_in       T1078.004  emergency access account used (always investigate)
    policy_mismatch           -          MFA passed, Conditional Access still blocked (grant-control design)
    mfa_auth_failure          -          single MFA failure that is not part of a fatigue burst
"""

import hashlib
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set

# Microsoft Entra sign-in error codes (ResultType)
SUCCESS_CODES = {'0'}
BAD_PASSWORD_CODES = {'50126'}                    # invalid username or password
MFA_FAILURE_CODES = {'500121'}                    # strong authentication request failed
SMART_LOCKOUT_CODES = {'50053'}                   # IdsLocked
CA_BLOCK_CODES = {'53003', '53000', '53001'}      # Conditional Access denied the grant

# Modern clients; anything else in clientAppUsed is a legacy protocol (IMAP, POP, SMTP AUTH, EAS, ...)
MODERN_CLIENTS = {'Browser', 'Mobile Apps and Desktop clients'}

# Push-style MFA denials that make up an MFA fatigue (push bombing) burst
FATIGUE_MARKERS = ('declined', 'did not respond', 'not respond', 'reported fraud', 'fraud')

PASSWORD_SPRAY_MIN_USERS = 5        # distinct accounts from one IP
PASSWORD_SPRAY_WINDOW_S = 30 * 60
MFA_FATIGUE_MIN_PROMPTS = 3         # denied / unanswered prompts for one user
MFA_FATIGUE_WINDOW_S = 10 * 60

WATCHED_CODES = SUCCESS_CODES | BAD_PASSWORD_CODES | MFA_FAILURE_CODES | SMART_LOCKOUT_CODES | CA_BLOCK_CODES

MITRE = {
    'password_spray': ('Credential Access', 'T1110.003', 'Brute Force: Password Spraying'),
    'mfa_fatigue': ('Credential Access', 'T1621', 'Multi-Factor Authentication Request Generation'),
    'smart_lockout': ('Credential Access', 'T1110.001', 'Brute Force: Password Guessing'),
    'legacy_auth_sign_in': ('Defense Evasion / Initial Access', 'T1078.004', 'Valid Accounts: Cloud Accounts'),
    'privileged_single_factor': ('Initial Access', 'T1078.004', 'Valid Accounts: Cloud Accounts'),
    'break_glass_sign_in': ('Initial Access', 'T1078.004', 'Valid Accounts: Cloud Accounts'),
}

DETECTIONS = [
    'password_spray', 'mfa_fatigue', 'smart_lockout', 'legacy_auth_sign_in',
    'privileged_single_factor', 'break_glass_sign_in', 'policy_mismatch', 'mfa_auth_failure',
]

ID_PREFIX = {
    'password_spray': 'SPRAY', 'mfa_fatigue': 'FATIGUE', 'smart_lockout': 'LOCKOUT',
    'legacy_auth_sign_in': 'LEGACY', 'privileged_single_factor': 'PRIV-1FA',
    'break_glass_sign_in': 'BREAKGLASS', 'policy_mismatch': 'POLICY', 'mfa_auth_failure': 'MFA-AUTH',
}


@dataclass
class Context:
    """What the engine needs to know about the tenant (lower-cased UPNs)."""
    privileged_upns: Set[str] = field(default_factory=set)
    break_glass_upns: Set[str] = field(default_factory=set)
    environment: str = 'dev'
    ttl_seconds: int = 7 * 24 * 3600
    run_salt: str = ''      # simulator runs set a random salt so repeated demos get new incident IDs


# ---------------------------------------------------------------- record helpers

def props(r: Dict[str, Any]) -> Dict[str, Any]:
    return r.get('properties') or {}


def result_type(r: Dict[str, Any]) -> str:
    status = props(r).get('status') or {}
    return str(r.get('resultType') or status.get('errorCode') or '0')


def upn(r: Dict[str, Any]) -> str:
    return str(props(r).get('userPrincipalName') or r.get('identity') or 'unknown').lower()


def ip(r: Dict[str, Any]) -> str:
    return str(props(r).get('ipAddress') or r.get('callerIpAddress') or 'unknown')


def record_id(r: Dict[str, Any]) -> str:
    return str(props(r).get('id') or '')


def event_time(r: Dict[str, Any]) -> float:
    raw = r.get('time') or props(r).get('createdDateTime')
    if not raw:
        return time.time()
    try:
        return datetime.fromisoformat(str(raw).replace('Z', '+00:00')).timestamp()
    except ValueError:
        return time.time()


def details_text(r: Dict[str, Any]) -> str:
    """Status and authentication-step details, lower-cased, for marker matching."""
    p = props(r)
    status = p.get('status') or {}
    parts = [str(status.get('additionalDetails', '')), str(status.get('failureReason', ''))]
    for step in p.get('authenticationDetails') or []:
        parts.append(str(step.get('authenticationStepResultDetail', '')))
    return ' '.join(parts).lower()


def mfa_was_satisfied(r: Dict[str, Any]) -> bool:
    p = props(r)
    steps = p.get('authenticationDetails') or []
    if steps:
        return any(s.get('succeeded') and str(s.get('authenticationStepRequirement', '')).lower().startswith('multi')
                   for s in steps)
    return p.get('authenticationRequirement') == 'multiFactorAuthentication'


def is_legacy_client(r: Dict[str, Any]) -> bool:
    client = props(r).get('clientAppUsed')
    return bool(client) and client not in MODERN_CLIENTS


def is_signin_record(r: Any) -> bool:
    return isinstance(r, dict) and r.get('category') == 'SignInLogs' and isinstance(r.get('properties'), dict)


# ---------------------------------------------------------------- incident factory

def stable_id(prefix: str, *key: Any) -> str:
    raw = '|'.join(str(k) for k in key)
    return f"{prefix}-{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:8].upper()}"


def bucket(ts: float, size_s: int) -> int:
    return int(ts // size_s) * size_s


def make_incident(detection: str, key: Iterable[Any], severity: str, records: List[Dict[str, Any]],
                  description: str, recommended_action: str, ctx: Context,
                  extra_signal: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """One incident document (Cosmos DB id = incident_id, partition key = scenario)."""
    incident_id = stable_id(ID_PREFIX[detection], ctx.run_salt, detection, *key)
    times = sorted(event_time(r) for r in records)
    users = sorted({upn(r) for r in records})
    ips = sorted({ip(r) for r in records})
    first = records[0]
    tactic, technique_id, technique = MITRE.get(detection, ('', '', ''))
    now = int(time.time())
    return {
        'id': incident_id,
        'incident_id': incident_id,
        'scenario': detection,                       # Cosmos DB partition key
        'severity': severity,
        'status': 'OPEN',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'created_at': now,
        'user': users[0] if len(users) == 1 else f'{len(users)} accounts',
        'users': users[:50],
        'source_ip': ips[0] if len(ips) == 1 else f'{len(ips)} addresses',
        'ips': ips[:50],
        'mitre': {'tactic': tactic, 'technique_id': technique_id, 'technique': technique} if technique_id else None,
        'description': description,
        'recommended_action': recommended_action,
        'evidence': {
            'sign_in_count': len(records),
            'first_seen': datetime.fromtimestamp(times[0], timezone.utc).isoformat(),
            'last_seen': datetime.fromtimestamp(times[-1], timezone.utc).isoformat(),
            'result_types': sorted({result_type(r) for r in records}),
            'sign_in_ids': [record_id(r) for r in records if record_id(r)][:20],
        },
        'detection_signal': {
            'result_type': result_type(first),
            'failure_reason': (props(first).get('status') or {}).get('failureReason', ''),
            'additional_details': (props(first).get('status') or {}).get('additionalDetails', ''),
            'client_app': props(first).get('clientAppUsed', ''),
            'app': props(first).get('appDisplayName', ''),
            'authentication_requirement': props(first).get('authenticationRequirement', ''),
            **(extra_signal or {}),
        },
        'environment': ctx.environment,
        'ttl': ctx.ttl_seconds,
    }


# ---------------------------------------------------------------- detections

def detect_password_spray(records: List[Dict[str, Any]], ctx: Context) -> List[Dict[str, Any]]:
    """One source IP failing passwords across many accounts inside the window."""
    out = []
    failures = defaultdict(list)
    for r in records:
        if result_type(r) in BAD_PASSWORD_CODES:
            failures[ip(r)].append(r)
    for source, recs in failures.items():
        recs.sort(key=event_time)
        start = event_time(recs[0])
        in_window = [r for r in recs if event_time(r) - start <= PASSWORD_SPRAY_WINDOW_S]
        accounts = {upn(r) for r in in_window}
        if len(accounts) < PASSWORD_SPRAY_MIN_USERS:
            continue
        # Escalate when the same IP also got a successful sign-in for one of the sprayed accounts
        hits = [r for r in records if ip(r) == source and result_type(r) in SUCCESS_CODES and upn(r) in accounts]
        severity = 'CRITICAL' if hits else 'HIGH'
        desc = (f'Password spray from {source}: {len(in_window)} bad-password sign-ins (50126) across '
                f'{len(accounts)} accounts in {int((event_time(in_window[-1]) - start) / 60) + 1} min')
        if hits:
            desc += f'; {len({upn(r) for r in hits})} sprayed account(s) then signed in successfully from the same IP'
        out.append(make_incident(
            'password_spray', [source, bucket(start, PASSWORD_SPRAY_WINDOW_S)], severity, in_window + hits, desc,
            'Block the source IP with a named location, confirm compromised accounts, '
            'reset and revoke sessions for any account that signed in',
            ctx, {'accounts_targeted': len(accounts),
                  'compromised_accounts': sorted({upn(r) for r in hits})}))
    return out


def detect_mfa_fatigue(records: List[Dict[str, Any]], ctx: Context) -> List[Dict[str, Any]]:
    """Repeated push denials / unanswered prompts for one user: someone holds the password."""
    out = []
    pushes = defaultdict(list)
    for r in records:
        if result_type(r) in MFA_FAILURE_CODES and any(m in details_text(r) for m in FATIGUE_MARKERS):
            pushes[upn(r)].append(r)
    for user, recs in pushes.items():
        recs.sort(key=event_time)
        start = event_time(recs[0])
        in_window = [r for r in recs if event_time(r) - start <= MFA_FATIGUE_WINDOW_S]
        fraud = any('fraud' in details_text(r) for r in in_window)
        if len(in_window) < MFA_FATIGUE_MIN_PROMPTS and not fraud:
            continue
        minutes = int((event_time(in_window[-1]) - start) / 60) + 1
        desc = (f'MFA fatigue against {user}: {len(in_window)} push prompts denied or unanswered in '
                f'{minutes} min from {len({ip(r) for r in in_window})} IP(s); '
                'the password is likely known to the attacker')
        if fraud:
            desc += '; the user reported the prompt as fraud'
        out.append(make_incident(
            'mfa_fatigue', [user, bucket(start, MFA_FATIGUE_WINDOW_S)], 'HIGH', in_window, desc,
            'Reset the password, revoke sessions, confirm number matching is enforced in the Authenticator policy',
            ctx, {'prompts': len(in_window), 'user_reported_fraud': fraud}))
    return out


def detect_smart_lockout(records: List[Dict[str, Any]], ctx: Context) -> List[Dict[str, Any]]:
    out = []
    by_user = defaultdict(list)
    for r in records:
        if result_type(r) in SMART_LOCKOUT_CODES:
            by_user[upn(r)].append(r)
    for user, recs in by_user.items():
        prior = [r for r in records if upn(r) == user and result_type(r) in BAD_PASSWORD_CODES]
        inc = make_incident(
            'smart_lockout', [record_id(recs[0]) or user, bucket(event_time(recs[0]), 300)], 'HIGH', prior + recs,
            f'Smart lockout engaged for {user} (50053) after {len(prior) or "repeated"} failed password attempts',
            'Wait for the lockout to clear; if the attempts were not the user, treat as password guessing and reset',
            ctx, {'failed_attempts_before_lockout': len(prior)})
        inc.update({'auto_remediation': True, 'remediation_type': 'assisted', 'cooldown_seconds': 300})
        out.append(inc)
    return out


def detect_legacy_auth(records: List[Dict[str, Any]], ctx: Context) -> List[Dict[str, Any]]:
    out = []
    groups = defaultdict(list)
    for r in records:
        if result_type(r) in SUCCESS_CODES and is_legacy_client(r):
            groups[(upn(r), props(r).get('clientAppUsed'))].append(r)
    for (user, client), recs in groups.items():
        out.append(make_incident(
            'legacy_auth_sign_in', [record_id(recs[0]) or user, client], 'HIGH', recs,
            f'{user} signed in successfully over a legacy protocol ({client}); legacy authentication cannot do MFA',
            'Block legacy authentication with Conditional Access; move the client to modern authentication',
            ctx))
    return out


def detect_privileged_single_factor(records: List[Dict[str, Any]], ctx: Context) -> List[Dict[str, Any]]:
    out = []
    for r in records:
        if (result_type(r) in SUCCESS_CODES and upn(r) in ctx.privileged_upns
                and props(r).get('authenticationRequirement') == 'singleFactorAuthentication'):
            out.append(make_incident(
                'privileged_single_factor', [record_id(r) or upn(r)], 'HIGH', [r],
                f'Admin role holder {upn(r)} signed in to {props(r).get("appDisplayName", "an app")} '
                'with a password only',
                'Require phishing-resistant MFA for every admin role with Conditional Access; '
                'confirm the sign-in was the admin',
                ctx))
    return out


def detect_break_glass(records: List[Dict[str, Any]], ctx: Context) -> List[Dict[str, Any]]:
    out = []
    for r in records:
        if upn(r) in ctx.break_glass_upns:
            ok = result_type(r) in SUCCESS_CODES
            out.append(make_incident(
                'break_glass_sign_in', [record_id(r) or upn(r), bucket(event_time(r), 60)], 'CRITICAL', [r],
                f'Emergency access account {upn(r)} {"signed in" if ok else "attempted a sign-in"} from {ip(r)}',
                'Confirm with the owner of the emergency procedure; '
                'if unplanned, treat as compromise and rotate the credential',
                ctx, {'succeeded': ok}))
    return out


def detect_policy_mismatch(records: List[Dict[str, Any]], ctx: Context) -> List[Dict[str, Any]]:
    out = []
    for r in records:
        if result_type(r) in CA_BLOCK_CODES and mfa_was_satisfied(r):
            failed = [{'name': p.get('displayName', ''), 'grant_controls': p.get('enforcedGrantControls', [])}
                      for p in props(r).get('appliedConditionalAccessPolicies') or [] if p.get('result') == 'failure']
            out.append(make_incident(
                'policy_mismatch', [record_id(r) or upn(r)], 'MEDIUM', [r],
                f'{upn(r)} completed MFA but Conditional Access still blocked access ({result_type(r)})',
                'Review the grant controls (require all vs require one) with the What If tool',
                ctx, {'failed_policies': failed,
                      'conditional_access_status': props(r).get('conditionalAccessStatus', '')}))
    return out


def detect_mfa_failures(records: List[Dict[str, Any]], ctx: Context, fatigue_users: Set[str]) -> List[Dict[str, Any]]:
    out = []
    by_user = defaultdict(list)
    for r in records:
        if result_type(r) in MFA_FAILURE_CODES and upn(r) not in fatigue_users:
            by_user[upn(r)].append(r)
    for user, recs in by_user.items():
        out.append(make_incident(
            'mfa_auth_failure', [record_id(recs[0]) or user], 'LOW', recs,
            f'MFA failed for {user} ({len(recs)}x 500121), consistent with an expired or mistyped code',
            'User signs in again with a fresh code; re-register the method only if it keeps failing',
            ctx))
    return out


def evaluate(records: Iterable[Dict[str, Any]], ctx: Optional[Context] = None) -> List[Dict[str, Any]]:
    """Run every detection over a batch of sign-in records."""
    ctx = ctx or Context()
    recs = [r for r in records if is_signin_record(r)]
    fatigue = detect_mfa_fatigue(recs, ctx)
    fatigue_users = {u for inc in fatigue for u in inc['users']}
    return (detect_password_spray(recs, ctx) + fatigue + detect_smart_lockout(recs, ctx)
            + detect_legacy_auth(recs, ctx) + detect_privileged_single_factor(recs, ctx)
            + detect_break_glass(recs, ctx) + detect_policy_mismatch(recs, ctx)
            + detect_mfa_failures(recs, ctx, fatigue_users))
