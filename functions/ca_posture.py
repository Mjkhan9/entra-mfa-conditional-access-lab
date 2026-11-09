"""
Conditional Access posture check.

Reads the tenant's Conditional Access policies and security defaults setting (Microsoft Graph,
read-only, application permission Policy.Read.All) and reports the gaps an attacker would use:

    CA-01  No MFA baseline at all (no enabled policy and security defaults off)       CRITICAL
    CA-02  No enabled policy requires MFA for all users                               HIGH
    CA-03  Admin roles not covered by an enabled MFA policy (Microsoft's 14 roles)    HIGH
    CA-04  Legacy authentication not blocked                                          HIGH
    CA-05  Enabled policy with no emergency access (break-glass) exclusion            MEDIUM
    CA-06  "Require all" grant mixing MFA with device controls for all users          MEDIUM
    CA-07  Policy in report-only mode (not enforced)                                   LOW
    CA-08  No risk-based policy (sign-in or user risk, Entra ID P2)                    LOW
    CA-09  Device code flow not blocked                                                LOW

Run without a tenant:   python ca_posture.py --demo
Run on an export:       python ca_posture.py --file policies.json
    (export: Invoke-MgGraphRequest -Uri /v1.0/identity/conditionalAccess/policies -OutputType Json)
"""

import json
import os
import sys
from typing import Any, Dict, Iterable, List, Optional

# Roles Microsoft recommends protecting with (phishing-resistant) MFA at a minimum
PRIVILEGED_ROLES = {
    '62e90394-69f5-4237-9190-012177145e10': 'Global Administrator',
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3': 'Application Administrator',
    'c4e39bd9-1100-46d3-8c65-fb160da0071f': 'Authentication Administrator',
    'b0f54661-2d74-4c50-afa3-1ec803f12efe': 'Billing Administrator',
    '158c047a-c907-4556-b7ef-446551a6b5f7': 'Cloud Application Administrator',
    'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9': 'Conditional Access Administrator',
    '29232cdf-9323-42fd-ade2-1d097af3e4de': 'Exchange Administrator',
    '729827e3-9c14-49f7-bb1b-9608f156bbb8': 'Helpdesk Administrator',
    '966707d0-3269-4727-9be2-8c3a10f19b9d': 'Password Administrator',
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13': 'Privileged Authentication Administrator',
    'e8611ab8-c189-46e8-94e1-60213ab1f814': 'Privileged Role Administrator',
    '194ae4cb-b126-40b2-bd5b-6091b380977d': 'Security Administrator',
    'f28a1f50-f6e7-4571-818b-6a12f2af6b6c': 'SharePoint Administrator',
    'fe930be7-5e62-47db-91af-98c3a49a38b1': 'User Administrator',
}

LEARN = {
    'admins': 'https://learn.microsoft.com/entra/identity/conditional-access/policy-admin-phish-resistant-mfa',
    'managed': 'https://learn.microsoft.com/entra/identity/conditional-access/managed-policies',
    'breakglass': 'https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access',
    'defaults': 'https://learn.microsoft.com/entra/fundamentals/security-defaults',
}

SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
SEVERITY_WEIGHT = {'CRITICAL': 40, 'HIGH': 15, 'MEDIUM': 7, 'LOW': 2, 'INFO': 0}


def _c(p: Dict[str, Any]) -> Dict[str, Any]:
    return p.get('conditions') or {}


def _users(p: Dict[str, Any]) -> Dict[str, Any]:
    return _c(p).get('users') or {}


def _grants(p: Dict[str, Any]) -> set:
    return set(((p.get('grantControls') or {}).get('builtInControls')) or [])


def _requires_mfa(p: Dict[str, Any]) -> bool:
    gc = p.get('grantControls') or {}
    return 'mfa' in _grants(p) or bool(gc.get('authenticationStrength'))


def _all_apps(p: Dict[str, Any]) -> bool:
    return 'All' in ((_c(p).get('applications') or {}).get('includeApplications') or [])


def _all_users(p: Dict[str, Any]) -> bool:
    return 'All' in (_users(p).get('includeUsers') or [])


def _client_types(p: Dict[str, Any]) -> set:
    return set(_c(p).get('clientAppTypes') or ['all'])


def finding(fid: str, severity: str, title: str, detail: str, remediation: str, ref: str = '',
            policies: Optional[List[str]] = None) -> Dict[str, Any]:
    return {'id': fid, 'severity': severity, 'title': title, 'detail': detail,
            'remediation': remediation, 'reference': ref, 'policies': policies or []}


def assess(policies: Iterable[Dict[str, Any]], security_defaults_enabled: Optional[bool] = None,
           break_glass_ids: Iterable[str] = ()) -> Dict[str, Any]:
    """Evaluate Conditional Access policies (Graph v1.0 shape) and return findings plus a score."""
    policies = list(policies)
    break_glass = {b.lower() for b in break_glass_ids if b}
    enabled = [p for p in policies if p.get('state') == 'enabled']
    report_only = [p for p in policies if p.get('state') == 'enabledForReportingButNotEnforced']
    out: List[Dict[str, Any]] = []

    # CA-01 baseline
    if not enabled and security_defaults_enabled is not True:
        out.append(finding(
            'CA-01', 'CRITICAL', 'No MFA baseline',
            f'0 enabled Conditional Access policies and security defaults '
            f'{"off" if security_defaults_enabled is False else "not readable"}: nothing requires MFA.',
            'Turn on the Microsoft-managed MFA policies or create CA-02/CA-03/CA-04 equivalents '
            '(start in report-only, exclude the break-glass account).', LEARN['managed']))

    # CA-02 MFA for all users
    mfa_all = [p for p in enabled if _all_users(p) and _all_apps(p) and _requires_mfa(p)]
    if not mfa_all:
        out.append(finding(
            'CA-02', 'HIGH', 'MFA is not required for all users',
            'No enabled policy targets All users and All resources with an MFA grant.',
            'Create "Require MFA for all users" (All users, All resources, grant: require MFA or an '
            'authentication strength), excluding emergency access accounts.', LEARN['managed']))

    # CA-03 admin roles
    covered = set()
    for p in enabled:
        if not _requires_mfa(p):
            continue
        excluded = set(_users(p).get('excludeRoles') or [])
        if _all_users(p) and _all_apps(p):
            covered |= set(PRIVILEGED_ROLES) - excluded
        else:
            covered |= set(_users(p).get('includeRoles') or []) - excluded
    missing = [name for rid, name in PRIVILEGED_ROLES.items() if rid not in covered]
    if missing:
        out.append(finding(
            'CA-03', 'HIGH', f'{len(missing)} of {len(PRIVILEGED_ROLES)} admin roles have no MFA policy',
            'Not covered: ' + ', '.join(missing) + '.',
            'Add the roles to an enabled policy that requires phishing-resistant MFA (authentication strength).',
            LEARN['admins']))

    # CA-04 legacy authentication
    blocks_legacy = [p for p in enabled if 'block' in _grants(p) and _all_users(p)
                     and {'exchangeActiveSync', 'other'} <= _client_types(p)]
    if not blocks_legacy:
        staged = [p.get('displayName', '') for p in report_only
                  if 'block' in _grants(p) and {'exchangeActiveSync', 'other'} <= _client_types(p)]
        note = f' A block policy exists but is report-only: {", ".join(staged)}.' if staged else ''
        out.append(finding(
            'CA-04', 'HIGH', 'Legacy authentication is not blocked',
            'Legacy protocols (IMAP, POP, SMTP AUTH, Exchange ActiveSync basic) cannot do MFA, so they bypass '
            'every MFA policy.' + note,
            'Enforce a policy for All users, client apps Exchange ActiveSync + Other clients, grant: block.',
            LEARN['managed'], staged))

    # CA-05 break-glass exclusion
    if break_glass:
        for p in enabled:
            targets_everyone = _all_users(p) or bool(_users(p).get('includeRoles'))
            excluded = {u.lower() for u in (_users(p).get('excludeUsers') or [])}
            if targets_everyone and (_grants(p) or _requires_mfa(p)) and not break_glass <= excluded:
                out.append(finding(
                    'CA-05', 'MEDIUM', f'"{p.get("displayName")}" does not exclude the emergency access account',
                    'A misconfigured or failing control in this policy could lock every administrator out.',
                    'Exclude the break-glass account(s) from the policy and monitor their sign-ins instead '
                    '(detection: break_glass_sign_in).', LEARN['breakglass'], [p.get('displayName', '')]))
    else:
        out.append(finding(
            'CA-05', 'INFO', 'Emergency access accounts not configured for this check',
            'Set BREAK_GLASS_OBJECT_IDS to verify every policy excludes them.', '', LEARN['breakglass']))

    # CA-06 require-all grant mixing MFA with device controls
    for p in enabled:
        gc = p.get('grantControls') or {}
        device = _grants(p) & {'compliantDevice', 'domainJoinedDevice'}
        if gc.get('operator') == 'AND' and device and _requires_mfa(p) and _all_users(p):
            out.append(finding(
                'CA-06', 'MEDIUM', f'"{p.get("displayName")}" requires MFA AND a managed device for all users',
                'Users on unmanaged devices pass MFA and are still blocked (sign-in error 53003): the '
                'policy_mismatch detection fires on exactly this.',
                'Confirm "Require all the selected controls" is intended; otherwise switch to "Require one of" '
                'or scope the device requirement to admins.', '', [p.get('displayName', '')]))

    # CA-07 report-only
    for p in report_only:
        out.append(finding(
            'CA-07', 'LOW', f'"{p.get("displayName")}" is report-only',
            'The policy is evaluated and logged but not enforced.',
            'Review its sign-in impact in the Conditional Access insights workbook, then enable it.', '',
            [p.get('displayName', '')]))

    # CA-08 risk-based
    risk = [p for p in enabled if _c(p).get('signInRiskLevels') or _c(p).get('userRiskLevels')]
    if not risk:
        out.append(finding(
            'CA-08', 'LOW', 'No risk-based Conditional Access policy',
            'Sign-in risk and user risk from ID Protection are not used to require MFA or a password change.',
            'With Entra ID P2: require MFA for medium/high sign-in risk and a secure password change for high '
            'user risk.', LEARN['managed']))

    # CA-09 device code flow
    blocks_dcf = [p for p in enabled if 'block' in _grants(p) and 'deviceCodeFlow' in
                  (((_c(p).get('authenticationFlows') or {}).get('transferMethods')) or '')]
    if not blocks_dcf:
        out.append(finding(
            'CA-09', 'LOW', 'Device code flow is not blocked',
            'Device code phishing lets an attacker complete sign-in on the victim\'s behalf.',
            'Block authentication flows → device code flow for everyone who does not need it.', LEARN['managed']))

    out.sort(key=lambda f: SEVERITY_ORDER.index(f['severity']))
    counts = {s: sum(1 for f in out if f['severity'] == s) for s in SEVERITY_ORDER}
    score = max(0, 100 - sum(SEVERITY_WEIGHT[f['severity']] for f in out))
    return {
        'policies_evaluated': len(policies),
        'enabled': len(enabled),
        'report_only': len(report_only),
        'disabled': len(policies) - len(enabled) - len(report_only),
        'security_defaults_enabled': security_defaults_enabled,
        'admin_roles_covered': f'{len(PRIVILEGED_ROLES) - len(missing)}/{len(PRIVILEGED_ROLES)}',
        'score': score,
        'counts': counts,
        'findings': out,
    }


SAMPLE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'samples', 'ca-policies-sample.json')


def demo() -> Dict[str, Any]:
    with open(SAMPLE, encoding='utf-8') as f:
        data = json.load(f)
    result = assess(data['value'], data.get('securityDefaultsEnabled'), data.get('breakGlassObjectIds', []))
    result['source'] = 'demo (samples/ca-policies-sample.json)'
    return result


def live() -> Dict[str, Any]:
    """Read the tenant with the managed identity (Policy.Read.All)."""
    import graph
    policies = graph.get_all('/identity/conditionalAccess/policies')
    defaults = graph.get('/policies/identitySecurityDefaultsEnforcementPolicy').get('isEnabled')
    ids = [i.strip() for i in os.environ.get('BREAK_GLASS_OBJECT_IDS', '').split(',') if i.strip()]
    result = assess(policies, defaults, ids)
    result['source'] = 'live (Microsoft Graph)'
    return result


def render(result: Dict[str, Any]) -> str:
    lines = [f"Conditional Access posture  score {result['score']}/100  "
             f"({result['enabled']} enabled, {result['report_only']} report-only, {result['disabled']} off; "
             f"admin roles covered {result['admin_roles_covered']})", '']
    for f in result['findings']:
        lines.append(f"[{f['severity']:<8}] {f['id']}  {f['title']}")
        lines.append(f"           {f['detail']}")
        lines.append(f"           Fix: {f['remediation']}")
    return '\n'.join(lines)


if __name__ == '__main__':
    if '--file' in sys.argv:
        with open(sys.argv[sys.argv.index('--file') + 1], encoding='utf-8-sig') as fh:
            raw = json.load(fh)
        print(render(assess(raw.get('value', raw) if isinstance(raw, dict) else raw)))
    else:
        print(render(demo()))
