import copy

import ca_posture

ALL_ROLES = list(ca_posture.PRIVILEGED_ROLES)
BG = 'bg-object-id'


def policy(name, state='enabled', users=None, roles=None, exclude=None, apps=None, grants=None, operator='OR',
           clients=None, **conditions):
    return {
        'displayName': name, 'state': state,
        'conditions': {
            'clientAppTypes': clients or ['all'],
            'applications': {'includeApplications': apps or ['All']},
            'users': {'includeUsers': users or [], 'includeRoles': roles or [], 'excludeUsers': exclude or []},
            **conditions,
        },
        'grantControls': {'operator': operator, 'builtInControls': grants or ['mfa']},
    }


HARDENED = [
    policy('MFA all users', users=['All'], exclude=[BG]),
    policy('MFA admins', roles=ALL_ROLES, exclude=[BG]),
    policy('Block legacy', users=['All'], exclude=[BG], grants=['block'], clients=['exchangeActiveSync', 'other']),
    policy('Risky sign-ins', users=['All'], exclude=[BG], signInRiskLevels=['high', 'medium']),
    policy('Block device code', users=['All'], exclude=[BG], grants=['block'],
           authenticationFlows={'transferMethods': 'deviceCodeFlow'}),
]


def ids(result):
    return sorted(f['id'] for f in result['findings'])


def test_empty_tenant_without_security_defaults_is_critical():
    r = ca_posture.assess([], security_defaults_enabled=False, break_glass_ids=[BG])
    assert r['findings'][0]['id'] == 'CA-01' and r['findings'][0]['severity'] == 'CRITICAL'
    assert r['admin_roles_covered'] == '0/14'


def test_security_defaults_on_removes_baseline_finding():
    r = ca_posture.assess([], security_defaults_enabled=True, break_glass_ids=[BG])
    assert 'CA-01' not in ids(r)


def test_hardened_tenant_has_no_findings():
    r = ca_posture.assess(HARDENED, False, [BG])
    assert r['findings'] == [] and r['score'] == 100 and r['admin_roles_covered'] == '14/14'


def test_report_only_legacy_block_counts_as_not_blocked():
    p = copy.deepcopy(HARDENED)
    p[2]['state'] = 'enabledForReportingButNotEnforced'
    r = ca_posture.assess(p, False, [BG])
    assert ids(r) == ['CA-04', 'CA-07']
    assert r['findings'][0]['policies'] == ['Block legacy']


def test_missing_admin_roles_are_named():
    p = copy.deepcopy(HARDENED)
    p[0]['state'] = 'disabled'
    p[3]['state'] = 'disabled'   # the risk policy (All users + MFA) would cover every role too
    p[1]['conditions']['users']['includeRoles'] = ALL_ROLES[:10]
    r = ca_posture.assess(p, False, [BG])
    ca03 = next(f for f in r['findings'] if f['id'] == 'CA-03')
    assert ca03['title'].startswith('4 of 14')
    assert 'Privileged Role Administrator' in ca03['detail']


def test_excluded_role_is_not_covered():
    p = copy.deepcopy(HARDENED)
    p[0]['conditions']['users']['excludeRoles'] = ['62e90394-69f5-4237-9190-012177145e10']
    p[1]['state'] = 'disabled'
    p[3]['state'] = 'disabled'
    ca03 = next(f for f in ca_posture.assess(p, False, [BG])['findings'] if f['id'] == 'CA-03')
    assert 'Global Administrator' in ca03['detail']


def test_policy_without_break_glass_exclusion():
    p = copy.deepcopy(HARDENED)
    p[0]['conditions']['users']['excludeUsers'] = []
    r = ca_posture.assess(p, False, [BG])
    assert ids(r) == ['CA-05'] and r['findings'][0]['policies'] == ['MFA all users']


def test_require_all_mfa_and_device_is_flagged():
    p = copy.deepcopy(HARDENED) + [policy('Device + MFA', users=['All'], exclude=[BG],
                                          grants=['mfa', 'compliantDevice'], operator='AND')]
    assert ids(ca_posture.assess(p, False, [BG])) == ['CA-06']


def test_demo_sample_findings():
    r = ca_posture.demo()
    assert ids(r) == ['CA-02', 'CA-03', 'CA-04', 'CA-05', 'CA-06', 'CA-07', 'CA-08', 'CA-09']
    assert r['admin_roles_covered'] == '8/14'
