from datetime import datetime, timedelta, timezone

import pytest

import detections
import scenarios
from simulator import demo_context

NOW = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)


def run(records):
    return detections.evaluate(records, demo_context(detections.Context()))


def kinds(incidents):
    return sorted(i['scenario'] for i in incidents)


@pytest.mark.parametrize('scenario', scenarios.SCENARIOS)
def test_each_scenario_raises_exactly_its_detection(scenario):
    incidents = run(scenarios.build(scenario))
    assert kinds(incidents) == [scenario]


def test_all_scenarios_together_one_incident_each():
    assert kinds(run(scenarios.build('all'))) == sorted(scenarios.SCENARIOS)


def test_password_spray_with_successful_sign_in_is_critical():
    inc = run(scenarios.build('password_spray'))[0]
    assert inc['severity'] == 'CRITICAL'
    assert inc['mitre']['technique_id'] == 'T1110.003'
    assert inc['detection_signal']['compromised_accounts'] == ['h.patel@contoso.com']


def test_spray_below_threshold_is_not_a_spray():
    recs = [scenarios.record(f'u{i}@contoso.com', '50126', NOW + timedelta(seconds=i), '203.0.113.5')
            for i in range(detections.PASSWORD_SPRAY_MIN_USERS - 1)]
    assert run(recs) == []


def test_spray_outside_window_is_not_a_spray():
    recs = [scenarios.record(f'u{i}@contoso.com', '50126', NOW + timedelta(minutes=20 * i), '203.0.113.5')
            for i in range(6)]
    assert run(recs) == []


def test_mfa_fatigue_suppresses_single_failure_incident_for_same_user():
    incidents = run(scenarios.build('mfa_fatigue'))
    assert kinds(incidents) == ['mfa_fatigue']
    assert incidents[0]['mitre']['technique_id'] == 'T1621'
    assert incidents[0]['detection_signal']['prompts'] == 5


def test_two_push_denials_are_not_fatigue():
    recs = scenarios.build('mfa_fatigue', 'x@contoso.com')[:2]
    assert kinds(run(recs)) == ['mfa_auth_failure']


def test_single_fraud_report_is_fatigue():
    rec = scenarios.build('mfa_fatigue', 'x@contoso.com')[0]
    rec['properties']['status']['additionalDetails'] = 'MFA denied; user reported fraud'
    assert kinds(run([rec])) == ['mfa_fatigue']


def test_mfa_required_interrupts_are_not_incidents():
    # 50074 / 50076 are normal "MFA required" interrupts, not failures
    recs = [scenarios.record('x@contoso.com', code, NOW, '192.0.2.1') for code in ('50074', '50076')]
    assert run(recs) == []


def test_modern_successful_sign_in_is_clean():
    rec = scenarios.record('x@contoso.com', '0', NOW, '192.0.2.1', requirement='multiFactorAuthentication')
    assert run([rec]) == []


def test_single_factor_sign_in_only_flagged_for_admins():
    user = scenarios.record('x@contoso.com', '0', NOW, '192.0.2.1')
    admin = scenarios.record(scenarios.DEMO_ADMIN, '0', NOW, '192.0.2.1')
    assert kinds(run([user, admin])) == ['privileged_single_factor']


def test_break_glass_failed_attempt_is_still_critical():
    rec = scenarios.record(scenarios.DEMO_BREAK_GLASS, '50126', NOW, '192.0.2.1')
    inc = run([rec])
    assert kinds(inc) == ['break_glass_sign_in'] and inc[0]['severity'] == 'CRITICAL'
    assert inc[0]['detection_signal']['succeeded'] is False


def test_ca_block_without_mfa_is_not_policy_mismatch():
    rec = scenarios.record('x@contoso.com', '53003', NOW, '192.0.2.1')
    assert run([rec]) == []


def test_incident_ids_are_stable_for_the_same_records():
    recs = scenarios.build('all')
    first = sorted(i['incident_id'] for i in run(recs))
    second = sorted(i['incident_id'] for i in run(recs))
    assert first == second and len(set(first)) == len(first)


def test_lockout_carries_cooldown_for_responder():
    inc = run(scenarios.build('smart_lockout'))[0]
    assert inc['cooldown_seconds'] == 300 and inc['auto_remediation'] is True
    assert inc['detection_signal']['failed_attempts_before_lockout'] == 10


def test_non_signin_records_are_ignored():
    assert run([{'category': 'AuditLogs', 'properties': {}}, 'junk', None]) == []
