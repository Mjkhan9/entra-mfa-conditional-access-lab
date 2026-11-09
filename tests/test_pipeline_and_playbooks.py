import json

import common
import detections
import detector
import pipeline
import playbooks
import scenarios
from simulator import demo_context


def test_every_detection_has_a_playbook_and_nothing_is_automated():
    for name in detections.DETECTIONS:
        steps = playbooks.PLAYBOOKS[name]
        assert steps, name
        for s in steps:
            assert s['step'] and s['graph'] and s['powershell']
    inc = detections.evaluate(scenarios.build('mfa_fatigue'))[0]
    assert all(step['automated'] is False for step in playbooks.for_incident(inc))
    assert any('j.miller@contoso.com' in step['graph'] for step in playbooks.for_incident(inc))


def test_pipeline_stores_alerts_and_attaches_playbook():
    body = pipeline.run(scenarios.build('all'), demo_context(detections.Context()), 'simulator')
    assert body['incidents'] == len(scenarios.SCENARIOS)
    assert all(r['status'] == 'created' for r in body['results'])
    stored = common.store[body['results'][0]['incident_id']]
    assert stored['playbook'] and stored['detection_source'] == 'simulator'


def test_detector_pull_is_idempotent():
    rows = []
    for r in scenarios.build('password_spray'):
        p = r['properties']
        rows.append({'Id': p['id'], 'CreatedDateTime': r['time'], 'ResultType': r['resultType'],
                     'UserPrincipalName': p['userPrincipalName'], 'IPAddress': p['ipAddress'],
                     'ClientAppUsed': p['clientAppUsed'], 'Status': json.dumps(p['status']),
                     'AuthenticationRequirement': p['authenticationRequirement'],
                     'AuthenticationDetails': json.dumps(p['authenticationDetails']),
                     'ConditionalAccessPolicies': '[]'})
    records = [detector.row_to_record(r) for r in rows]
    ctx = detections.Context()
    first = pipeline.run(records, ctx, 'signin_logs')
    second = pipeline.run(records, ctx, 'signin_logs')
    assert [r['status'] for r in first['results']] == ['created']
    assert [r['status'] for r in second['results']] == ['duplicate']
    assert first['results'][0]['incident_id'] == second['results'][0]['incident_id']


def test_row_mapping_parses_dynamic_columns():
    rec = detector.row_to_record({'Id': 'x', 'ResultType': '53003', 'Status': '{"errorCode": 53003}',
                                  'AuthenticationDetails': 'not json', 'ConditionalAccessPolicies': None})
    assert rec['properties']['status'] == {'errorCode': 53003}
    assert rec['properties']['authenticationDetails'] == []
    assert rec['properties']['appliedConditionalAccessPolicies'] == []


def test_detector_query_includes_break_glass_and_skips_mfa_interrupts():
    q = detector.build_query(['emergency@contoso.com'])
    assert '"emergency@contoso.com"' in q and '50126' in q and '50074' not in q
