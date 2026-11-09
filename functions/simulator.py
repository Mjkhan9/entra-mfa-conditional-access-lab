"""
Simulator mode: synthetic Entra sign-in records for an attack scenario, run through the real detections.

POST /api/simulate
    {"scenario": "password_spray"}             one scenario (see scenarios.SCENARIOS)
    {"scenario": "all"}                        every scenario, one account each
    {"scenario": "mfa_fatigue", "user": "x@contoso.com"}
    {"records": [ {sign-in record}, ... ]}     replay captured sign-in records

Run without Azure (prints incidents, stores nothing):
    python simulator.py password_spray
"""

import json
import sys
import uuid
from typing import Any, Dict

import detections
import scenarios


def demo_context(ctx: detections.Context) -> detections.Context:
    """Simulator accounts: the demo admin and break-glass account are known as such."""
    ctx.privileged_upns |= {scenarios.DEMO_ADMIN}
    ctx.break_glass_upns |= {scenarios.DEMO_BREAK_GLASS}
    return ctx


def handle(payload: Any) -> Dict[str, Any]:
    import pipeline

    if detections.is_signin_record(payload):
        payload = {'records': [payload]}

    if isinstance(payload, dict) and isinstance(payload.get('records'), list):
        body = pipeline.run(payload['records'], pipeline.tenant_context(), 'replay')
        return {'statusCode': 200, 'body': {'mode': 'replay', **body}}

    payload = payload if isinstance(payload, dict) else {}
    scenario = payload.get('scenario', 'all')
    if scenario != 'all' and scenario not in scenarios.SCENARIOS:
        return {'statusCode': 400, 'body': {'error': f'Unknown scenario: {scenario}',
                                            'valid_scenarios': scenarios.SCENARIOS + ['all']}}

    records = scenarios.build(scenario, payload.get('user'))
    ctx = demo_context(pipeline.tenant_context())
    ctx.run_salt = uuid.uuid4().hex  # each simulation is a new set of incidents
    body = pipeline.run(records, ctx, 'simulator')
    return {'statusCode': 200, 'body': {'mode': 'simulator', 'scenario': scenario, **body}}


if __name__ == '__main__':
    import playbooks
    name = sys.argv[1] if len(sys.argv) > 1 else 'all'
    for inc in detections.evaluate(scenarios.build(name), demo_context(detections.Context())):
        mitre = (inc.get('mitre') or {}).get('technique_id') or '-'
        print(f"[{inc['severity']:<8}] {inc['incident_id']:<20} {inc['scenario']:<25} {mitre:<10} {inc['description']}")
        if '--playbook' in sys.argv:
            print(json.dumps(playbooks.for_incident(inc), indent=2))
