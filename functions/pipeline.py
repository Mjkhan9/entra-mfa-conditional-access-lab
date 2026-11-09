"""
Detection pipeline: sign-in records -> detections -> Cosmos DB -> alert + metrics.

Shared by simulator mode (synthetic records) and detector mode (records pulled from Log Analytics).
"""

import os
from typing import Any, Dict, List, Set

import detections
import playbooks
from common import ENVIRONMENT, INCIDENT_TTL_SECONDS, emit_metric, publish_alert, store_incident


def _env_upns(name: str) -> Set[str]:
    return {u.strip().lower() for u in os.environ.get(name, '').split(',') if u.strip()}


def tenant_context(lookup_admins: bool = True) -> detections.Context:
    """Who counts as privileged / break-glass: app settings plus live admin role holders."""
    privileged = _env_upns('PRIVILEGED_ACCOUNTS')
    if lookup_admins:
        privileged |= privileged_role_holders()
    return detections.Context(privileged_upns=privileged, break_glass_upns=_env_upns('BREAK_GLASS_ACCOUNTS'),
                              environment=ENVIRONMENT, ttl_seconds=INCIDENT_TTL_SECONDS)


def privileged_role_holders() -> Set[str]:
    """UPNs holding one of the 14 admin roles (Graph, RoleManagement.Read.Directory). Empty on failure."""
    try:
        import ca_posture
        import graph
        upns = set()
        for a in graph.get_all('/roleManagement/directory/roleAssignments?$expand=principal'):
            if a.get('roleDefinitionId') in ca_posture.PRIVILEGED_ROLES:
                principal = a.get('principal') or {}
                if principal.get('userPrincipalName'):
                    upns.add(principal['userPrincipalName'].lower())
        return upns
    except Exception as e:  # detection still runs; privileged_single_factor then relies on app settings
        print(f'[WARN] Admin role lookup failed: {e}')
        return set()


def run(records: List[Dict[str, Any]], ctx: detections.Context, source: str) -> Dict[str, Any]:
    """Evaluate records, store new incidents, raise alerts. Detector incidents are never overwritten."""
    results = []
    for incident in detections.evaluate(records, ctx):
        incident['detection_source'] = source
        incident['playbook'] = playbooks.for_incident(incident)
        if not store_incident(incident, create_only=(source == 'signin_logs')):
            results.append(summary(incident, 'duplicate'))
            continue
        publish_alert(incident)
        emit_metric('IncidentCount', 1, Scenario=incident['scenario'], Severity=incident['severity'],
                    Environment=ENVIRONMENT, Source=source,
                    Technique=(incident.get('mitre') or {}).get('technique_id', ''))
        results.append(summary(incident, 'created'))
    return {'records': len(records), 'incidents': len(results), 'results': results}


def summary(incident: Dict[str, Any], status: str) -> Dict[str, Any]:
    return {
        'incident_id': incident['incident_id'],
        'detection': incident['scenario'],
        'severity': incident['severity'],
        'mitre': (incident.get('mitre') or {}).get('technique_id'),
        'user': incident['user'],
        'source_ip': incident['source_ip'],
        'description': incident['description'],
        'status': status,
    }
