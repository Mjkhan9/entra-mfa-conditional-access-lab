"""
MFA Incident Simulator & Detector

Dual-mode handler:
1. SIMULATOR MODE: Generates synthetic incidents for testing (HTTP invoke with a test payload)
2. DETECTOR MODE: Processes real Microsoft Entra sign-in log records (diagnostic settings -> Event Hub)

Scenarios:
- MFA authentication failure (consistent with an expired or mistyped verification code)
- Smart lockout after repeated failed sign-ins
- Policy mismatch (MFA satisfied but Conditional Access blocks access)
"""

import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict

from common import ENVIRONMENT, INCIDENT_TTL_SECONDS, emit_metric, publish_alert, store_incident

# Microsoft Entra sign-in error codes (ResultType)
MFA_FAILURE_CODES = {'500121', '50074', '50076'}   # MFA challenge not completed
SMART_LOCKOUT_CODES = {'50053'}                    # IdsLocked - account locked after repeated failures
CA_BLOCK_CODES = {'53003', '53000', '53001'}       # Conditional Access denied the grant

VALID_SCENARIOS = ['mfa_auth_failure', 'smart_lockout', 'policy_mismatch']


def handle(event: Any) -> Dict[str, Any]:
    """
    Main handler supporting both simulator and detector modes.

    Simulator Mode (HTTP invoke):
    {
        "scenario": "mfa_auth_failure" | "smart_lockout" | "policy_mismatch",
        "user": "username",
        ...
    }

    Detector Mode (sign-in log record streamed by Entra diagnostic settings):
    {
        "category": "SignInLogs",
        "resultType": "500121",
        "properties": { ... sign-in log fields ... }
    }
    A whole diagnostic batch ({"records": [...]}) is accepted too.
    """

    # Determine mode based on event structure
    if is_signin_log_record(event):
        return process_signin_record(event)

    if isinstance(event, dict) and isinstance(event.get('records'), list):
        results = [process_signin_record(r)['body'] for r in event['records'] if is_signin_log_record(r)]
        return {
            'statusCode': 200,
            'body': {'mode': 'detector', 'processed': len(results), 'results': results}
        }

    return process_simulator_event(event if isinstance(event, dict) else {})


def is_signin_log_record(event: Any) -> bool:
    """Check if this is a real Entra sign-in log record (diagnostic settings schema)."""
    return (
        isinstance(event, dict) and
        event.get('category') == 'SignInLogs' and
        isinstance(event.get('properties'), dict)
    )


def process_signin_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process a real sign-in log record from the Event Hub stream.

    Detects:
    - MFA challenge failures (MFA auth failure pattern)
    - Smart lockout events (lockout pattern)
    - Conditional Access blocks with MFA satisfied (policy mismatch pattern)
    """
    props = record.get('properties', {})
    status = props.get('status', {}) or {}

    print(f"[INFO] Processing sign-in log record: resultType={record.get('resultType')}")

    # Extract common fields
    result_type = str(record.get('resultType') or status.get('errorCode') or '')
    username = props.get('userPrincipalName') or record.get('identity') or 'unknown'
    source_ip = props.get('ipAddress') or record.get('callerIpAddress') or 'unknown'

    incident = None

    # Pattern 1: MFA challenge not completed (MFA auth failure)
    if result_type in MFA_FAILURE_CODES:
        incident = create_mfa_auth_failure_incident(
            user=username,
            source_ip=source_ip,
            record=record
        )

    # Pattern 2: Smart lockout engaged after repeated failures
    elif result_type in SMART_LOCKOUT_CODES:
        incident = create_smart_lockout_incident(
            user=username,
            source_ip=source_ip,
            record=record
        )

    # Pattern 3: Conditional Access blocked the sign-in although MFA was satisfied (policy mismatch)
    elif result_type in CA_BLOCK_CODES and mfa_was_satisfied(props):
        incident = create_policy_mismatch_incident(
            user=username,
            source_ip=source_ip,
            record=record
        )

    if incident:
        store_incident(incident)
        publish_alert(incident)
        emit_incident_metric(incident)

        return {
            'statusCode': 200,
            'body': {
                'mode': 'detector',
                'incident_id': incident['incident_id'],
                'scenario': incident['scenario'],
                'status': 'created',
                'source': 'signin_logs'
            }
        }

    print(f"[INFO] Record did not match any incident pattern: resultType={result_type}")
    return {
        'statusCode': 200,
        'body': {
            'mode': 'detector',
            'status': 'no_match',
            'result_type': result_type
        }
    }


def mfa_was_satisfied(props: Dict[str, Any]) -> bool:
    """True when the sign-in completed an MFA step before Conditional Access denied the grant."""
    steps = props.get('authenticationDetails') or []
    if steps:
        return any(
            step.get('succeeded') and
            str(step.get('authenticationStepRequirement', '')).lower().startswith('multi')
            for step in steps
        )
    return props.get('authenticationRequirement') == 'multiFactorAuthentication'


def process_simulator_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process synthetic test events (HTTP invoke).
    Original simulator functionality for testing and demos.
    """
    scenario = event.get('scenario', 'mfa_auth_failure')
    user = event.get('user', 'test-user')
    source_ip = event.get('source_ip', '192.0.2.1')  # TEST-NET-1 per RFC 5737
    metadata = event.get('metadata', {})

    print(f"[INFO] Simulator mode: generating {scenario} incident")

    # Generate incident based on scenario
    if scenario == 'mfa_auth_failure':
        incident = simulate_mfa_auth_failure(user, source_ip, metadata)
    elif scenario == 'smart_lockout':
        incident = simulate_smart_lockout(user, source_ip, metadata)
    elif scenario == 'policy_mismatch':
        incident = simulate_policy_mismatch(user, source_ip, metadata)
    else:
        return {
            'statusCode': 400,
            'body': {
                'error': f'Unknown scenario: {scenario}',
                'valid_scenarios': VALID_SCENARIOS
            }
        }

    # Store incident in Cosmos DB
    store_incident(incident)

    # Publish alert (Application Insights -> alert rule -> action group)
    publish_alert(incident)

    # Emit metric for the workbook
    emit_incident_metric(incident)

    return {
        'statusCode': 200,
        'body': {
            'mode': 'simulator',
            'incident_id': incident['incident_id'],
            'scenario': scenario,
            'status': 'created',
            'timestamp': incident['timestamp']
        }
    }


def base_incident(incident_id: str, scenario: str, severity: str, user: str, source_ip: str,
                  detection_source: str) -> Dict[str, Any]:
    """Fields every incident record carries."""
    now = int(time.time())
    return {
        'id': incident_id,                      # Cosmos DB document id
        'incident_id': incident_id,
        'scenario': scenario,                   # Cosmos DB partition key
        'severity': severity,
        'status': 'OPEN',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'created_at': now,
        'user': user,
        'source_ip': source_ip,
        'detection_source': detection_source,
        'environment': ENVIRONMENT,
        'ttl': INCIDENT_TTL_SECONDS             # Cosmos DB per-item TTL (seconds)
    }


def signin_signal(record: Dict[str, Any]) -> Dict[str, Any]:
    """Detection signal fields shared by every detector-mode incident."""
    props = record.get('properties', {})
    status = props.get('status', {}) or {}
    return {
        'category': 'SignInLogs',
        'result_type': str(record.get('resultType') or status.get('errorCode') or ''),
        'failure_reason': status.get('failureReason') or record.get('resultDescription', ''),
        'additional_details': status.get('additionalDetails', ''),
        'authentication_requirement': props.get('authenticationRequirement', ''),
        'app': props.get('appDisplayName', ''),
        'event_time': record.get('time') or props.get('createdDateTime', ''),
        'correlation_id': props.get('correlationId') or record.get('correlationId', ''),
        'authentication_details': props.get('authenticationDetails', [])
    }


def create_mfa_auth_failure_incident(user: str, source_ip: str, record: Dict) -> Dict[str, Any]:
    """Create incident from a real sign-in log MFA failure."""
    incident = base_incident(
        incident_id=f"MFA-AUTH-{uuid.uuid4().hex[:8].upper()}",
        scenario='mfa_auth_failure', severity='MEDIUM',
        user=user, source_ip=source_ip, detection_source='signin_logs'
    )
    incident.update({
        'detection_signal': signin_signal(record),
        'description': f'MFA authentication failure for user {user} consistent with an expired '
                       f'or mistyped verification code',
        'recommended_action': 'User must sign in again and complete the MFA prompt with a fresh code',
        'auto_remediation': False
    })
    return incident


def create_smart_lockout_incident(user: str, source_ip: str, record: Dict) -> Dict[str, Any]:
    """Create incident from a real sign-in log smart lockout event (50053)."""
    incident = base_incident(
        incident_id=f"LOCKOUT-{uuid.uuid4().hex[:8].upper()}",
        scenario='smart_lockout', severity='HIGH',
        user=user, source_ip=source_ip, detection_source='signin_logs'
    )
    incident.update({
        'detection_signal': {
            **signin_signal(record),
            'pattern': 'Smart lockout after repeated failed sign-ins from the same user and IP'
        },
        'description': f'Smart lockout triggered for user {user} after repeated failed sign-in attempts',
        'recommended_action': 'Wait for the lockout to clear, then sign in again with a fresh MFA code',
        'auto_remediation': True,
        'remediation_type': 'assisted',
        'cooldown_seconds': 300
    })
    return incident


def create_policy_mismatch_incident(user: str, source_ip: str, record: Dict) -> Dict[str, Any]:
    """Create incident from a real sign-in log Conditional Access block."""
    props = record.get('properties', {})
    failed_policies = [
        {'name': p.get('displayName', ''), 'grant_controls': p.get('enforcedGrantControls', [])}
        for p in props.get('appliedConditionalAccessPolicies', []) or []
        if p.get('result') == 'failure'
    ]
    incident = base_incident(
        incident_id=f"POLICY-{uuid.uuid4().hex[:8].upper()}",
        scenario='policy_mismatch', severity='MEDIUM',
        user=user, source_ip=source_ip, detection_source='signin_logs'
    )
    incident.update({
        'detection_signal': {
            **signin_signal(record),
            'conditional_access_status': props.get('conditionalAccessStatus', ''),
            'failed_policies': failed_policies,
            'resource': props.get('resourceDisplayName', '')
        },
        'description': f'Policy mismatch: User {user} satisfied MFA but Conditional Access blocked access',
        'recommended_action': 'Admin must review the Conditional Access grant controls (AND vs OR) '
                              'with the What If tool',
        'auto_remediation': False
    })
    return incident


def simulate_mfa_auth_failure(user: str, source_ip: str, metadata: Dict) -> Dict[str, Any]:
    """Simulate MFA authentication failure for testing."""
    incident = base_incident(
        incident_id=f"MFA-AUTH-{uuid.uuid4().hex[:8].upper()}",
        scenario='mfa_auth_failure', severity='MEDIUM',
        user=user, source_ip=source_ip, detection_source='simulator'
    )
    incident.update({
        'detection_signal': {
            'category': 'SignInLogs',
            'result_type': '500121',
            'failure_reason': 'Authentication failed during strong authentication request.',
            'additional_details': "The user didn't complete the MFA prompt. They may have decided not to "
                                  "authenticate, timed out while doing other work, or has an issue with "
                                  "their authentication setup.",
            'authentication_requirement': 'multiFactorAuthentication',
            'app': 'Azure portal',
            'authentication_details': [
                {
                    'authenticationStepRequirement': 'Primary authentication',
                    'authenticationMethod': 'Password',
                    'succeeded': True,
                    'authenticationStepResultDetail': 'Correct password'
                },
                {
                    'authenticationStepRequirement': 'Multi-factor authentication',
                    'authenticationMethod': 'OATH verification code',
                    'succeeded': False,
                    'authenticationStepResultDetail': 'MFA denied; invalid mobile app verification code'
                }
            ]
        },
        'description': f'MFA authentication failure for user {user} consistent with an expired '
                       f'or mistyped verification code',
        'recommended_action': 'User must sign in again and complete the MFA prompt with a fresh code',
        'auto_remediation': False,
        'metadata': metadata
    })
    return incident


def simulate_smart_lockout(user: str, source_ip: str, metadata: Dict) -> Dict[str, Any]:
    """Simulate smart lockout scenario for testing."""
    failure_count = metadata.get('failure_count', 5)
    window_seconds = metadata.get('window_seconds', 60)

    incident = base_incident(
        incident_id=f"LOCKOUT-{uuid.uuid4().hex[:8].upper()}",
        scenario='smart_lockout', severity='HIGH',
        user=user, source_ip=source_ip, detection_source='simulator'
    )
    incident.update({
        'detection_signal': {
            'category': 'SignInLogs',
            'result_type': '50053',
            'failure_reason': 'The account is locked because the user tried to sign in too many times '
                              'with an incorrect user ID or password.',
            'failure_count': failure_count,
            'window_seconds': window_seconds,
            'pattern': 'Multiple failed attempts from same user and IP'
        },
        'description': f'Smart lockout triggered: {failure_count} failed sign-in attempts '
                       f'in {window_seconds}s for user {user}',
        'recommended_action': 'Wait for the lockout to clear, then sign in again with a fresh MFA code',
        'auto_remediation': True,
        'remediation_type': 'assisted',
        'cooldown_seconds': 300,
        'metadata': metadata
    })
    return incident


def simulate_policy_mismatch(user: str, source_ip: str, metadata: Dict) -> Dict[str, Any]:
    """Simulate Conditional Access policy mismatch scenario for testing."""
    app = metadata.get('app', 'Azure portal')
    resource = metadata.get('resource', 'Windows Azure Service Management API')
    policy = metadata.get('policy', 'Require compliant device for Azure management')

    incident = base_incident(
        incident_id=f"POLICY-{uuid.uuid4().hex[:8].upper()}",
        scenario='policy_mismatch', severity='MEDIUM',
        user=user, source_ip=source_ip, detection_source='simulator'
    )
    incident.update({
        'detection_signal': {
            'category': 'SignInLogs',
            'result_type': '53003',
            'failure_reason': 'Access has been blocked by Conditional Access policies. '
                              'The access policy does not allow token issuance.',
            'authentication_requirement': 'multiFactorAuthentication',
            'mfa_result': 'MFA requirement satisfied by claim in the token',
            'conditional_access_status': 'failure',
            'failed_policies': [
                {'name': policy, 'grant_controls': ['Mfa', 'RequireCompliantDevice'], 'operator': 'AND'}
            ],
            'condition_evaluated': 'grantControls.operator = AND (require all the selected controls)',
            'condition_result': 'Mfa satisfied; RequireCompliantDevice not satisfied',
            'app': app,
            'resource': resource
        },
        'description': f'Policy mismatch: User {user} satisfied MFA but Conditional Access blocked {app} '
                       f'due to a grant-control mismatch',
        'recommended_action': 'Admin must review the Conditional Access grant controls (AND vs OR) '
                              'with the What If tool',
        'auto_remediation': False,
        'metadata': metadata
    })
    return incident


def emit_incident_metric(incident: Dict[str, Any]) -> None:
    """Emit the IncidentCount metric for the workbook and alert rules."""
    emit_metric(
        'IncidentCount', 1,
        Scenario=incident['scenario'],
        Severity=incident['severity'],
        Environment=ENVIRONMENT,
        Source=incident.get('detection_source', 'unknown')
    )
    print(f"[INFO] Emitted metric for incident {incident['incident_id']}")
