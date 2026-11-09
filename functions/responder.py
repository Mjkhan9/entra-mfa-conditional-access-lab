"""
MFA Incident Responder

Assisted remediation for smart lockout scenarios.
Updates incident state after cooldown - does NOT touch the Entra user.

This is constrained auto-response:
- Only handles smart_lockout scenarios
- Only updates incident state in Cosmos DB
- Logs all actions for audit trail
- Raises a resolution notification through Azure Monitor
"""

import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

from common import ENVIRONMENT, emit_event, emit_metric, incidents_container


def handle() -> Dict[str, Any]:
    """
    Process incidents eligible for assisted remediation.

    Triggered by:
    - POST /api/respond (on demand)
    - The start of every simulate / detect call (sweep, so no timer has to run while idle)

    Only processes smart_lockout incidents that have exceeded cooldown.
    """
    print(f"[INFO] Responder triggered at {datetime.now(timezone.utc).isoformat()}")

    # Get incidents eligible for remediation
    eligible_incidents = get_eligible_incidents()

    if not eligible_incidents:
        print("[INFO] No incidents eligible for remediation")
        return {'processed': 0, 'message': 'No eligible incidents'}

    processed = 0
    for incident in eligible_incidents:
        try:
            process_remediation(incident)
            processed += 1
        except Exception as e:
            print(f"[ERROR] Failed to process {incident['incident_id']}: {str(e)}")

    return {'processed': processed, 'total_eligible': len(eligible_incidents)}


def get_eligible_incidents() -> List[Dict[str, Any]]:
    """
    Query Cosmos DB for smart_lockout incidents past cooldown period.

    Eligibility criteria:
    - scenario = 'smart_lockout'
    - status = 'OPEN'
    - created_at + cooldown_seconds < current_time

    The container is partitioned by scenario, so this is a single-partition query.
    """
    try:
        current_time = int(time.time())

        items = incidents_container().query_items(
            query='SELECT * FROM c WHERE c.scenario = @scenario AND c.status = @status',
            parameters=[
                {'name': '@scenario', 'value': 'smart_lockout'},
                {'name': '@status', 'value': 'OPEN'}
            ],
            partition_key='smart_lockout'
        )

        eligible = []
        for item in items:
            created_at = int(item.get('created_at', 0))
            cooldown = int(item.get('cooldown_seconds', 300))

            if current_time > (created_at + cooldown):
                eligible.append(item)
                print(f"[INFO] Incident {item['incident_id']} eligible for remediation")

        return eligible

    except Exception as e:
        print(f"[ERROR] Failed to query incidents: {str(e)}")
        return []


def process_remediation(incident: Dict[str, Any]) -> None:
    """
    Process assisted remediation for a single incident.

    Actions:
    1. Update incident status to RESOLVED
    2. Record resolution timestamp
    3. Calculate resolution time (simulated MTTR)
    4. Raise resolution notification
    5. Emit resolution metrics

    Does NOT:
    - Modify the Entra user, authentication methods or Conditional Access policies
    - Unlock accounts or reset passwords (smart lockout clears on its own)
    - Revoke sessions or make any destructive changes
    """
    incident_id = incident['incident_id']
    print(f"[INFO] Processing remediation for {incident_id}")

    # Calculate resolution time
    created_at = int(incident.get('created_at', int(time.time())))
    resolved_at = int(time.time())
    resolution_time_seconds = resolved_at - created_at

    # Update incident in Cosmos DB
    update_incident_status(
        incident=incident,
        new_status='RESOLVED',
        resolution_time=resolution_time_seconds,
        resolution_notes='Cooldown period completed. Smart lockout cleared. User may attempt re-authentication.'
    )

    # Send resolution notification
    send_resolution_notification(incident, resolution_time_seconds)

    # Emit resolution metrics
    emit_resolution_metric(incident, resolution_time_seconds)

    print(f"[INFO] Remediation complete for {incident_id} (resolution time: {resolution_time_seconds}s)")


def update_incident_status(
    incident: Dict[str, Any],
    new_status: str,
    resolution_time: int,
    resolution_notes: str
) -> None:
    """Update incident status in Cosmos DB with a partial document update (patch)."""
    try:
        incidents_container().patch_item(
            item=incident['id'],
            partition_key=incident['scenario'],
            patch_operations=[
                {'op': 'set', 'path': '/status', 'value': new_status},
                {'op': 'set', 'path': '/resolved_at', 'value': datetime.now(timezone.utc).isoformat()},
                {'op': 'set', 'path': '/resolution_time_seconds', 'value': resolution_time},
                {'op': 'set', 'path': '/resolution_notes', 'value': resolution_notes},
                {'op': 'set', 'path': '/remediation_type', 'value': 'assisted_auto'}
            ]
        )

        print(f"[INFO] Updated incident {incident['incident_id']} to {new_status}")

    except Exception as e:
        print(f"[ERROR] Failed to update incident: {str(e)}")
        raise


def send_resolution_notification(incident: Dict[str, Any], resolution_time: int) -> None:
    """Raise the resolution notification (same alert path as new incidents)."""
    try:
        message = {
            'event': 'INCIDENT_RESOLVED',
            'incident_id': incident['incident_id'],
            'scenario': incident['scenario'],
            'user': incident['user'],
            'original_severity': incident['severity'],
            'resolution_time_seconds': resolution_time,
            'resolution_time_formatted': format_duration(resolution_time),
            'remediation_type': 'assisted',
            'notes': 'Cooldown period completed. Smart lockout cleared.',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

        emit_event('IncidentAlert', message)

        print(f"[INFO] Sent resolution notification for {incident['incident_id']}")

    except Exception as e:
        print(f"[ERROR] Failed to send notification: {str(e)}")


def emit_resolution_metric(incident: Dict[str, Any], resolution_time: int) -> None:
    """Emit resolution metrics for the workbook and the slow-resolution alert."""
    try:
        emit_metric('IncidentResolved', 1,
                    Scenario=incident['scenario'], Environment=ENVIRONMENT)
        emit_metric('ResolutionTimeSeconds', resolution_time,
                    Scenario=incident['scenario'], Environment=ENVIRONMENT)

        print(f"[INFO] Emitted resolution metrics for {incident['incident_id']}")

    except Exception as e:
        print(f"[ERROR] Failed to emit metrics: {str(e)}")


def format_duration(seconds: int) -> str:
    """Format seconds as human-readable duration."""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        minutes = seconds // 60
        secs = seconds % 60
        return f"{minutes}m {secs}s"
    else:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{hours}h {minutes}m"


# For local testing
if __name__ == '__main__':
    print("Testing responder logic...")

    # Mock incident for testing
    test_incident = {
        'id': 'LOCKOUT-TEST123',
        'incident_id': 'LOCKOUT-TEST123',
        'scenario': 'smart_lockout',
        'severity': 'HIGH',
        'status': 'OPEN',
        'user': 'test-user',
        'created_at': int(time.time()) - 400,  # 400 seconds ago
        'cooldown_seconds': 300
    }

    print(f"Test incident: {json.dumps(test_incident, indent=2)}")
    print(f"Would be eligible: {int(time.time()) > (test_incident['created_at'] + test_incident['cooldown_seconds'])}")
