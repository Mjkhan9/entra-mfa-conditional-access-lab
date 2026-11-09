"""
Detector mode: pull Microsoft Entra sign-in logs from Log Analytics and run the detections.

Entra diagnostic settings send SignInLogs to the Log Analytics workspace (enable_entra_log_export).
POST /api/detect queries the last N minutes with the function app's managed identity
(Log Analytics Reader, no keys), maps each row back to the diagnostic-settings record shape and
runs the batch through pipeline.run(), the same path simulator records take.

Why pull instead of stream: an event hub bills every hour it exists, even with no traffic.
Workspace ingestion stays inside the free monthly allowance and queries are free, so this path
costs nothing when idle. Incident IDs come from the sign-in ID (or attacker IP / user plus a time
bucket for burst detections), so overlapping pulls never create duplicates.
"""

import json
import os
from datetime import datetime, timedelta
from typing import Any, Dict, List

import detections

WORKSPACE_ID = os.environ.get('LOG_ANALYTICS_WORKSPACE_ID', '')
MAX_MINUTES = 24 * 60
MAX_ROWS = 1000

_codes = ', '.join(f'"{c}"' for c in sorted(detections.WATCHED_CODES - detections.SUCCESS_CODES))
_modern = ', '.join(f'"{c}"' for c in sorted(detections.MODERN_CLIENTS))


def build_query(break_glass: List[str]) -> str:
    """Failures the detections use, plus successful sign-ins that matter (legacy, single-factor, break-glass)."""
    bg = ', '.join(f'"{u}"' for u in break_glass) or '""'
    return f"""
SigninLogs
| where ResultType in ({_codes})
     or (ResultType == "0" and (ClientAppUsed !in ({_modern})
                                or AuthenticationRequirement == "singleFactorAuthentication"))
     or UserPrincipalName in~ ({bg})
| project TimeGenerated, Id, CreatedDateTime, ResultType, ResultDescription, UserPrincipalName, IPAddress,
          ClientAppUsed, Status, AuthenticationRequirement, AppDisplayName, CorrelationId,
          AuthenticationDetails, ConditionalAccessStatus, ConditionalAccessPolicies, ResourceDisplayName
| order by TimeGenerated asc
| take {MAX_ROWS}
"""


def handle(minutes: Any = 15) -> Dict[str, Any]:
    """Query the last `minutes` of SignInLogs and run the detections."""
    try:
        minutes = max(1, min(int(minutes), MAX_MINUTES))
    except (TypeError, ValueError):
        return {'statusCode': 400, 'body': {'error': 'minutes must be a number'}}

    if not WORKSPACE_ID:
        return {'statusCode': 500, 'body': {'error': 'LOG_ANALYTICS_WORKSPACE_ID is not set'}}

    import pipeline
    ctx = pipeline.tenant_context()
    try:
        rows = query_signin_logs(minutes, sorted(ctx.break_glass_upns))
    except Exception as e:
        if 'SigninLogs' in str(e) and 'resolve' in str(e):
            # The table only exists once Entra has exported sign-in logs to the workspace
            return {'statusCode': 200, 'body': {
                'mode': 'detector', 'window_minutes': minutes, 'records': 0, 'incidents': 0, 'results': [],
                'note': 'No SigninLogs table in the workspace yet: set enable_entra_log_export = true'
            }}
        print(f"[ERROR] Sign-in log query failed: {e}")
        return {'statusCode': 502, 'body': {'error': 'Sign-in log query failed', 'detail': str(e)[:300]}}

    records = [row_to_record(r) for r in rows]
    body = pipeline.run(records, ctx, 'signin_logs')
    print(f"[INFO] Detector pulled {len(records)} records over {minutes} min")
    return {'statusCode': 200, 'body': {'mode': 'detector', 'window_minutes': minutes, **body}}


def query_signin_logs(minutes: int, break_glass: List[str]) -> List[Dict[str, Any]]:
    """Run the KQL query with the managed identity and return rows as dicts."""
    from azure.identity import DefaultAzureCredential
    from azure.monitor.query import LogsQueryClient, LogsQueryStatus

    client = LogsQueryClient(DefaultAzureCredential())
    response = client.query_workspace(WORKSPACE_ID, build_query(break_glass), timespan=timedelta(minutes=minutes))

    if response.status == LogsQueryStatus.SUCCESS:
        tables = response.tables
    else:  # partial result: keep what came back, log the error
        print(f"[WARN] Partial query result: {response.partial_error}")
        tables = response.partial_data

    rows: List[Dict[str, Any]] = []
    for table in tables:
        rows.extend(dict(zip(table.columns, row)) for row in table.rows)
    return rows


def parse_dynamic(value: Any, default: Any) -> Any:
    """Log Analytics returns dynamic columns as JSON text; AuthenticationDetails is JSON text too."""
    if value is None or value == '':
        return default
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return default
    return value


def iso(value: Any) -> str:
    return value.isoformat() if isinstance(value, datetime) else str(value or '')


def row_to_record(row: Dict[str, Any]) -> Dict[str, Any]:
    """Map a SigninLogs row to the diagnostic-settings record schema the detections expect."""
    created = iso(row.get('CreatedDateTime') or row.get('TimeGenerated'))
    correlation_id = row.get('CorrelationId') or ''
    return {
        'category': 'SignInLogs',
        'time': created,
        'resultType': str(row.get('ResultType') or ''),
        'resultDescription': row.get('ResultDescription') or '',
        'correlationId': correlation_id,
        'properties': {
            'id': row.get('Id') or '',
            'createdDateTime': created,
            'userPrincipalName': row.get('UserPrincipalName') or '',
            'ipAddress': row.get('IPAddress') or '',
            'clientAppUsed': row.get('ClientAppUsed') or '',
            'status': parse_dynamic(row.get('Status'), {}),
            'authenticationRequirement': row.get('AuthenticationRequirement') or '',
            'appDisplayName': row.get('AppDisplayName') or '',
            'correlationId': correlation_id,
            'authenticationDetails': parse_dynamic(row.get('AuthenticationDetails'), []),
            'conditionalAccessStatus': row.get('ConditionalAccessStatus') or '',
            'appliedConditionalAccessPolicies': parse_dynamic(row.get('ConditionalAccessPolicies'), []),
            'resourceDisplayName': row.get('ResourceDisplayName') or '',
        },
    }
