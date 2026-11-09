"""
Shared helpers for the MFA incident simulator.

- Settings come from app settings (set via Terraform).
- Incidents are stored in Azure Cosmos DB using the function app's managed identity (no keys).
- Alerts and metrics are written to Application Insights as structured log events for the workbook.
  Azure Monitor metric alerts fire on the Cosmos DB writes themselves (Create = new incident,
  Patch = resolution), which keeps alerting inside the free tier.
"""

import json
import logging
import os
from functools import lru_cache
from typing import Any, Dict

from azure.cosmos import CosmosClient
from azure.cosmos.exceptions import CosmosResourceExistsError
from azure.identity import DefaultAzureCredential

# Environment variables (set via Terraform)
COSMOS_ENDPOINT = os.environ.get('COSMOS_ENDPOINT', '')
COSMOS_DATABASE = os.environ.get('COSMOS_DATABASE', 'incidents-db')
COSMOS_CONTAINER = os.environ.get('COSMOS_CONTAINER', 'incidents')
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'dev')
INCIDENT_TTL_SECONDS = int(os.environ.get('INCIDENT_TTL_DAYS', '7')) * 24 * 60 * 60

logger = logging.getLogger('mfa-incident-simulator')


@lru_cache(maxsize=1)
def incidents_container():
    """Cosmos DB container client, authenticated with the managed identity."""
    client = CosmosClient(COSMOS_ENDPOINT, credential=DefaultAzureCredential())
    return client.get_database_client(COSMOS_DATABASE).get_container_client(COSMOS_CONTAINER)


def store_incident(incident: Dict[str, Any], create_only: bool = False) -> bool:
    """
    Store incident in Cosmos DB (id = incident_id, partition key = scenario).

    create_only=True never overwrites: returns False when the incident already exists
    (detector pulls overlap, and their incident IDs are derived from the sign-in record).
    """
    try:
        if create_only:
            incidents_container().create_item(incident)
        else:
            incidents_container().upsert_item(incident)
        logger.info("[INFO] Stored incident %s in Cosmos DB", incident['incident_id'])
        return True
    except CosmosResourceExistsError:
        logger.info("[INFO] Incident %s already stored, skipped", incident['incident_id'])
        return False
    except Exception as e:
        logger.error("[ERROR] Failed to store incident: %s", str(e))
        raise


def publish_alert(incident: Dict[str, Any]) -> None:
    """
    Publish an incident alert.

    The alert is written to Application Insights as an 'IncidentAlert' event.
    The 'incident-created' alert rule picks it up and the action group sends the email,
    so the function never needs to know who gets notified.
    """
    message = {
        'event': 'INCIDENT_CREATED',
        'incident_id': incident['incident_id'],
        'scenario': incident['scenario'],
        'severity': incident['severity'],
        'user': incident['user'],
        'description': incident['description'],
        'timestamp': incident['timestamp'],
        'detection_source': incident.get('detection_source', 'unknown'),
        'recommended_action': incident['recommended_action']
    }
    emit_event('IncidentAlert', message)
    logger.info("[INFO] Published alert for incident %s", incident['incident_id'])


def emit_metric(name: str, value: float, **dimensions: Any) -> None:
    """Emit a metric event for the workbook and alert rules (name + value + dimensions)."""
    emit_event(name, {'value': value, **dimensions})


def emit_event(name: str, payload: Dict[str, Any]) -> None:
    """
    Write one structured event to Application Insights.

    Format: '<EventName> {json}'. KQL reads it back with
    parse_json(extract(@"^\\S+ (.*)$", 1, message)).
    """
    try:
        logger.info("%s %s", name, json.dumps(payload, default=str))
    except Exception as e:
        logger.error("[ERROR] Failed to emit event %s: %s", name, str(e))
