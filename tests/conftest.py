import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'functions'))

# Stand-in for common.py (Cosmos DB + App Insights) so the pipeline runs offline
_store = {}
fake = types.ModuleType('common')
fake.ENVIRONMENT = 'test'
fake.INCIDENT_TTL_SECONDS = 3600
fake.alerts = []
fake.metrics = []


def store_incident(incident, create_only=False):
    if create_only and incident['id'] in _store:
        return False
    _store[incident['id']] = incident
    return True


fake.store_incident = store_incident
fake.publish_alert = lambda incident: fake.alerts.append(incident['incident_id'])
fake.emit_metric = lambda name, value, **dims: fake.metrics.append((name, dims))
fake.store = _store
sys.modules['common'] = fake


def pytest_runtest_setup(item):
    _store.clear()
