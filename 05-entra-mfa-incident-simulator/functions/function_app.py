"""
Azure Functions entry point (Python v2 programming model).

Three triggers, one pipeline:
- simulate  (HTTP)       -> simulator mode: test payload in, incident out
- detect    (Event Hub)  -> detector mode: real Entra sign-in log records streamed by diagnostic settings
- respond   (Timer)      -> assisted remediation for smart lockout incidents past cooldown

All three share the same handler code in simulator.py / responder.py.
"""

import json
import logging
from typing import List

import azure.functions as func

import responder
import simulator

app = func.FunctionApp()


@app.function_name(name="simulate")
@app.route(route="simulate", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def simulate(req: func.HttpRequest) -> func.HttpResponse:
    """
    Simulator mode. POST a scenario payload:
        {"scenario": "smart_lockout", "user": "test-user"}

    A captured sign-in log record (or a whole {"records": [...]} batch) is accepted too,
    which replays it through detector mode - handy for testing with real events.
    """
    try:
        payload = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({'error': 'Request body must be JSON'}),
            status_code=400,
            mimetype='application/json'
        )

    result = simulator.handle(payload)
    return func.HttpResponse(
        json.dumps(result['body']),
        status_code=result['statusCode'],
        mimetype='application/json'
    )


@app.function_name(name="detect")
@app.event_hub_message_trigger(
    arg_name="events",
    event_hub_name="%EVENTHUB_NAME%",
    connection="EventHubConnection",
    cardinality="many"
)
def detect(events: List[func.EventHubEvent]) -> None:
    """
    Detector mode. Each Event Hub message is a diagnostic-settings batch:
        {"records": [ {sign-in log record}, ... ]}
    """
    for event in events:
        batch = json.loads(event.get_body().decode('utf-8'))
        result = simulator.handle(batch)
        logging.info("[INFO] Detector processed batch: %s", json.dumps(result['body']))


@app.function_name(name="respond")
@app.timer_trigger(schedule="%RESPONDER_SCHEDULE%", arg_name="timer", run_on_startup=False, use_monitor=False)
def respond(timer: func.TimerRequest) -> None:
    """Assisted remediation. Runs on the schedule in RESPONDER_SCHEDULE (default: every 5 minutes)."""
    if timer.past_due:
        logging.info("[INFO] Responder timer is past due")
    result = responder.handle()
    logging.info("[INFO] Responder run: %s", json.dumps(result))
