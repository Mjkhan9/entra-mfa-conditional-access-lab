"""
Azure Functions entry point (Python v2 programming model).

Four HTTP functions, nothing running between calls:
- simulate  POST  synthetic attack sign-ins (password spray, MFA fatigue, ...) through the real detections
- detect    POST  pulls recent Entra sign-in logs from Log Analytics and runs the detections
- respond   POST  assisted remediation: resolves smart lockout incidents past their cooldown
- posture   GET   Conditional Access posture check (live via Microsoft Graph, or ?demo=1)

HTTP triggers only: the Flex Consumption app scales to zero when idle, so idle cost is zero.
simulate and detect run the responder first, so lockouts past their cooldown resolve on the
next call without a timer.
"""

import json
import logging

import azure.functions as func

import ca_posture
import detector
import responder
import simulator

app = func.FunctionApp()


def json_response(body, status_code: int = 200) -> func.HttpResponse:
    return func.HttpResponse(json.dumps(body, default=str), status_code=status_code, mimetype='application/json')


def sweep_responder() -> None:
    """Resolve smart lockouts past cooldown before handling the request (replaces a timer)."""
    try:
        result = responder.handle()
        logging.info("[INFO] Responder sweep: %s", json.dumps(result))
    except Exception as e:  # never fail the main request because of the sweep
        logging.error("[ERROR] Responder sweep failed: %s", str(e))


@app.function_name(name="simulate")
@app.route(route="simulate", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def simulate(req: func.HttpRequest) -> func.HttpResponse:
    """Simulator mode: {"scenario": "password_spray" | ... | "all"} or {"records": [...]} to replay."""
    try:
        payload = req.get_json()
    except ValueError:
        return json_response({'error': 'Request body must be JSON'}, 400)

    sweep_responder()
    result = simulator.handle(payload)
    return json_response(result['body'], result['statusCode'])


@app.function_name(name="detect")
@app.route(route="detect", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def detect(req: func.HttpRequest) -> func.HttpResponse:
    """Detector mode: {"minutes": 60} (default 15) of SignInLogs from Log Analytics."""
    try:
        body = req.get_json()
    except ValueError:
        body = {}
    minutes = body.get('minutes', 15) if isinstance(body, dict) else 15

    sweep_responder()
    result = detector.handle(minutes)
    return json_response(result['body'], result['statusCode'])


@app.function_name(name="respond")
@app.route(route="respond", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def respond(req: func.HttpRequest) -> func.HttpResponse:
    """Assisted remediation on demand: resolves smart lockout incidents past their cooldown."""
    result = responder.handle()
    logging.info("[INFO] Responder run: %s", json.dumps(result))
    return json_response(result)


@app.function_name(name="posture")
@app.route(route="posture", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def posture(req: func.HttpRequest) -> func.HttpResponse:
    """Conditional Access posture: live from Microsoft Graph (Policy.Read.All), or ?demo=1 for the sample."""
    if req.params.get('demo') in ('1', 'true'):
        return json_response(ca_posture.demo())
    try:
        return json_response(ca_posture.live())
    except Exception as e:
        logging.error("[ERROR] Posture check failed: %s", str(e))
        status = getattr(e, 'status', 502)
        hint = ('Grant the function app\'s managed identity the Microsoft Graph application permission '
                'Policy.Read.All' if status == 403 else '')
        return json_response({'error': str(e)[:300], 'hint': hint}, 502 if status >= 500 else status)
