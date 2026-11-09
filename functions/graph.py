"""Minimal Microsoft Graph client (stdlib HTTP + azure-identity token). Read-only GETs with paging."""

import json
import urllib.error
import urllib.request
from typing import Any, Dict, List

GRAPH = 'https://graph.microsoft.com/v1.0'


class GraphError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(f'Graph {status}: {message}')
        self.status = status


def _token() -> str:
    from azure.identity import DefaultAzureCredential
    return DefaultAzureCredential().get_token('https://graph.microsoft.com/.default').token


def get(path: str, token: str = '') -> Dict[str, Any]:
    url = path if path.startswith('https://') else f'{GRAPH}{path}'
    req = urllib.request.Request(url, headers={'Authorization': f'Bearer {token or _token()}'})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', 'replace')
        try:
            message = json.loads(body)['error']['message']
        except (ValueError, KeyError):
            message = body[:300]
        raise GraphError(e.code, message) from None


def get_all(path: str) -> List[Dict[str, Any]]:
    token = _token()
    items: List[Dict[str, Any]] = []
    page = get(path, token)
    items.extend(page.get('value', []))
    while page.get('@odata.nextLink'):
        page = get(page['@odata.nextLink'], token)
        items.extend(page.get('value', []))
    return items
