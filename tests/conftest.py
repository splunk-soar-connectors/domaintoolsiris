"""
Shared fixtures and phantom module stubs for DomainTools connector tests.

phantom.* packages are only available inside a real Splunk SOAR instance.
We stub the minimum surface area needed to import and exercise the connector.
"""

import sys
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Stub out the phantom.* namespace before the connector is imported
# ---------------------------------------------------------------------------

def _make_phantom_stub():
    phantom = ModuleType("phantom")
    phantom.APP_SUCCESS = True
    phantom.APP_ERROR = False
    phantom.APP_PROG_CONNECTING_TO_ELLIPSES = "Connecting to %s..."
    phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY = "test_asset_connectivity"

    # phantom.app sub-module
    app = ModuleType("phantom.app")
    app.APP_SUCCESS = True
    app.APP_ERROR = False
    app.APP_PROG_CONNECTING_TO_ELLIPSES = "Connecting to %s..."
    app.ACTION_ID_TEST_ASSET_CONNECTIVITY = "test_asset_connectivity"
    phantom.app = app

    # phantom.action_result sub-module
    ar_mod = ModuleType("phantom.action_result")

    class ActionResult:
        def __init__(self, param=None):
            self._param = param or {}
            self._data = []
            self._status = None
            self._message = ""
            self._summary = {}

        def set_status(self, status, message="", *args):
            self._status = status
            self._message = str(message)
            return status

        def get_status(self):
            return self._status

        def get_message(self):
            return self._message

        def add_data(self, data):
            self._data.append(data)

        def update_data(self, data):
            self._data.extend(data)

        def get_data(self):
            return self._data

        def update_summary(self, summary):
            self._summary.update(summary)

        def get_summary(self):
            return self._summary

    ar_mod.ActionResult = ActionResult
    phantom.action_result = ar_mod

    # phantom.base_connector sub-module
    bc_mod = ModuleType("phantom.base_connector")

    class BaseConnector:
        def __init__(self):
            self._action_results = []

        def add_action_result(self, ar):
            self._action_results.append(ar)
            return ar

        def last_action_result(self):
            return self._action_results[-1] if self._action_results else None

        def get_action_identifier(self):
            return ""

        def get_app_json(self):
            return {"app_version": "1.8.0", "name": "DomainTools Iris Investigate"}

        def get_phantom_base_url(self):
            return "https://soar.local"

        def get_config(self):
            return {}

        def save_progress(self, msg, *args):
            pass

        def debug_print(self, msg, *args):
            pass

        def set_status_save_progress(self, status, msg):
            return status

        def set_status(self, status, msg="", *args):
            return status

    bc_mod.BaseConnector = BaseConnector
    phantom.base_connector = bc_mod

    # phantom.requests stub
    requests_stub = MagicMock()
    phantom.requests = requests_stub

    # phantom.rules stub (used in playbooks, not connector — included for completeness)
    rules_stub = MagicMock()
    phantom.rules = rules_stub

    return phantom


# Install stubs into sys.modules before any connector import
_phantom = _make_phantom_stub()
sys.modules.setdefault("phantom", _phantom)
sys.modules.setdefault("phantom.app", _phantom.app)
sys.modules.setdefault("phantom.action_result", _phantom.action_result)
sys.modules.setdefault("phantom.base_connector", _phantom.base_connector)
sys.modules.setdefault("phantom.requests", _phantom.requests)
sys.modules.setdefault("phantom.rules", _phantom.rules)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def connector():
    """A DomainToolsConnector with minimal config pre-loaded."""
    from domaintools_iris_connector import DomainToolsConnector

    conn = DomainToolsConnector()
    conn._username = "test_user"
    conn._key = "test_key"
    conn._ssl = True
    conn._proxy_url = None
    conn.app_partner = "splunk_soar"
    conn.app_name = "DomainTools Iris Investigate"
    conn.app_version_number = "1.8.0"
    return conn


@pytest.fixture()
def mock_dt_api(mocker):
    """Patches _get_dt_api on the connector and returns the mock API instance."""
    mock_api = MagicMock()
    mocker.patch(
        "domaintools_iris_connector.DomainToolsConnector._get_dt_api",
        return_value=mock_api,
    )
    return mock_api


# ---------------------------------------------------------------------------
# Sample API response helpers
# ---------------------------------------------------------------------------

def make_domain(
    domain="evil-example.com",
    state="new",
    risk_score=85,
    domain_id="abc123",
    discovered_date="2026-01-01T00:00:00Z",
    changed_date="2026-01-02T00:00:00Z",
    status="active",
    tld="com",
    mx_exists=False,
    escalations=None,
    monitor_ids=None,
):
    return {
        "domain": domain,
        "state": state,
        "risk_score": risk_score,
        "risk_score_status": "full",
        "id": domain_id,
        "discovered_date": discovered_date,
        "changed_date": changed_date,
        "status": status,
        "tld": tld,
        "mx_exists": mx_exists,
        "escalations": escalations or [],
        "monitor_ids": monitor_ids or ["mon1"],
    }


def make_monitor(
    term="domaintools",
    monitor_id="mon1",
    state="active",
    status="completed",
    created_by="test_user",
):
    return {
        "term": term,
        "id": monitor_id,
        "state": state,
        "status": status,
        "created_date": "2026-01-01T00:00:00Z",
        "updated_date": "2026-01-01T00:00:00Z",
        "created_by": created_by,
        "match_substring_variations": False,
        "nameserver_exclusions": [],
        "text_exclusions": [],
    }


def make_escalation(
    watchlist_domain_id="abc123",
    escalation_type="blocked",
    escalation_id="esc1",
):
    return {
        "watchlist_domain_id": watchlist_domain_id,
        "escalation_type": escalation_type,
        "id": escalation_id,
        "created_date": "2026-01-01T00:00:00Z",
        "updated_date": "2026-01-01T00:00:00Z",
        "created_by": "test_user",
    }
