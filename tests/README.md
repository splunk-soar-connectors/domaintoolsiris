# Running Tests

## Setup

Create and activate a virtual environment, then install test dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-test.txt
```

> The `.venv` directory is already created if you have run tests before. Just activate it.

## Running Tests

### All tests
```bash
.venv/bin/python -m pytest
```

### A specific test file
```bash
.venv/bin/python -m pytest tests/test_iris_detect_get_new_domains.py
```

### A specific test case
```bash
.venv/bin/python -m pytest tests/test_iris_detect_get_new_domains.py::TestIrisDetectGetNewDomains::test_returns_success_with_results
```

### With verbose output
```bash
.venv/bin/python -m pytest -v
```

### Stop on first failure
```bash
.venv/bin/python -m pytest -x
```

## Test Files

| File | Action Tested |
|---|---|
| `test_iris_detect_get_new_domains.py` | `_iris_detect_get_new_domains` |
| `test_iris_detect_get_watched_domains.py` | `_iris_detect_get_watched_domains` |
| `test_iris_detect_get_ignored_domains.py` | `_iris_detect_get_ignored_domains` |
| `test_iris_detect_get_escalated_domains.py` | `_iris_detect_get_escalated_domains` |
| `test_iris_detect_get_blocklist_domains.py` | `_iris_detect_get_blocklist_domains` |
| `test_iris_detect_get_monitors_list.py` | `_iris_detect_get_monitors_list` |
| `test_iris_detect_escalate_domains.py` | `_iris_detect_escalate_domains` |
| `test_iris_detect_blocklist_domains.py` | `_iris_detect_blocklist_domains` |
| `test_iris_detect_watch_domains.py` | `_iris_detect_watch_domains` |
| `test_iris_detect_ignore_domains.py` | `_iris_detect_ignore_domains` |

## How It Works

The `phantom.*` packages are only available inside a real Splunk SOAR instance. The `conftest.py` file stubs out the entire `phantom` namespace before the connector is imported, allowing tests to run locally without a SOAR instance.

The `domaintools.API` wrapper is patched via the `mock_dt_api` fixture in `conftest.py`, so no real API credentials or network access are needed.

### Key fixtures (defined in `conftest.py`)

| Fixture | Description |
|---|---|
| `connector` | A pre-configured `DomainToolsConnector` instance |
| `mock_dt_api` | Patches `_get_dt_api` and returns a `MagicMock` API instance |

### Response helpers (defined in `conftest.py`)

| Helper | Returns |
|---|---|
| `make_domain(...)` | A fake domain dict matching the Iris Detect API response shape |
| `make_monitor(...)` | A fake monitor dict |
| `make_escalation(...)` | A fake escalation dict |
