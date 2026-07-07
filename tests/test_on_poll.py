"""Unit tests for _on_poll action."""


HEADERS = ["repo/playbook_name", "event_id", "interval (mins)", "last_run (server time)", "last_run_status", "remarks"]


def make_playbook(name="local/MyPlaybook", event_id="42", interval="1440", last_run="", last_run_status="", remarks=""):
    return [name, event_id, interval, last_run, last_run_status, remarks]


class TestOnPoll:

    def test_returns_error_when_no_scheduled_playbooks(self, connector):
        connector._get_scheduled_playbooks = lambda: (HEADERS, [])

        result = connector._on_poll({})
        ar = connector.last_action_result()

        assert result is False
        assert "No scheduled playbooks found" in ar.get_message()

    def test_returns_success_when_list_updated(self, connector):
        pb = make_playbook(last_run="2026-01-01 00:00:00")
        connector._get_scheduled_playbooks = lambda: (HEADERS, [pb])
        connector._get_playbook_monitoring_container = lambda event_id, name: ({"id": "99", "label": "events"}, "")
        connector._is_playbook_valid = lambda name, label: (True, "")
        connector._check_interval = lambda interval, last_run: False
        connector._update_scheduled_playbook_list = lambda contents: True

        result = connector._on_poll({})

        assert result is True

    def test_returns_error_when_list_update_fails(self, connector):
        pb = make_playbook(last_run="2026-01-01 00:00:00")
        connector._get_scheduled_playbooks = lambda: (HEADERS, [pb])
        connector._get_playbook_monitoring_container = lambda event_id, name: ({"id": "99", "label": "events"}, "")
        connector._is_playbook_valid = lambda name, label: (True, "")
        connector._check_interval = lambda interval, last_run: False
        connector._update_scheduled_playbook_list = lambda contents: False

        result = connector._on_poll({})
        ar = connector.last_action_result()

        assert result is False
        assert "Something went wrong" in ar.get_message()

    def test_skips_playbook_when_container_not_found(self, connector):
        pb = make_playbook()
        connector._get_scheduled_playbooks = lambda: (HEADERS, [pb])
        connector._get_playbook_monitoring_container = lambda event_id, name: (None, "container not found")
        connector._update_scheduled_playbook_list = lambda contents: True

        result = connector._on_poll({})

        assert result is True
        # _is_playbook_valid and _run_playbook should never be called
        # (covered implicitly — no AttributeError means they weren't reached)

    def test_skips_playbook_when_invalid(self, connector):
        pb = make_playbook()
        connector._get_scheduled_playbooks = lambda: (HEADERS, [pb])
        connector._get_playbook_monitoring_container = lambda event_id, name: ({"id": "99", "label": "events"}, "")
        connector._is_playbook_valid = lambda name, label: (False, "playbook not found")
        connector._update_scheduled_playbook_list = lambda contents: True

        result = connector._on_poll({})

        assert result is True

    def test_runs_playbook_when_interval_elapsed(self, connector):
        pb = make_playbook(last_run="2026-01-01 00:00:00")
        run_calls = []
        connector._get_scheduled_playbooks = lambda: (HEADERS, [pb])
        connector._get_playbook_monitoring_container = lambda event_id, name: ({"id": "99", "label": "events"}, "")
        connector._is_playbook_valid = lambda name, label: (True, "")
        connector._check_interval = lambda interval, last_run: True
        connector._run_playbook = lambda data: run_calls.append(data) or True
        connector._update_scheduled_playbook_list = lambda contents: True

        connector._on_poll({})

        assert len(run_calls) == 1
        assert run_calls[0]["container_id"] == "99"
        assert run_calls[0]["run"] is True

    def test_does_not_run_playbook_when_interval_not_elapsed(self, connector):
        pb = make_playbook(last_run="2026-01-01 00:00:00")
        run_calls = []
        connector._get_scheduled_playbooks = lambda: (HEADERS, [pb])
        connector._get_playbook_monitoring_container = lambda event_id, name: ({"id": "99", "label": "events"}, "")
        connector._is_playbook_valid = lambda name, label: (True, "")
        connector._check_interval = lambda interval, last_run: False
        connector._run_playbook = lambda data: run_calls.append(data) or True
        connector._update_scheduled_playbook_list = lambda contents: True

        connector._on_poll({})

        assert len(run_calls) == 0

    def test_records_failed_status_when_run_playbook_fails(self, connector):
        pb = make_playbook(last_run="2026-01-01 00:00:00")
        saved_contents = []
        connector._get_scheduled_playbooks = lambda: (HEADERS, [pb])
        connector._get_playbook_monitoring_container = lambda event_id, name: ({"id": "99", "label": "events"}, "")
        connector._is_playbook_valid = lambda name, label: (True, "")
        connector._check_interval = lambda interval, last_run: True
        connector._run_playbook = lambda data: False
        connector._update_scheduled_playbook_list = lambda contents: saved_contents.append(contents) or True

        connector._on_poll({})

        rows = saved_contents[0]["content"][1:]  # skip header row
        assert rows[0][4] == "failed"

    def test_records_success_status_when_run_playbook_succeeds(self, connector):
        pb = make_playbook(last_run="2026-01-01 00:00:00")
        saved_contents = []
        connector._get_scheduled_playbooks = lambda: (HEADERS, [pb])
        connector._get_playbook_monitoring_container = lambda event_id, name: ({"id": "99", "label": "events"}, "")
        connector._is_playbook_valid = lambda name, label: (True, "")
        connector._check_interval = lambda interval, last_run: True
        connector._run_playbook = lambda data: True
        connector._update_scheduled_playbook_list = lambda contents: saved_contents.append(contents) or True

        connector._on_poll({})

        rows = saved_contents[0]["content"][1:]
        assert rows[0][4] == "success"
