# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Unit tests for _iris_detect_get_monitors_list action."""

from tests.conftest import make_detect_page, make_monitor


class TestIrisDetectGetMonitorsList:
    def test_returns_success_with_results(self, connector, mock_dt_api):
        monitors = [make_monitor("domaintools", "mon1"), make_monitor("acme", "mon2")]
        mock_dt_api.iris_detect_monitors.return_value = make_detect_page(monitors)

        result = connector._iris_detect_get_monitors_list({})
        ar = connector.last_action_result()

        assert result is True
        assert ar.get_status() is True
        assert ar.get_summary()["monitor_count"] == 2
        assert len(ar.get_data()) == 2

    def test_returns_success_with_no_results(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_monitors.return_value = make_detect_page([])

        result = connector._iris_detect_get_monitors_list({})
        ar = connector.last_action_result()

        assert result is True
        assert ar.get_summary()["monitor_count"] == 0
        assert ar.get_data() == []

    def test_passes_sort_and_order(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_monitors.return_value = make_detect_page([])

        connector._iris_detect_get_monitors_list({"sort": "created_date", "order": "asc"})

        mock_dt_api.iris_detect_monitors.assert_called_once_with(
            offset=0,
            sort="created_date",
            order="asc",
            limit=None,
        )

    def test_default_order_is_desc(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_monitors.return_value = make_detect_page([])

        connector._iris_detect_get_monitors_list({})

        _, kwargs = mock_dt_api.iris_detect_monitors.call_args
        assert kwargs["order"] == "desc"

    def test_passes_limit(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_monitors.return_value = make_detect_page([])

        connector._iris_detect_get_monitors_list({"limit": 100})

        _, kwargs = mock_dt_api.iris_detect_monitors.call_args
        assert kwargs["limit"] == 100

    def test_passes_include_counts_with_datetime(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_monitors.return_value = make_detect_page([])

        connector._iris_detect_get_monitors_list(
            {
                "include_counts": True,
                "datetime_counts_since": "2026-01-01T00:00:00Z",
            }
        )

        mock_dt_api.iris_detect_monitors.assert_called_once_with(
            offset=0,
            sort=None,
            order="desc",
            limit=None,
            include_counts=True,
            datetime_counts_since="2026-01-01T00:00:00Z",
        )

    def test_include_counts_false_does_not_pass_datetime(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_monitors.return_value = make_detect_page([])

        connector._iris_detect_get_monitors_list({"include_counts": False})

        _, kwargs = mock_dt_api.iris_detect_monitors.call_args
        assert "include_counts" not in kwargs
        assert "datetime_counts_since" not in kwargs

    def test_monitor_data_stored_correctly(self, connector, mock_dt_api):
        monitor = make_monitor("mybrand", "mon42", state="active", status="completed", created_by="admin")
        mock_dt_api.iris_detect_monitors.return_value = make_detect_page([monitor])

        connector._iris_detect_get_monitors_list({})
        ar = connector.last_action_result()

        stored = ar.get_data()[0]
        assert stored["term"] == "mybrand"
        assert stored["id"] == "mon42"
        assert stored["state"] == "active"
        assert stored["status"] == "completed"
        assert stored["created_by"] == "admin"

    def test_summary_key_is_monitor_count(self, connector, mock_dt_api):
        monitors = [make_monitor("a", "m1"), make_monitor("b", "m2"), make_monitor("c", "m3")]
        mock_dt_api.iris_detect_monitors.return_value = make_detect_page(monitors)

        connector._iris_detect_get_monitors_list({})
        ar = connector.last_action_result()

        assert "monitor_count" in ar.get_summary()
        assert ar.get_summary()["monitor_count"] == 3

    def test_returns_error_on_api_exception(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_monitors.side_effect = Exception("API error")

        result = connector._iris_detect_get_monitors_list({})
        ar = connector.last_action_result()

        assert result is False
        assert "API error" in ar.get_message()

    def test_returns_error_with_code_on_structured_exception(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_monitors.side_effect = Exception(403, "Forbidden")

        connector._iris_detect_get_monitors_list({})
        ar = connector.last_action_result()

        assert "403" in ar.get_message()
        assert "Forbidden" in ar.get_message()
