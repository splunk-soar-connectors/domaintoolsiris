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
"""Unit tests for _iris_detect_get_ignored_domains action."""

from tests.conftest import make_detect_page, make_domain


class TestIrisDetectGetIgnoredDomains:
    def test_returns_success_with_results(self, connector, mock_dt_api):
        domains = [make_domain("fp1.com", state="ignored", domain_id="id1"), make_domain("fp2.net", state="ignored", domain_id="id2")]
        mock_dt_api.iris_detect_ignored_domains.return_value = make_detect_page(domains)

        result = connector._iris_detect_get_ignored_domains({})
        ar = connector.last_action_result()

        assert result is True
        assert ar.get_status() is True
        assert ar.get_summary()["domain_count"] == 2
        assert len(ar.get_data()) == 2

    def test_returns_success_with_no_results(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_ignored_domains.return_value = make_detect_page([])

        result = connector._iris_detect_get_ignored_domains({})
        ar = connector.last_action_result()

        assert result is True
        assert ar.get_summary()["domain_count"] == 0
        assert ar.get_data() == []

    def test_passes_all_params(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_ignored_domains.return_value = make_detect_page([])

        connector._iris_detect_get_ignored_domains(
            {
                "monitor_id": "mon456",
                "tlds": "org",
                "risk_score_ranges": "1-39",
                "mx_exists": False,
                "discovered_since": "2026-01-01T00:00:00Z",
                "changed_since": "2026-01-02T00:00:00Z",
                "escalated_since": "2026-01-03T00:00:00Z",
                "search": "false-positive",
                "sort": "discovered_date",
                "order": "asc",
                "include_domain_data": False,
                "limit": 10,
                "preview": True,
            }
        )

        mock_dt_api.iris_detect_ignored_domains.assert_called_once_with(
            monitor_id="mon456",
            tlds=["org"],
            risk_score_ranges=["1-39"],
            mx_exists=False,
            discovered_since="2026-01-01T00:00:00Z",
            changed_since="2026-01-02T00:00:00Z",
            escalated_since="2026-01-03T00:00:00Z",
            search="false-positive",
            sort="discovered_date",
            order="asc",
            include_domain_data=False,
            offset=0,
            limit=10,
            preview=True,
        )

    def test_passes_escalated_since(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_ignored_domains.return_value = make_detect_page([])

        connector._iris_detect_get_ignored_domains({"escalated_since": "2026-05-01T00:00:00Z"})

        _, kwargs = mock_dt_api.iris_detect_ignored_domains.call_args
        assert kwargs["escalated_since"] == "2026-05-01T00:00:00Z"

    def test_defaults_include_domain_data_to_false(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_ignored_domains.return_value = make_detect_page([])

        connector._iris_detect_get_ignored_domains({})

        _, kwargs = mock_dt_api.iris_detect_ignored_domains.call_args
        assert kwargs["include_domain_data"] is False

    def test_domain_data_stored_correctly(self, connector, mock_dt_api):
        domain = make_domain("ignored.com", state="ignored", risk_score=15, domain_id="ig1", tld="com")
        mock_dt_api.iris_detect_ignored_domains.return_value = make_detect_page([domain])

        connector._iris_detect_get_ignored_domains({})
        ar = connector.last_action_result()

        stored = ar.get_data()[0]
        assert stored["domain"] == "ignored.com"
        assert stored["state"] == "ignored"
        assert stored["risk_score"] == 15
        assert stored["id"] == "ig1"

    def test_returns_error_on_api_exception(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_ignored_domains.side_effect = Exception("connection timeout")

        result = connector._iris_detect_get_ignored_domains({})
        ar = connector.last_action_result()

        assert result is False
        assert "connection timeout" in ar.get_message()

    def test_returns_error_with_code_on_structured_exception(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_ignored_domains.side_effect = Exception(401, "Unauthorized")

        connector._iris_detect_get_ignored_domains({})
        ar = connector.last_action_result()

        assert "401" in ar.get_message()
        assert "Unauthorized" in ar.get_message()
