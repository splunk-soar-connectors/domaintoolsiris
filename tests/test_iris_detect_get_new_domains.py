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
"""Unit tests for _iris_detect_get_new_domains action."""

from tests.conftest import make_domain


class TestIrisDetectGetNewDomains:
    def test_returns_success_with_results(self, connector, mock_dt_api):
        domains = [make_domain("evil.com", domain_id="id1"), make_domain("phish.net", domain_id="id2")]
        mock_dt_api.iris_detect_new_domains.return_value = iter(domains)

        result = connector._iris_detect_get_new_domains({})
        ar = connector.last_action_result()

        assert result is True
        assert ar.get_status() is True
        assert ar.get_summary()["domain_count"] == 2
        assert len(ar.get_data()) == 2

    def test_returns_success_with_no_results(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_new_domains.return_value = iter([])

        result = connector._iris_detect_get_new_domains({})
        ar = connector.last_action_result()

        assert result is True
        assert ar.get_summary()["domain_count"] == 0
        assert ar.get_data() == []

    def test_passes_monitor_id(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_new_domains.return_value = iter([])

        connector._iris_detect_get_new_domains({"monitor_id": "mon123"})

        mock_dt_api.iris_detect_new_domains.assert_called_once_with(
            monitor_id="mon123",
            tlds=None,
            risk_score_ranges=None,
            mx_exists=None,
            discovered_since=None,
            changed_since=None,
            search=None,
            sort=None,
            order=None,
            include_domain_data=False,
            limit=None,
            preview=None,
        )

    def test_passes_discovered_since(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_new_domains.return_value = iter([])

        connector._iris_detect_get_new_domains({"discovered_since": "2026-01-01T00:00:00Z"})

        _, kwargs = mock_dt_api.iris_detect_new_domains.call_args
        assert kwargs["discovered_since"] == "2026-01-01T00:00:00Z"

    def test_passes_risk_score_ranges(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_new_domains.return_value = iter([])

        connector._iris_detect_get_new_domains({"risk_score_ranges": "70-99,100-100"})

        _, kwargs = mock_dt_api.iris_detect_new_domains.call_args
        assert kwargs["risk_score_ranges"] == "70-99,100-100"

    def test_passes_include_domain_data(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_new_domains.return_value = iter([])

        connector._iris_detect_get_new_domains({"include_domain_data": True})

        _, kwargs = mock_dt_api.iris_detect_new_domains.call_args
        assert kwargs["include_domain_data"] is True

    def test_passes_preview(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_new_domains.return_value = iter([])

        connector._iris_detect_get_new_domains({"preview": True})

        _, kwargs = mock_dt_api.iris_detect_new_domains.call_args
        assert kwargs["preview"] is True

    def test_passes_limit(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_new_domains.return_value = iter([])

        connector._iris_detect_get_new_domains({"limit": 50})

        _, kwargs = mock_dt_api.iris_detect_new_domains.call_args
        assert kwargs["limit"] == 50

    def test_passes_sort_and_order(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_new_domains.return_value = iter([])

        connector._iris_detect_get_new_domains({"sort": "risk_score", "order": "desc"})

        _, kwargs = mock_dt_api.iris_detect_new_domains.call_args
        assert kwargs["sort"] == "risk_score"
        assert kwargs["order"] == "desc"

    def test_domain_data_stored_correctly(self, connector, mock_dt_api):
        domain = make_domain("evil.com", risk_score=99, domain_id="xyz", state="new")
        mock_dt_api.iris_detect_new_domains.return_value = iter([domain])

        connector._iris_detect_get_new_domains({})
        ar = connector.last_action_result()

        stored = ar.get_data()[0]
        assert stored["domain"] == "evil.com"
        assert stored["risk_score"] == 99
        assert stored["id"] == "xyz"
        assert stored["state"] == "new"

    def test_returns_error_on_api_exception(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_new_domains.side_effect = Exception("API unavailable")

        result = connector._iris_detect_get_new_domains({})
        ar = connector.last_action_result()

        assert result is False
        assert "API unavailable" in ar.get_message()

    def test_returns_error_with_code_on_structured_exception(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_new_domains.side_effect = Exception(401, "Unauthorized")

        connector._iris_detect_get_new_domains({})
        ar = connector.last_action_result()

        assert "401" in ar.get_message()
        assert "Unauthorized" in ar.get_message()
