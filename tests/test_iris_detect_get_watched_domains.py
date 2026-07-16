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
"""Unit tests for _iris_detect_get_watched_domains action."""

from tests.conftest import make_domain


class TestIrisDetectGetWatchedDomains:
    def test_returns_success_with_results(self, connector, mock_dt_api):
        domains = [make_domain("evil.com", state="watched", domain_id="id1"), make_domain("phish.net", state="watched", domain_id="id2")]
        mock_dt_api.iris_detect_watched_domains.return_value = iter(domains)

        result = connector._iris_detect_get_watched_domains({})
        ar = connector.last_action_result()

        assert result is True
        assert ar.get_status() is True
        assert ar.get_summary()["domain_count"] == 2
        assert len(ar.get_data()) == 2

    def test_returns_success_with_no_results(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_watched_domains.return_value = iter([])

        result = connector._iris_detect_get_watched_domains({})
        ar = connector.last_action_result()

        assert result is True
        assert ar.get_summary()["domain_count"] == 0
        assert ar.get_data() == []

    def test_passes_all_params(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_watched_domains.return_value = iter([])

        connector._iris_detect_get_watched_domains(
            {
                "monitor_id": "mon123",
                "tlds": "com,net",
                "risk_score_ranges": "70-99",
                "mx_exists": True,
                "discovered_since": "2026-01-01T00:00:00Z",
                "changed_since": "2026-01-02T00:00:00Z",
                "escalated_since": "2026-01-03T00:00:00Z",
                "search": "evil",
                "sort": "risk_score",
                "order": "desc",
                "include_domain_data": True,
                "limit": 25,
                "preview": False,
            }
        )

        mock_dt_api.iris_detect_watched_domains.assert_called_once_with(
            monitor_id="mon123",
            tlds="com,net",
            risk_score_ranges="70-99",
            mx_exists=True,
            discovered_since="2026-01-01T00:00:00Z",
            changed_since="2026-01-02T00:00:00Z",
            escalated_since="2026-01-03T00:00:00Z",
            search="evil",
            sort="risk_score",
            order="desc",
            include_domain_data=True,
            limit=25,
            preview=False,
        )

    def test_passes_escalated_since(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_watched_domains.return_value = iter([])

        connector._iris_detect_get_watched_domains({"escalated_since": "2026-06-01T00:00:00Z"})

        _, kwargs = mock_dt_api.iris_detect_watched_domains.call_args
        assert kwargs["escalated_since"] == "2026-06-01T00:00:00Z"

    def test_defaults_include_domain_data_to_false(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_watched_domains.return_value = iter([])

        connector._iris_detect_get_watched_domains({})

        _, kwargs = mock_dt_api.iris_detect_watched_domains.call_args
        assert kwargs["include_domain_data"] is False

    def test_domain_data_stored_correctly(self, connector, mock_dt_api):
        domain = make_domain(
            "watched.com",
            state="watched",
            risk_score=72,
            domain_id="w1",
            escalations=[{"escalation_type": "blocked", "id": "esc1"}],
        )
        mock_dt_api.iris_detect_watched_domains.return_value = iter([domain])

        connector._iris_detect_get_watched_domains({})
        ar = connector.last_action_result()

        stored = ar.get_data()[0]
        assert stored["domain"] == "watched.com"
        assert stored["state"] == "watched"
        assert stored["risk_score"] == 72
        assert stored["escalations"][0]["escalation_type"] == "blocked"

    def test_returns_error_on_api_exception(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_watched_domains.side_effect = Exception("API unavailable")

        result = connector._iris_detect_get_watched_domains({})
        ar = connector.last_action_result()

        assert result is False
        assert "API unavailable" in ar.get_message()

    def test_returns_error_with_code_on_structured_exception(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_watched_domains.side_effect = Exception(403, "Forbidden")

        connector._iris_detect_get_watched_domains({})
        ar = connector.last_action_result()

        assert "403" in ar.get_message()
        assert "Forbidden" in ar.get_message()
