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
"""Unit tests for _iris_detect_get_blocklist_domains action."""

from tests.conftest import make_detect_page, make_domain


class TestIrisDetectGetBlocklistDomains:
    def test_returns_success_with_results(self, connector, mock_dt_api):
        domains = [
            make_domain("block1.com", state="watched", domain_id="id1", escalations=[{"escalation_type": "blocked", "id": "b1"}]),
            make_domain("block2.net", state="watched", domain_id="id2", escalations=[{"escalation_type": "blocked", "id": "b2"}]),
        ]
        mock_dt_api.iris_detect_watched_domains.return_value = make_detect_page(domains)

        result = connector._iris_detect_get_blocklist_domains({})
        ar = connector.last_action_result()

        assert result is True
        assert ar.get_status() is True
        assert ar.get_summary()["domain_count"] == 2
        assert len(ar.get_data()) == 2

    def test_returns_success_with_no_results(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_watched_domains.return_value = make_detect_page([])

        result = connector._iris_detect_get_blocklist_domains({})
        ar = connector.last_action_result()

        assert result is True
        assert ar.get_summary()["domain_count"] == 0

    def test_always_filters_blocked(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_watched_domains.return_value = make_detect_page([])

        connector._iris_detect_get_blocklist_domains({})

        _, kwargs = mock_dt_api.iris_detect_watched_domains.call_args
        assert kwargs["escalation_types"] == ["blocked"]

    def test_blocked_not_overridable_by_caller(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_watched_domains.return_value = make_detect_page([])

        connector._iris_detect_get_blocklist_domains({"monitor_id": "mon1"})

        _, kwargs = mock_dt_api.iris_detect_watched_domains.call_args
        assert kwargs["escalation_types"] == ["blocked"]

    def test_passes_additional_params(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_watched_domains.return_value = make_detect_page([])

        connector._iris_detect_get_blocklist_domains(
            {
                "monitor_id": "mon999",
                "tlds": "io",
                "risk_score_ranges": "100-100",
                "mx_exists": False,
                "discovered_since": "2026-02-01T00:00:00Z",
                "changed_since": "2026-02-02T00:00:00Z",
                "escalated_since": "2026-02-03T00:00:00Z",
                "search": "threat",
                "sort": "risk_score",
                "order": "desc",
                "include_domain_data": True,
                "limit": 50,
                "preview": False,
            }
        )

        mock_dt_api.iris_detect_watched_domains.assert_called_once_with(
            monitor_id="mon999",
            escalation_types=["blocked"],
            tlds=["io"],
            risk_score_ranges=["100-100"],
            mx_exists=False,
            discovered_since="2026-02-01T00:00:00Z",
            changed_since="2026-02-02T00:00:00Z",
            escalated_since="2026-02-03T00:00:00Z",
            search="threat",
            sort="risk_score",
            order="desc",
            include_domain_data=True,
            offset=0,
            limit=50,
            preview=False,
        )

    def test_domain_data_stored_correctly(self, connector, mock_dt_api):
        domain = make_domain(
            "blocked.com",
            state="watched",
            risk_score=100,
            domain_id="blk1",
            escalations=[{"escalation_type": "blocked", "id": "b99", "created": "2026-01-01T00:00:00Z"}],
        )
        mock_dt_api.iris_detect_watched_domains.return_value = make_detect_page([domain])

        connector._iris_detect_get_blocklist_domains({})
        ar = connector.last_action_result()

        stored = ar.get_data()[0]
        assert stored["domain"] == "blocked.com"
        assert stored["risk_score"] == 100
        assert stored["escalations"][0]["escalation_type"] == "blocked"

    def test_returns_error_on_api_exception(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_watched_domains.side_effect = Exception("network error")

        result = connector._iris_detect_get_blocklist_domains({})
        ar = connector.last_action_result()

        assert result is False
        assert "network error" in ar.get_message()

    def test_returns_error_with_code_on_structured_exception(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_watched_domains.side_effect = Exception(401, "Unauthorized")

        connector._iris_detect_get_blocklist_domains({})
        ar = connector.last_action_result()

        assert "401" in ar.get_message()
        assert "Unauthorized" in ar.get_message()
