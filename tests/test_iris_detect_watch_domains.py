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
"""Unit tests for _iris_detect_watch_domains action."""

from tests.conftest import make_domain


class TestIrisDetectWatchDomains:
    def test_returns_success_with_results(self, connector, mock_dt_api):
        domains = [make_domain("watch1.com", state="watched", domain_id="id1"), make_domain("watch2.net", state="watched", domain_id="id2")]
        mock_dt_api.iris_detect_manage_watchlist_domains.return_value = iter(domains)

        result = connector._iris_detect_watch_domains({"watchlist_domain_ids": "id1,id2"})
        ar = connector.last_action_result()

        assert result is True
        assert ar.get_status() is True
        assert ar.get_summary()["watched_count"] == 2
        assert len(ar.get_data()) == 2

    def test_returns_success_with_single_id(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_manage_watchlist_domains.return_value = iter([make_domain("watch1.com", state="watched", domain_id="id1")])

        result = connector._iris_detect_watch_domains({"watchlist_domain_ids": "id1"})
        ar = connector.last_action_result()

        assert result is True
        assert ar.get_summary()["watched_count"] == 1

    def test_always_uses_watched_state(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_manage_watchlist_domains.return_value = iter([])

        connector._iris_detect_watch_domains({"watchlist_domain_ids": "id1"})

        _, kwargs = mock_dt_api.iris_detect_manage_watchlist_domains.call_args
        assert kwargs["state"] == "watched"

    def test_state_is_not_ignored(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_manage_watchlist_domains.return_value = iter([])

        connector._iris_detect_watch_domains({"watchlist_domain_ids": "id1"})

        _, kwargs = mock_dt_api.iris_detect_manage_watchlist_domains.call_args
        assert kwargs["state"] != "ignored"

    def test_passes_single_domain_id_as_list(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_manage_watchlist_domains.return_value = iter([])

        connector._iris_detect_watch_domains({"watchlist_domain_ids": "abc123"})

        _, kwargs = mock_dt_api.iris_detect_manage_watchlist_domains.call_args
        assert kwargs["watchlist_domain_ids"] == ["abc123"]

    def test_passes_multiple_domain_ids_as_list(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_manage_watchlist_domains.return_value = iter([])

        connector._iris_detect_watch_domains({"watchlist_domain_ids": "id1,id2,id3"})

        _, kwargs = mock_dt_api.iris_detect_manage_watchlist_domains.call_args
        assert kwargs["watchlist_domain_ids"] == ["id1", "id2", "id3"]

    def test_strips_spaces_from_domain_ids(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_manage_watchlist_domains.return_value = iter([])

        connector._iris_detect_watch_domains({"watchlist_domain_ids": "id1, id2, id3"})

        _, kwargs = mock_dt_api.iris_detect_manage_watchlist_domains.call_args
        assert kwargs["watchlist_domain_ids"] == ["id1", "id2", "id3"]

    def test_domain_data_stored_correctly(self, connector, mock_dt_api):
        domain = make_domain("watched.com", state="watched", domain_id="w99", discovered_date="2026-01-01T00:00:00Z")
        mock_dt_api.iris_detect_manage_watchlist_domains.return_value = iter([domain])

        connector._iris_detect_watch_domains({"watchlist_domain_ids": "w99"})
        ar = connector.last_action_result()

        stored = ar.get_data()[0]
        assert stored["domain"] == "watched.com"
        assert stored["state"] == "watched"
        assert stored["id"] == "w99"
        assert stored["discovered_date"] == "2026-01-01T00:00:00Z"

    def test_summary_key_is_watched_count(self, connector, mock_dt_api):
        domains = [make_domain(f"d{i}.com", state="watched", domain_id=f"id{i}") for i in range(5)]
        mock_dt_api.iris_detect_manage_watchlist_domains.return_value = iter(domains)

        connector._iris_detect_watch_domains({"watchlist_domain_ids": "id0,id1,id2,id3,id4"})
        ar = connector.last_action_result()

        assert "watched_count" in ar.get_summary()
        assert ar.get_summary()["watched_count"] == 5

    def test_returns_error_on_api_exception(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_manage_watchlist_domains.side_effect = Exception("service unavailable")

        result = connector._iris_detect_watch_domains({"watchlist_domain_ids": "id1"})
        ar = connector.last_action_result()

        assert result is False
        assert "service unavailable" in ar.get_message()

    def test_returns_error_with_code_on_structured_exception(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_manage_watchlist_domains.side_effect = Exception(403, "Forbidden")

        connector._iris_detect_watch_domains({"watchlist_domain_ids": "id1"})
        ar = connector.last_action_result()

        assert "403" in ar.get_message()
        assert "Forbidden" in ar.get_message()
