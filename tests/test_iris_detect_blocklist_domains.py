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
"""Unit tests for _iris_detect_blocklist_domains action."""

from tests.conftest import make_escalation


class TestIrisDetectBlocklistDomains:
    def test_returns_success_with_results(self, connector, mock_dt_api):
        escalations = [make_escalation("id1", "blocked", "b1"), make_escalation("id2", "blocked", "b2")]
        mock_dt_api.iris_detect_escalate_domains.return_value = iter(escalations)

        result = connector._iris_detect_blocklist_domains({"watchlist_domain_ids": "id1,id2"})
        ar = connector.last_action_result()

        assert result is True
        assert ar.get_status() is True
        assert ar.get_summary()["blocklisted_count"] == 2
        assert len(ar.get_data()) == 2

    def test_returns_success_with_single_id(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_escalate_domains.return_value = iter([make_escalation("id1", "blocked", "b1")])

        result = connector._iris_detect_blocklist_domains({"watchlist_domain_ids": "id1"})
        ar = connector.last_action_result()

        assert result is True
        assert ar.get_summary()["blocklisted_count"] == 1

    def test_always_uses_blocked_escalation_type(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_escalate_domains.return_value = iter([])

        connector._iris_detect_blocklist_domains({"watchlist_domain_ids": "id1"})

        _, kwargs = mock_dt_api.iris_detect_escalate_domains.call_args
        assert kwargs["escalation_type"] == "blocked"

    def test_passes_single_domain_id_as_list(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_escalate_domains.return_value = iter([])

        connector._iris_detect_blocklist_domains({"watchlist_domain_ids": "abc123"})

        _, kwargs = mock_dt_api.iris_detect_escalate_domains.call_args
        assert kwargs["watchlist_domain_ids"] == ["abc123"]

    def test_passes_multiple_domain_ids_as_list(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_escalate_domains.return_value = iter([])

        connector._iris_detect_blocklist_domains({"watchlist_domain_ids": "id1,id2,id3"})

        _, kwargs = mock_dt_api.iris_detect_escalate_domains.call_args
        assert kwargs["watchlist_domain_ids"] == ["id1", "id2", "id3"]

    def test_strips_spaces_from_domain_ids(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_escalate_domains.return_value = iter([])

        connector._iris_detect_blocklist_domains({"watchlist_domain_ids": "id1, id2, id3"})

        _, kwargs = mock_dt_api.iris_detect_escalate_domains.call_args
        assert kwargs["watchlist_domain_ids"] == ["id1", "id2", "id3"]

    def test_blocklist_data_stored_correctly(self, connector, mock_dt_api):
        escalation = make_escalation("dom1", "blocked", "blk99")
        mock_dt_api.iris_detect_escalate_domains.return_value = iter([escalation])

        connector._iris_detect_blocklist_domains({"watchlist_domain_ids": "dom1"})
        ar = connector.last_action_result()

        stored = ar.get_data()[0]
        assert stored["watchlist_domain_id"] == "dom1"
        assert stored["escalation_type"] == "blocked"
        assert stored["id"] == "blk99"

    def test_summary_key_is_blocklisted_count(self, connector, mock_dt_api):
        escalations = [make_escalation(f"id{i}", "blocked", f"b{i}") for i in range(4)]
        mock_dt_api.iris_detect_escalate_domains.return_value = iter(escalations)

        connector._iris_detect_blocklist_domains({"watchlist_domain_ids": "id0,id1,id2,id3"})
        ar = connector.last_action_result()

        assert "blocklisted_count" in ar.get_summary()
        assert ar.get_summary()["blocklisted_count"] == 4

    def test_blocked_not_same_as_google_safe(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_escalate_domains.return_value = iter([])

        connector._iris_detect_blocklist_domains({"watchlist_domain_ids": "id1"})

        _, kwargs = mock_dt_api.iris_detect_escalate_domains.call_args
        assert kwargs["escalation_type"] != "google_safe"

    def test_returns_error_on_api_exception(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_escalate_domains.side_effect = Exception("timeout")

        result = connector._iris_detect_blocklist_domains({"watchlist_domain_ids": "id1"})
        ar = connector.last_action_result()

        assert result is False
        assert "timeout" in ar.get_message()

    def test_returns_error_with_code_on_structured_exception(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_escalate_domains.side_effect = Exception(401, "Unauthorized")

        connector._iris_detect_blocklist_domains({"watchlist_domain_ids": "id1"})
        ar = connector.last_action_result()

        assert "401" in ar.get_message()
        assert "Unauthorized" in ar.get_message()
