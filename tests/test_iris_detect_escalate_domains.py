"""Unit tests for _iris_detect_escalate_domains action."""

from tests.conftest import make_escalation


class TestIrisDetectEscalateDomains:

    def test_returns_success_with_results(self, connector, mock_dt_api):
        escalations = [make_escalation("id1", "google_safe", "e1"), make_escalation("id2", "google_safe", "e2")]
        mock_dt_api.iris_detect_escalate_domains.return_value = iter(escalations)

        result = connector._iris_detect_escalate_domains({"watchlist_domain_ids": "id1,id2"})
        ar = connector.last_action_result()

        assert result is True
        assert ar.get_status() is True
        assert ar.get_summary()["escalated_count"] == 2
        assert len(ar.get_data()) == 2

    def test_returns_success_with_single_id(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_escalate_domains.return_value = iter([make_escalation("id1", "google_safe", "e1")])

        result = connector._iris_detect_escalate_domains({"watchlist_domain_ids": "id1"})
        ar = connector.last_action_result()

        assert result is True
        assert ar.get_summary()["escalated_count"] == 1

    def test_always_uses_google_safe_escalation_type(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_escalate_domains.return_value = iter([])

        connector._iris_detect_escalate_domains({"watchlist_domain_ids": "id1"})

        _, kwargs = mock_dt_api.iris_detect_escalate_domains.call_args
        assert kwargs["escalation_type"] == "google_safe"

    def test_passes_single_domain_id_as_list(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_escalate_domains.return_value = iter([])

        connector._iris_detect_escalate_domains({"watchlist_domain_ids": "abc123"})

        _, kwargs = mock_dt_api.iris_detect_escalate_domains.call_args
        assert kwargs["watchlist_domain_ids"] == ["abc123"]

    def test_passes_multiple_domain_ids_as_list(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_escalate_domains.return_value = iter([])

        connector._iris_detect_escalate_domains({"watchlist_domain_ids": "id1,id2,id3"})

        _, kwargs = mock_dt_api.iris_detect_escalate_domains.call_args
        assert kwargs["watchlist_domain_ids"] == ["id1", "id2", "id3"]

    def test_strips_spaces_from_domain_ids(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_escalate_domains.return_value = iter([])

        connector._iris_detect_escalate_domains({"watchlist_domain_ids": "id1, id2, id3"})

        _, kwargs = mock_dt_api.iris_detect_escalate_domains.call_args
        assert kwargs["watchlist_domain_ids"] == ["id1", "id2", "id3"]

    def test_escalation_data_stored_correctly(self, connector, mock_dt_api):
        escalation = make_escalation("dom1", "google_safe", "esc99")
        mock_dt_api.iris_detect_escalate_domains.return_value = iter([escalation])

        connector._iris_detect_escalate_domains({"watchlist_domain_ids": "dom1"})
        ar = connector.last_action_result()

        stored = ar.get_data()[0]
        assert stored["watchlist_domain_id"] == "dom1"
        assert stored["escalation_type"] == "google_safe"
        assert stored["id"] == "esc99"

    def test_summary_key_is_escalated_count(self, connector, mock_dt_api):
        escalations = [make_escalation(f"id{i}", "google_safe", f"e{i}") for i in range(3)]
        mock_dt_api.iris_detect_escalate_domains.return_value = iter(escalations)

        connector._iris_detect_escalate_domains({"watchlist_domain_ids": "id0,id1,id2"})
        ar = connector.last_action_result()

        assert "escalated_count" in ar.get_summary()
        assert ar.get_summary()["escalated_count"] == 3

    def test_returns_error_on_api_exception(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_escalate_domains.side_effect = Exception("API error")

        result = connector._iris_detect_escalate_domains({"watchlist_domain_ids": "id1"})
        ar = connector.last_action_result()

        assert result is False
        assert "API error" in ar.get_message()

    def test_returns_error_with_code_on_structured_exception(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_escalate_domains.side_effect = Exception(403, "Forbidden")

        connector._iris_detect_escalate_domains({"watchlist_domain_ids": "id1"})
        ar = connector.last_action_result()

        assert "403" in ar.get_message()
        assert "Forbidden" in ar.get_message()
