"""Unit tests for _iris_detect_ignore_domains action."""

from tests.conftest import make_domain


class TestIrisDetectIgnoreDomains:

    def test_returns_success_with_results(self, connector, mock_dt_api):
        domains = [make_domain("fp1.com", state="ignored", domain_id="id1"), make_domain("fp2.net", state="ignored", domain_id="id2")]
        mock_dt_api.iris_detect_manage_watchlist_domains.return_value = iter(domains)

        result = connector._iris_detect_ignore_domains({"watchlist_domain_ids": "id1,id2"})
        ar = connector.last_action_result()

        assert result is True
        assert ar.get_status() is True
        assert ar.get_summary()["ignored_count"] == 2
        assert len(ar.get_data()) == 2

    def test_returns_success_with_single_id(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_manage_watchlist_domains.return_value = iter([make_domain("fp1.com", state="ignored", domain_id="id1")])

        result = connector._iris_detect_ignore_domains({"watchlist_domain_ids": "id1"})
        ar = connector.last_action_result()

        assert result is True
        assert ar.get_summary()["ignored_count"] == 1

    def test_always_uses_ignored_state(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_manage_watchlist_domains.return_value = iter([])

        connector._iris_detect_ignore_domains({"watchlist_domain_ids": "id1"})

        _, kwargs = mock_dt_api.iris_detect_manage_watchlist_domains.call_args
        assert kwargs["state"] == "ignored"

    def test_state_is_not_watched(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_manage_watchlist_domains.return_value = iter([])

        connector._iris_detect_ignore_domains({"watchlist_domain_ids": "id1"})

        _, kwargs = mock_dt_api.iris_detect_manage_watchlist_domains.call_args
        assert kwargs["state"] != "watched"

    def test_passes_single_domain_id_as_list(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_manage_watchlist_domains.return_value = iter([])

        connector._iris_detect_ignore_domains({"watchlist_domain_ids": "abc123"})

        _, kwargs = mock_dt_api.iris_detect_manage_watchlist_domains.call_args
        assert kwargs["watchlist_domain_ids"] == ["abc123"]

    def test_passes_multiple_domain_ids_as_list(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_manage_watchlist_domains.return_value = iter([])

        connector._iris_detect_ignore_domains({"watchlist_domain_ids": "id1,id2,id3"})

        _, kwargs = mock_dt_api.iris_detect_manage_watchlist_domains.call_args
        assert kwargs["watchlist_domain_ids"] == ["id1", "id2", "id3"]

    def test_strips_spaces_from_domain_ids(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_manage_watchlist_domains.return_value = iter([])

        connector._iris_detect_ignore_domains({"watchlist_domain_ids": "id1, id2, id3"})

        _, kwargs = mock_dt_api.iris_detect_manage_watchlist_domains.call_args
        assert kwargs["watchlist_domain_ids"] == ["id1", "id2", "id3"]

    def test_domain_data_stored_correctly(self, connector, mock_dt_api):
        domain = make_domain("ignored.com", state="ignored", domain_id="ig99", discovered_date="2026-01-01T00:00:00Z")
        mock_dt_api.iris_detect_manage_watchlist_domains.return_value = iter([domain])

        connector._iris_detect_ignore_domains({"watchlist_domain_ids": "ig99"})
        ar = connector.last_action_result()

        stored = ar.get_data()[0]
        assert stored["domain"] == "ignored.com"
        assert stored["state"] == "ignored"
        assert stored["id"] == "ig99"
        assert stored["discovered_date"] == "2026-01-01T00:00:00Z"

    def test_summary_key_is_ignored_count(self, connector, mock_dt_api):
        domains = [make_domain(f"fp{i}.com", state="ignored", domain_id=f"id{i}") for i in range(3)]
        mock_dt_api.iris_detect_manage_watchlist_domains.return_value = iter(domains)

        connector._iris_detect_ignore_domains({"watchlist_domain_ids": "id0,id1,id2"})
        ar = connector.last_action_result()

        assert "ignored_count" in ar.get_summary()
        assert ar.get_summary()["ignored_count"] == 3

    def test_returns_error_on_api_exception(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_manage_watchlist_domains.side_effect = Exception("connection refused")

        result = connector._iris_detect_ignore_domains({"watchlist_domain_ids": "id1"})
        ar = connector.last_action_result()

        assert result is False
        assert "connection refused" in ar.get_message()

    def test_returns_error_with_code_on_structured_exception(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_manage_watchlist_domains.side_effect = Exception(401, "Unauthorized")

        connector._iris_detect_ignore_domains({"watchlist_domain_ids": "id1"})
        ar = connector.last_action_result()

        assert "401" in ar.get_message()
        assert "Unauthorized" in ar.get_message()
