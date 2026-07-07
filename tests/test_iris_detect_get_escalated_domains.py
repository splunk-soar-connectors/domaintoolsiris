"""Unit tests for _iris_detect_get_escalated_domains action."""

from tests.conftest import make_domain


class TestIrisDetectGetEscalatedDomains:

    def test_returns_success_with_results(self, connector, mock_dt_api):
        domains = [
            make_domain("evil.com", state="watched", domain_id="id1", escalations=[{"escalation_type": "google_safe", "id": "e1"}]),
            make_domain("phish.net", state="watched", domain_id="id2", escalations=[{"escalation_type": "google_safe", "id": "e2"}]),
        ]
        mock_dt_api.iris_detect_watched_domains.return_value = iter(domains)

        result = connector._iris_detect_get_escalated_domains({})
        ar = connector.last_action_result()

        assert result is True
        assert ar.get_status() is True
        assert ar.get_summary()["domain_count"] == 2
        assert len(ar.get_data()) == 2

    def test_returns_success_with_no_results(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_watched_domains.return_value = iter([])

        result = connector._iris_detect_get_escalated_domains({})
        ar = connector.last_action_result()

        assert result is True
        assert ar.get_summary()["domain_count"] == 0

    def test_always_filters_google_safe(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_watched_domains.return_value = iter([])

        connector._iris_detect_get_escalated_domains({})

        _, kwargs = mock_dt_api.iris_detect_watched_domains.call_args
        assert kwargs["escalation_types"] == ["google_safe"]

    def test_passes_additional_params(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_watched_domains.return_value = iter([])

        connector._iris_detect_get_escalated_domains({
            "monitor_id": "mon789",
            "tlds": "com",
            "risk_score_ranges": "70-99",
            "mx_exists": True,
            "discovered_since": "2026-01-01T00:00:00Z",
            "changed_since": "2026-01-02T00:00:00Z",
            "escalated_since": "2026-01-03T00:00:00Z",
            "search": "brand",
            "sort": "changed_date",
            "order": "desc",
            "include_domain_data": True,
            "limit": 20,
            "preview": False,
        })

        mock_dt_api.iris_detect_watched_domains.assert_called_once_with(
            monitor_id="mon789",
            escalation_types=["google_safe"],
            tlds="com",
            risk_score_ranges="70-99",
            mx_exists=True,
            discovered_since="2026-01-01T00:00:00Z",
            changed_since="2026-01-02T00:00:00Z",
            escalated_since="2026-01-03T00:00:00Z",
            search="brand",
            sort="changed_date",
            order="desc",
            include_domain_data=True,
            limit=20,
            preview=False,
        )

    def test_google_safe_not_overridable_by_caller(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_watched_domains.return_value = iter([])

        # caller passes nothing — escalation_types must still be ["google_safe"]
        connector._iris_detect_get_escalated_domains({"monitor_id": "mon1"})

        _, kwargs = mock_dt_api.iris_detect_watched_domains.call_args
        assert kwargs["escalation_types"] == ["google_safe"]

    def test_domain_data_stored_correctly(self, connector, mock_dt_api):
        domain = make_domain(
            "escalated.com",
            state="watched",
            risk_score=95,
            domain_id="esc1",
            escalations=[{"escalation_type": "google_safe", "id": "e99", "created": "2026-01-01T00:00:00Z"}],
        )
        mock_dt_api.iris_detect_watched_domains.return_value = iter([domain])

        connector._iris_detect_get_escalated_domains({})
        ar = connector.last_action_result()

        stored = ar.get_data()[0]
        assert stored["domain"] == "escalated.com"
        assert stored["risk_score"] == 95
        assert stored["escalations"][0]["escalation_type"] == "google_safe"

    def test_returns_error_on_api_exception(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_watched_domains.side_effect = Exception("service error")

        result = connector._iris_detect_get_escalated_domains({})
        ar = connector.last_action_result()

        assert result is False
        assert "service error" in ar.get_message()

    def test_returns_error_with_code_on_structured_exception(self, connector, mock_dt_api):
        mock_dt_api.iris_detect_watched_domains.side_effect = Exception(403, "Forbidden")

        connector._iris_detect_get_escalated_domains({})
        ar = connector.last_action_result()

        assert "403" in ar.get_message()
        assert "Forbidden" in ar.get_message()
