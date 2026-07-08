"""Unit tests for _domain_reputation action."""

from tests.conftest import do_query_capture_args, do_query_capture_service, do_query_failure, do_query_success


def make_investigate_response(risk_score=75, components=None):
    if components is None:
        components = [
            {"name": "proximity", "risk_score": 40},
            {"name": "phishing", "risk_score": 75},
        ]
    return {
        "domain": "evil.com",
        "domain_risk": {"risk_score": risk_score, "components": components},
        "ip": [],
        "mx": [],
        "name_server": [],
    }


class TestDomainReputation:

    def test_returns_success_and_sets_risk_score_summary(self, connector):
        connector._domains = ["evil.com"]
        connector._do_query = do_query_success(make_investigate_response(risk_score=88))

        result = connector._domain_reputation({})
        ar = connector.last_action_result()

        assert result is True
        assert ar.get_summary()["domain_risk"] == 88

    def test_sets_component_risk_scores_in_summary(self, connector):
        components = [
            {"name": "proximity", "risk_score": 30},
            {"name": "phishing", "risk_score": 80},
            {"name": "malware", "risk_score": 10},
        ]
        connector._domains = ["evil.com"]
        connector._do_query = do_query_success(make_investigate_response(components=components))

        connector._domain_reputation({})
        ar = connector.last_action_result()

        assert ar.get_summary()["proximity"] == 30
        assert ar.get_summary()["phishing"] == 80
        assert ar.get_summary()["malware"] == 10

    def test_sets_zerolisted_true_when_component_is_zerolist(self, connector):
        components = [{"name": "zerolist", "risk_score": 0}]
        connector._domains = ["evil.com"]
        connector._do_query = do_query_success(make_investigate_response(components=components))

        connector._domain_reputation({})
        ar = connector.last_action_result()

        assert ar.get_summary()["zerolisted"] is True

    def test_returns_data_list_when_do_query_fails(self, connector):
        # When _do_query fails, _domain_reputation returns action_result.get_data()
        # (an empty list), not False directly.
        connector._domains = ["evil.com"]
        connector._do_query = do_query_failure("API error")

        result = connector._domain_reputation({})
        ar = connector.last_action_result()

        assert result == []
        assert ar.get_status() is False
        assert "API error" in ar.get_message()

    def test_returns_early_when_no_data(self, connector):
        connector._domains = ["evil.com"]
        connector._do_query = do_query_success()

        result = connector._domain_reputation({})
        ar = connector.last_action_result()

        assert result is True
        assert ar.get_summary() == {}

    def test_queries_iris_investigate_service(self, connector):
        fake, calls = do_query_capture_service()
        connector._domains = ["evil.com"]
        connector._do_query = fake

        connector._domain_reputation({})

        assert calls[0] == "iris_investigate"

    def test_passes_domains_to_query(self, connector):
        fake, calls = do_query_capture_args()
        connector._domains = ["evil.com"]
        connector._do_query = fake

        connector._domain_reputation({})

        assert calls[0]["domains"] == ["evil.com"]
