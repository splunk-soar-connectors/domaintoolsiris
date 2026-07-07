"""Unit tests for _domain_enrich action."""

from tests.conftest import do_query_capture_args, do_query_capture_service, do_query_failure, do_query_success


class TestDomainEnrich:

    def test_returns_success_with_results(self, connector):
        connector._domains = ["evil.com"]
        connector._do_query = do_query_success({"domain": "evil.com"})

        result = connector._domain_enrich({})
        ar = connector.last_action_result()

        assert result is True
        assert ar.get_status() is True
        assert len(ar.get_data()) == 1

    def test_returns_error_when_do_query_fails(self, connector):
        connector._domains = ["evil.com"]
        connector._do_query = do_query_failure("enrich API failure")

        result = connector._domain_enrich({})
        ar = connector.last_action_result()

        assert result is False
        assert "enrich API failure" in ar.get_message()

    def test_queries_iris_enrich_service(self, connector):
        fake, calls = do_query_capture_service()
        connector._domains = ["evil.com"]
        connector._do_query = fake

        connector._domain_enrich({})

        assert calls[0] == "iris_enrich"

    def test_joins_multiple_domains_as_csv(self, connector):
        fake, calls = do_query_capture_args()
        connector._domains = ["evil.com", "phish.net"]
        connector._do_query = fake

        connector._domain_enrich({})

        assert calls[0]["domains"] == "evil.com,phish.net"

    def test_single_domain_passed_without_comma(self, connector):
        fake, calls = do_query_capture_args()
        connector._domains = ["evil.com"]
        connector._do_query = fake

        connector._domain_enrich({})

        assert calls[0]["domains"] == "evil.com"

    def test_returns_error_when_do_query_raises(self, connector):
        def fake_do_query(service, action_result, query_args=None):
            raise Exception("timeout")

        connector._domains = ["evil.com"]
        connector._do_query = fake_do_query

        try:
            connector._domain_enrich({})
        except Exception:
            pass

        ar = connector.last_action_result()
        assert ar.get_status() is not True
