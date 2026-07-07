"""Unit tests for _test_connectivity action."""

from unittest.mock import patch

import pytest


class TestTestConnectivity:

    def test_returns_success_when_api_query_succeeds(self, connector, mocker):
        mocker.patch.object(
            connector,
            "_do_query",
            return_value=True,
        )
        # action_result status must be APP_SUCCESS for connectivity to pass
        def fake_do_query(service, action_result, query_args=None):
            action_result.set_status(True)
            return True

        connector._do_query = fake_do_query

        result = connector._test_connectivity()

        assert result is True

    def test_returns_error_when_do_query_sets_app_error(self, connector, mocker):
        def fake_do_query(service, action_result, query_args=None):
            action_result.set_status(False, "API unreachable")
            return False

        connector._do_query = fake_do_query

        result = connector._test_connectivity()
        ar = connector.last_action_result()

        assert result is False
        assert "Failed to connect to domaintools.com" in ar.get_message()

    def test_returns_error_when_do_query_raises(self, connector, mocker):
        def fake_do_query(service, action_result, query_args=None):
            raise Exception("Connection timed out")

        connector._do_query = fake_do_query

        result = connector._test_connectivity()
        ar = connector.last_action_result()

        assert result is False
        assert "Failed to connect to domaintools.com" in ar.get_message()

    def test_queries_iris_investigate_service(self, connector):
        calls = []

        def fake_do_query(service, action_result, query_args=None):
            calls.append((service, query_args))
            action_result.set_status(True)
            return True

        connector._do_query = fake_do_query

        connector._test_connectivity()

        assert len(calls) == 1
        assert calls[0][0] == "iris_investigate"
        assert calls[0][1]["domains"] == "domaintools.net"

    def test_action_result_is_added_before_query(self, connector):
        results_before = []

        def fake_do_query(service, action_result, query_args=None):
            results_before.append(len(connector._action_results))
            action_result.set_status(True)
            return True

        connector._do_query = fake_do_query
        connector._test_connectivity()

        # action_result should have been added before _do_query was called
        assert results_before[0] == 1
