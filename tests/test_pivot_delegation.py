"""
Unit tests for actions that delegate to _pivot_action.

reverse_lookup_ip, reverse_whois_email, and load_hash all follow the same
pattern: pull a value from param, set pivot_type + query_value + a key copy,
then call _pivot_action. A single parametrized class covers all three.

load_hash also has two extra edge-case tests for missing/None input that are
unique to that action and live in the LoadHash subclass below.
"""

import pytest


DELEGATION_CASES = [
    # (method,               input_param,                      pivot_type,     query_value,        preserved_key, preserved_value)
    ("_reverse_lookup_ip",   {"ip": "1.2.3.4"},                "ip",           "1.2.3.4",          "ip",          "1.2.3.4"),
    ("_reverse_whois_email", {"email": "admin@evil.com"},      "email",        "admin@evil.com",   "email",       "admin@evil.com"),
    ("_load_hash",           {"search_hash": "abc123"},        "search_hash",  "abc123",           "hash",        "abc123"),
]


@pytest.mark.parametrize("method_name,param,pivot_type,query_value,preserved_key,preserved_value", DELEGATION_CASES)
class TestPivotDelegation:

    def _fake_pivot(self):
        calls = []
        def fake(param):
            calls.append(param)
            return True
        return fake, calls

    def test_delegates_to_pivot_action(self, connector, method_name, param, pivot_type, query_value, preserved_key, preserved_value):
        fake, calls = self._fake_pivot()
        connector._pivot_action = fake

        getattr(connector, method_name)(dict(param))

        assert len(calls) == 1

    def test_sets_correct_pivot_type(self, connector, method_name, param, pivot_type, query_value, preserved_key, preserved_value):
        fake, calls = self._fake_pivot()
        connector._pivot_action = fake

        getattr(connector, method_name)(dict(param))

        assert calls[0]["pivot_type"] == pivot_type

    def test_sets_correct_query_value(self, connector, method_name, param, pivot_type, query_value, preserved_key, preserved_value):
        fake, calls = self._fake_pivot()
        connector._pivot_action = fake

        getattr(connector, method_name)(dict(param))

        assert calls[0]["query_value"] == query_value

    def test_preserves_key_in_param(self, connector, method_name, param, pivot_type, query_value, preserved_key, preserved_value):
        fake, calls = self._fake_pivot()
        connector._pivot_action = fake

        getattr(connector, method_name)(dict(param))

        assert calls[0][preserved_key] == preserved_value

    def test_returns_success_from_pivot_action(self, connector, method_name, param, pivot_type, query_value, preserved_key, preserved_value):
        connector._pivot_action = lambda p: True

        result = getattr(connector, method_name)(dict(param))

        assert result is True

    def test_returns_error_from_pivot_action(self, connector, method_name, param, pivot_type, query_value, preserved_key, preserved_value):
        connector._pivot_action = lambda p: False

        result = getattr(connector, method_name)(dict(param))

        assert result is False


class TestLoadHashEdgeCases:
    """load_hash-specific behaviour: missing or None search_hash defaults to empty string."""

    def test_empty_string_when_search_hash_missing(self, connector):
        calls = []
        connector._pivot_action = lambda p: calls.append(p) or True

        connector._load_hash({})

        assert calls[0]["query_value"] == ""
        assert calls[0]["hash"] == ""

    def test_empty_string_when_search_hash_is_none(self, connector):
        calls = []
        connector._pivot_action = lambda p: calls.append(p) or True

        connector._load_hash({"search_hash": None})

        assert calls[0]["query_value"] == ""
        assert calls[0]["hash"] == ""
