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
"""Unit tests for _domain_investigate action."""

from tests.conftest import do_query_capture_args, do_query_capture_service, do_query_failure, do_query_success


class TestDomainInvestigate:
    def test_returns_success_with_results(self, connector):
        connector._domains = ["evil.com"]
        connector._do_query = do_query_success({"domain": "evil.com", "domain_risk": {"risk_score": 90}})

        result = connector._domain_investigate({})
        ar = connector.last_action_result()

        assert result is True
        assert ar.get_status() is True
        assert len(ar.get_data()) == 1

    def test_returns_error_when_do_query_fails(self, connector):
        connector._domains = ["evil.com"]
        connector._do_query = do_query_failure("API failure")

        result = connector._domain_investigate({})
        ar = connector.last_action_result()

        assert result is False
        assert "API failure" in ar.get_message()

    def test_queries_iris_investigate_service(self, connector):
        fake, calls = do_query_capture_service()
        connector._domains = ["evil.com"]
        connector._do_query = fake

        connector._domain_investigate({})

        assert calls[0] == "iris_investigate"

    def test_passes_domains_to_query(self, connector):
        fake, calls = do_query_capture_args()
        connector._domains = ["evil.com", "phish.net"]
        connector._do_query = fake

        connector._domain_investigate({})

        assert calls[0]["domains"] == ["evil.com", "phish.net"]

    def test_returns_error_when_do_query_raises(self, connector):
        def fake_do_query(service, action_result, query_args=None):
            raise Exception("connection refused")

        connector._domains = ["evil.com"]
        connector._do_query = fake_do_query

        try:
            connector._domain_investigate({})
        except Exception:
            pass

        ar = connector.last_action_result()
        assert ar.get_status() is not True
