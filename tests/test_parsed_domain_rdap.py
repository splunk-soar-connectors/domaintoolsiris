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
"""Unit tests for _parsed_domain_rdap action."""

from tests.conftest import do_query_capture_args, do_query_capture_service, do_query_failure, do_query_success


class TestParsedDomainRdap:
    def test_returns_success_with_results(self, connector):
        connector._do_query = do_query_success({"registrant": "ACME Corp"})

        result = connector._parsed_domain_rdap({"domain": "evil.com"})
        ar = connector.last_action_result()

        assert result is True
        assert len(ar.get_data()) == 1

    def test_returns_data_list_when_do_query_fails(self, connector):
        connector._do_query = do_query_failure("RDAP API error")

        result = connector._parsed_domain_rdap({"domain": "evil.com"})
        ar = connector.last_action_result()

        assert result == []
        assert ar.get_status() is False

    def test_queries_parsed_domain_rdap_service(self, connector):
        fake, calls = do_query_capture_service()
        connector._do_query = fake

        connector._parsed_domain_rdap({"domain": "evil.com"})

        assert calls[0] == "parsed_domain_rdap"

    def test_passes_domain_as_query_param(self, connector):
        fake, calls = do_query_capture_args()
        connector._do_query = fake

        connector._parsed_domain_rdap({"domain": "evil.com"})

        assert calls[0]["query"] == "evil.com"

    def test_passes_none_when_domain_not_provided(self, connector):
        fake, calls = do_query_capture_args()
        connector._do_query = fake

        connector._parsed_domain_rdap({})

        assert calls[0]["query"] is None
