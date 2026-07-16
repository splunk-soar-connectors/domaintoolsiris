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
"""Unit tests for _reverse_lookup_domain action."""

from tests.conftest import do_query_capture_service, do_query_failure, do_query_success


def make_domain_response(host_ips=None, mx_ips=None, ns_ips=None):
    return {
        "domain": "evil.com",
        "ip": host_ips or [],
        "mx": mx_ips or [],
        "name_server": ns_ips or [],
    }


class TestReverseLookupDomain:
    def test_returns_success_with_no_ips(self, connector):
        connector._domains = ["evil.com"]
        connector._do_query = do_query_success(make_domain_response())

        result = connector._reverse_lookup_domain({})
        ar = connector.last_action_result()

        assert result is True
        assert ar.get_summary()["ip_list"] == []

    def test_extracts_host_ips_into_summary(self, connector):
        host_ips = [{"address": {"value": "1.2.3.4", "count": 100}}]
        connector._domains = ["evil.com"]
        connector._do_query = do_query_success(make_domain_response(host_ips=host_ips))

        connector._reverse_lookup_domain({})
        ar = connector.last_action_result()

        ip_list = ar.get_summary()["ip_list"]
        assert len(ip_list) == 1
        assert ip_list[0]["ip"] == "1.2.3.4"
        assert ip_list[0]["type"] == "Host IP"
        assert ip_list[0]["count"] == 100

    def test_extracts_mx_ips_into_summary(self, connector):
        mx_ips = [{"ip": [{"value": "5.6.7.8", "count": 50}]}]
        connector._domains = ["evil.com"]
        connector._do_query = do_query_success(make_domain_response(mx_ips=mx_ips))

        connector._reverse_lookup_domain({})
        ar = connector.last_action_result()

        ip_list = ar.get_summary()["ip_list"]
        assert len(ip_list) == 1
        assert ip_list[0]["ip"] == "5.6.7.8"
        assert ip_list[0]["type"] == "MX IP"

    def test_extracts_ns_ips_into_summary(self, connector):
        ns_ips = [{"ip": [{"value": "9.10.11.12", "count": 25}]}]
        connector._domains = ["evil.com"]
        connector._do_query = do_query_success(make_domain_response(ns_ips=ns_ips))

        connector._reverse_lookup_domain({})
        ar = connector.last_action_result()

        ip_list = ar.get_summary()["ip_list"]
        assert len(ip_list) == 1
        assert ip_list[0]["ip"] == "9.10.11.12"
        assert ip_list[0]["type"] == "NS IP"

    def test_ip_list_sorted_descending_by_count(self, connector):
        host_ips = [
            {"address": {"value": "1.1.1.1", "count": 10}},
            {"address": {"value": "2.2.2.2", "count": 200}},
            {"address": {"value": "3.3.3.3", "count": 50}},
        ]
        connector._domains = ["evil.com"]
        connector._do_query = do_query_success(make_domain_response(host_ips=host_ips))

        connector._reverse_lookup_domain({})
        ar = connector.last_action_result()

        ip_list = ar.get_summary()["ip_list"]
        counts = [entry["count"] for entry in ip_list]
        assert counts == sorted(counts, reverse=True)

    def test_null_count_sorted_last(self, connector):
        host_ips = [
            {"address": {"value": "1.1.1.1", "count": None}},
            {"address": {"value": "2.2.2.2", "count": 100}},
        ]
        connector._domains = ["evil.com"]
        connector._do_query = do_query_success(make_domain_response(host_ips=host_ips))

        connector._reverse_lookup_domain({})
        ar = connector.last_action_result()

        ip_list = ar.get_summary()["ip_list"]
        assert ip_list[0]["ip"] == "2.2.2.2"
        assert ip_list[1]["count_string"] == ""

    def test_returns_data_list_when_do_query_fails(self, connector):
        connector._domains = ["evil.com"]
        connector._do_query = do_query_failure("API error")

        result = connector._reverse_lookup_domain({})
        ar = connector.last_action_result()

        assert result == []
        assert ar.get_status() is False

    def test_returns_early_when_no_data(self, connector):
        connector._domains = ["evil.com"]
        connector._do_query = do_query_success()

        result = connector._reverse_lookup_domain({})
        ar = connector.last_action_result()

        assert result is True
        assert ar.get_summary() == {}

    def test_queries_iris_investigate_service(self, connector):
        fake, calls = do_query_capture_service()
        connector._domains = ["evil.com"]
        connector._do_query = fake

        connector._reverse_lookup_domain({})

        assert calls[0] == "iris_investigate"
