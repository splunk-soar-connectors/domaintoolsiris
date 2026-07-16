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
"""Unit tests for _pivot_action action."""

from datetime import datetime, timedelta

from tests.conftest import do_query_capture_args, do_query_capture_service, do_query_failure, do_query_success


class TestPivotAction:
    def test_returns_success(self, connector):
        connector._do_query = do_query_success()

        result = connector._pivot_action({"pivot_type": "ip", "query_value": "1.2.3.4"})

        assert result is True

    def test_returns_data_list_when_do_query_fails(self, connector):
        connector._do_query = do_query_failure("API error")

        result = connector._pivot_action({"pivot_type": "ip", "query_value": "1.2.3.4"})

        assert result == []

    def test_queries_iris_investigate_service(self, connector):
        fake, calls = do_query_capture_service()
        connector._do_query = fake

        connector._pivot_action({"pivot_type": "ip", "query_value": "1.2.3.4"})

        assert calls[0] == "iris_investigate"

    def test_uses_domains_field_for_domain_pivot_type(self, connector):
        fake, calls = do_query_capture_args()
        connector._domains = ["evil.com"]
        connector._do_query = fake

        connector._pivot_action({"pivot_type": "domain", "query_value": "evil.com"})

        assert "domains" in calls[0]
        assert calls[0]["domains"] == ["evil.com"]

    def test_uses_pivot_type_as_query_field_for_non_domain(self, connector):
        fake, calls = do_query_capture_args()
        connector._do_query = fake

        connector._pivot_action({"pivot_type": "ip", "query_value": " 1.2.3.4 "})

        assert "ip" in calls[0]
        assert calls[0]["ip"] == "1.2.3.4"  # stripped

    def test_passes_tld_when_present(self, connector):
        fake, calls = do_query_capture_args()
        connector._do_query = fake

        connector._pivot_action({"pivot_type": "ip", "query_value": "1.2.3.4", "tld": "com"})

        assert calls[0]["tld"] == "com"

    def test_resolves_today_in_data_updated_after(self, connector):
        fake, calls = do_query_capture_args()
        connector._do_query = fake

        connector._pivot_action({"pivot_type": "ip", "query_value": "1.2.3.4", "data_updated_after": "today"})

        assert calls[0]["data_updated_after"] == datetime.today().strftime("%Y-%m-%d")

    def test_resolves_yesterday_in_data_updated_after(self, connector):
        fake, calls = do_query_capture_args()
        connector._do_query = fake

        connector._pivot_action({"pivot_type": "ip", "query_value": "1.2.3.4", "data_updated_after": "yesterday"})

        expected = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
        assert calls[0]["data_updated_after"] == expected

    def test_resolves_today_in_create_date(self, connector):
        fake, calls = do_query_capture_args()
        connector._do_query = fake

        connector._pivot_action({"pivot_type": "ip", "query_value": "1.2.3.4", "create_date": "today"})

        assert calls[0]["create_date"] == datetime.today().strftime("%Y-%m-%d")

    def test_resolves_today_in_expiration_date(self, connector):
        fake, calls = do_query_capture_args()
        connector._do_query = fake

        connector._pivot_action({"pivot_type": "ip", "query_value": "1.2.3.4", "expiration_date": "today"})

        assert calls[0]["expiration_date"] == datetime.today().strftime("%Y-%m-%d")

    def test_status_active_sets_active_true(self, connector):
        fake, calls = do_query_capture_args()
        connector._do_query = fake

        connector._pivot_action({"pivot_type": "ip", "query_value": "1.2.3.4", "status": "active"})

        assert calls[0]["active"] is True

    def test_status_inactive_sets_active_false(self, connector):
        fake, calls = do_query_capture_args()
        connector._do_query = fake

        connector._pivot_action({"pivot_type": "ip", "query_value": "1.2.3.4", "status": "inactive"})

        assert calls[0]["active"] is False

    def test_status_any_not_added_to_params(self, connector):
        fake, calls = do_query_capture_args()
        connector._do_query = fake

        connector._pivot_action({"pivot_type": "ip", "query_value": "1.2.3.4", "status": "any"})

        assert "active" not in calls[0]

    def test_passes_first_seen_within(self, connector):
        fake, calls = do_query_capture_args()
        connector._do_query = fake

        connector._pivot_action({"pivot_type": "ip", "query_value": "1.2.3.4", "first_seen_within": "30"})

        assert calls[0]["first_seen_within"] == "30"

    def test_passes_create_date_within(self, connector):
        fake, calls = do_query_capture_args()
        connector._do_query = fake

        connector._pivot_action({"pivot_type": "ip", "query_value": "1.2.3.4", "create_date_within": "7"})

        assert calls[0]["create_date_within"] == "7"
