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
"""
Unit tests for all RTUF feed actions.

All seven feed actions share identical logic via _get_rtuf_actions_params —
only the action method and the DT service name differ. A single parametrized
class covers all of them instead of seven near-identical files.
"""

import pytest

from tests.conftest import do_query_capture_args, do_query_capture_service, do_query_failure, do_query_success


FEED_CASES = [
    ("_nod_feed", "nod"),
    ("_nad_feed", "nad"),
    ("_noh_feed", "noh"),
    ("_domain_discovery_feed", "domaindiscovery"),
    ("_parsed_domain_rdap_feed", "domainrdap"),
    ("_domain_risk_feed", "realtime_domain_risk"),
    ("_domain_hotlist_feed", "domainhotlist"),
]


@pytest.mark.parametrize("method_name,service_name", FEED_CASES)
class TestRtufFeeds:
    def _call(self, connector, method_name, param=None):
        return getattr(connector, method_name)(param or {})

    def test_returns_success(self, connector, method_name, service_name):
        connector._do_query = do_query_success()

        result = self._call(connector, method_name)
        ar = connector.last_action_result()

        assert result is True
        assert ar.get_status() is True

    def test_returns_data_list_when_do_query_fails(self, connector, method_name, service_name):
        connector._do_query = do_query_failure("feed error")

        result = self._call(connector, method_name)
        ar = connector.last_action_result()

        assert result == []
        assert ar.get_status() is False

    def test_queries_correct_service(self, connector, method_name, service_name):
        fake, calls = do_query_capture_service()
        connector._do_query = fake

        self._call(connector, method_name)

        assert calls[0] == service_name

    def test_sets_always_sign_api_key_false(self, connector, method_name, service_name):
        fake, calls = do_query_capture_args()
        connector._do_query = fake

        self._call(connector, method_name)

        assert calls[0]["always_sign_api_key"] is False

    def test_passes_through_extra_params(self, connector, method_name, service_name):
        fake, calls = do_query_capture_args()
        connector._do_query = fake

        self._call(connector, method_name, {"date": "2026-01-01", "limit": 100})

        assert calls[0]["date"] == "2026-01-01"
        assert calls[0]["limit"] == 100

    def test_renames_session_id_to_sessionID(self, connector, method_name, service_name):
        fake, calls = do_query_capture_args()
        connector._do_query = fake

        self._call(connector, method_name, {"session_id": "sess-abc"})

        assert "sessionID" in calls[0]
        assert calls[0]["sessionID"] == "sess-abc"
        assert "session_id" not in calls[0]

    def test_session_id_not_added_when_absent(self, connector, method_name, service_name):
        fake, calls = do_query_capture_args()
        connector._do_query = fake

        self._call(connector, method_name)

        assert "sessionID" not in calls[0]
        assert "session_id" not in calls[0]
