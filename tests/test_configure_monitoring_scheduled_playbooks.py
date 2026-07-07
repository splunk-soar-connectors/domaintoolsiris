"""Unit tests for _configure_monitoring_scheduled_playbooks action."""


class TestConfigureMonitoringScheduledPlaybooks:

    def test_returns_success_when_list_created(self, connector):
        connector._create_scheduled_playbook_list = lambda: ({"id": 1}, True)

        result = connector._configure_monitoring_scheduled_playbooks({})
        ar = connector.last_action_result()

        assert result is True
        assert ar.get_status() is True

    def test_success_message_includes_list_name(self, connector):
        connector._create_scheduled_playbook_list = lambda: ({"id": 1}, True)

        connector._configure_monitoring_scheduled_playbooks({})
        ar = connector.last_action_result()

        assert connector._scheduled_playbooks_list_name in ar.get_message()
        assert "sucessfully created" in ar.get_message()

    def test_returns_error_when_list_already_exists(self, connector):
        connector._create_scheduled_playbook_list = lambda: ({"message": "already exists"}, False)

        result = connector._configure_monitoring_scheduled_playbooks({})
        ar = connector.last_action_result()

        assert result is False
        assert ar.get_status() is False

    def test_error_message_includes_api_response_message(self, connector):
        connector._create_scheduled_playbook_list = lambda: ({"message": "already exists"}, False)

        connector._configure_monitoring_scheduled_playbooks({})
        ar = connector.last_action_result()

        assert "already exists" in ar.get_message()

    def test_error_message_includes_list_name(self, connector):
        connector._create_scheduled_playbook_list = lambda: ({"message": "conflict"}, False)

        connector._configure_monitoring_scheduled_playbooks({})
        ar = connector.last_action_result()

        assert connector._scheduled_playbooks_list_name in ar.get_message()

    def test_error_message_when_response_has_no_message_key(self, connector):
        connector._create_scheduled_playbook_list = lambda: ({}, False)

        connector._configure_monitoring_scheduled_playbooks({})
        ar = connector.last_action_result()

        assert ar.get_status() is False
        # res.get('message') returns None — message should still be formed without error
        assert connector._scheduled_playbooks_list_name in ar.get_message()
