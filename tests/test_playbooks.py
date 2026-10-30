import pytest

from src.playbooks import PLAYBOOKS, get_playbook, list_playbooks


def test_list_playbooks_returns_all_initial_playbooks():
    assert list_playbooks() == [
        "DHCP / APIPA failure",
        "DNS resolution failure",
        "Default gateway / routing failure",
    ]


@pytest.mark.parametrize("name", list(PLAYBOOKS))
def test_playbook_has_required_sections(name):
    playbook = get_playbook(name)

    assert playbook["trigger"]
    assert playbook["purpose"]
    assert playbook["safety"]
    assert playbook["steps"]
    assert playbook["remediation"]
    assert playbook["closure"]


@pytest.mark.parametrize("name", list(PLAYBOOKS))
def test_playbook_steps_have_actionable_details(name):
    playbook = get_playbook(name)

    for step in playbook["steps"]:
        assert step["title"]
        assert step["purpose"]
        assert step["command"]
        assert step["expected"]
        assert step["interpretation"]


def test_unknown_playbook_raises_key_error():
    with pytest.raises(KeyError, match="Unknown troubleshooting playbook"):
        get_playbook("Unknown playbook")


def test_playbooks_do_not_include_automatic_execution_handlers():
    for playbook in PLAYBOOKS.values():
        for step in playbook["steps"]:
            assert "execute" not in step
            assert "run_command" not in step
