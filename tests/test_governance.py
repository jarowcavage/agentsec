from pathlib import Path

import pytest

from agentsec.governance import PRIMARY_AGENT, AuthorizationDenied, Governance
from agentsec.storage import Store


@pytest.fixture
def policy(tmp_path):
    store = Store(Path(tmp_path / "governance.db"))
    store.initialize()
    return Governance(store)


def test_scoped_identity_and_audit(policy):
    token = policy.credential(PRIMARY_AGENT, "scan:one")
    assert policy.authorize(token, "lookup_vulnerability", "scan:one") == PRIMARY_AGENT
    for credential, tool, resource in [
        (token, "create_issue", "repo:production"),
        (token, "lookup_vulnerability", "scan:two"),
        ("agentsec-remediation", "lookup_vulnerability", "scan:one"),
        ("", "lookup_vulnerability", "scan:one"),
    ]:
        with pytest.raises(AuthorizationDenied):
            policy.authorize(credential, tool, resource)
    assert len([e for e in policy.events() if e["outcome"] == "denied"]) == 4
    assert token not in str(policy.events()) + str(policy.inventory())


def test_expiration_revocation_and_restart(policy):
    expired = policy.credential(PRIMARY_AGENT, "scan:one", lifetime=-1)
    with pytest.raises(AuthorizationDenied):
        policy.authorize(expired, "lookup_vulnerability", "scan:one")
    token = policy.credential(PRIMARY_AGENT, "scan:one")
    policy.change(PRIMARY_AGENT, revoke="vulnerability.read")
    policy.initialize()
    with pytest.raises(AuthorizationDenied):
        policy.authorize(token, "lookup_vulnerability", "scan:one")
    assert policy.authorize(token, "get_dependency_context", "scan:one")
    policy.change(PRIMARY_AGENT, status="suspended")
    with pytest.raises(AuthorizationDenied):
        policy.authorize(token, "get_dependency_context", "scan:one")


def test_new_agent_has_no_permissions(policy):
    agent = policy.register("Synthetic unowned agent", synthetic=True)
    token = policy.credential(agent, "scan:one")
    with pytest.raises(AuthorizationDenied):
        policy.authorize(token, "lookup_vulnerability", "scan:one")
    item = next(a for a in policy.inventory() if a["id"] == agent)
    assert "Missing human owner" in item["risks"]
    policy.change(agent, owner="Security administrator", certify=True)
    assert not next(a for a in policy.inventory() if a["id"] == agent)["risks"][:2] == [
        "Missing human owner",
        "Access not certified",
    ]
