from src.config import Settings


def _base_kwargs():
    return {
        "lumu_email": "user@example.com",
        "lumu_password": "secret",
        "lumu_mssp_uuid": "mssp-uuid",
    }


def test_profile_resolution_balanced_defaults():
    settings = Settings(**_base_kwargs(), lumu_rate_policy_profile="balanced")
    policy = settings.resolve_rate_policy()
    assert policy.profile == "balanced"
    assert policy.tenant_concurrency_cap == 2
    assert policy.journal_delay_time_seconds == 20


def test_profile_resolution_tenant_cap_override():
    settings = Settings(**_base_kwargs(), lumu_rate_policy_profile="strict", lumu_rate_policy_tenant_cap=3)
    policy = settings.resolve_rate_policy()
    assert policy.profile == "strict"
    assert policy.tenant_concurrency_cap == 3


def test_profile_advanced_allows_expert_override():
    settings = Settings(
        **_base_kwargs(),
        lumu_rate_policy_profile="strict",
        lumu_rate_policy_advanced=True,
        lumu_journal_delay_time_seconds=17,
    )
    policy = settings.resolve_rate_policy()
    assert policy.journal_delay_time_seconds == 17
