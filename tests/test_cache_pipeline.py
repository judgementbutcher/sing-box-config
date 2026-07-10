import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import build_singbox
from build_singbox import (
    SubscriptionContent,
    fetch_source_with_cache,
    prepare_subscription,
    subscription_cache_path,
    write_cached_subscription,
)


def cached_content(text, *, days_old=0):
    timestamp = (datetime.now(timezone.utc) - timedelta(days=days_old)).isoformat().replace("+00:00", "Z")
    return SubscriptionContent(
        text=text,
        userinfo={},
        from_cache=True,
        cache_status="cache",
        fetched_at=timestamp,
        validated_at=timestamp,
    )


def test_offline_mode_uses_fresh_cache(tmp_path):
    url = "https://subscription.example/profile"
    path = subscription_cache_path(tmp_path, url)
    write_cached_subscription(path, cached_content("vless://placeholder"))
    loaded = fetch_source_with_cache(url, tmp_path, "test", offline=True, cache_max_stale="7d")
    assert loaded.content.cache_status == "offline-cache"
    assert loaded.content.text == "vless://placeholder"


def test_offline_mode_rejects_expired_cache(tmp_path):
    url = "https://subscription.example/profile"
    path = subscription_cache_path(tmp_path, url)
    write_cached_subscription(path, cached_content("vless://placeholder", days_old=10))
    with pytest.raises(RuntimeError, match="超过最大陈旧时间"):
        fetch_source_with_cache(url, tmp_path, "test", offline=True, cache_max_stale="1d")


def test_parse_failure_falls_back_without_overwriting_good_cache(tmp_path, monkeypatch):
    url = "https://subscription.example/profile"
    valid = json.dumps(
        {
            "outbounds": [
                {
                    "type": "vless",
                    "tag": "HK cached",
                    "server": "cached.example",
                    "server_port": 443,
                    "uuid": "00000000-0000-0000-0000-000000000001",
                }
            ]
        }
    )
    cache_path = subscription_cache_path(tmp_path, url)
    write_cached_subscription(cache_path, cached_content(valid))

    def invalid_download(*args, **kwargs):
        return SubscriptionContent(
            text="{not-json",
            userinfo={},
            from_cache=False,
            cache_status="remote",
        )

    monkeypatch.setattr(build_singbox, "fetch_subscription_content", invalid_download)
    result = prepare_subscription(
        {
            "name": "provider",
            "parser": "singbox-json",
            "source": "url",
            "url": url,
            "priority": 10,
            "role": "primary",
        },
        manifest_base_dir=tmp_path,
        user_agent="pytest",
        cache_dir=tmp_path,
        fetch_proxy=None,
        connect_timeout=1,
        read_timeout=1,
        retries=0,
        cache_max_stale="7d",
        offline=False,
    )
    assert result.cache_status == "parse-fallback"
    assert len(result.node_outbounds) == 1
    assert "回退" in result.warnings[0]
    assert cache_path.read_text(encoding="utf-8") == valid
