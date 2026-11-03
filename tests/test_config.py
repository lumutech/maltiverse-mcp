"""Tests for environment-variable configuration."""

from __future__ import annotations

from maltiverse_mcp.config import (
    DEFAULT_BASE_URL,
    DEFAULT_LOG_LEVEL,
    DEFAULT_TIMEOUT,
    load_config,
)


def test_defaults_when_env_empty() -> None:
    cfg = load_config(env={})
    assert cfg.api_key is None
    assert cfg.has_api_key is False
    assert cfg.base_url == DEFAULT_BASE_URL
    assert cfg.timeout == DEFAULT_TIMEOUT
    assert cfg.log_level == DEFAULT_LOG_LEVEL


def test_api_key_whitespace_is_stripped() -> None:
    cfg = load_config(env={"MALTIVERSE_API_KEY": "  sk-abc\n"})
    assert cfg.api_key == "sk-abc"
    assert cfg.has_api_key is True


def test_blank_api_key_is_treated_as_missing() -> None:
    cfg = load_config(env={"MALTIVERSE_API_KEY": "   "})
    assert cfg.api_key is None


def test_base_url_trailing_slash_trimmed() -> None:
    cfg = load_config(env={"MALTIVERSE_BASE_URL": "https://example.test/"})
    assert cfg.base_url == "https://example.test"


def test_invalid_and_nonpositive_timeout_falls_back() -> None:
    assert load_config(env={"MALTIVERSE_TIMEOUT": "not-a-number"}).timeout == DEFAULT_TIMEOUT
    assert load_config(env={"MALTIVERSE_TIMEOUT": "0"}).timeout == DEFAULT_TIMEOUT
    assert load_config(env={"MALTIVERSE_TIMEOUT": "-5"}).timeout == DEFAULT_TIMEOUT


def test_valid_timeout_and_log_level() -> None:
    cfg = load_config(env={"MALTIVERSE_TIMEOUT": "12.5", "MALTIVERSE_LOG_LEVEL": "debug"})
    assert cfg.timeout == 12.5
    assert cfg.log_level == "DEBUG"
