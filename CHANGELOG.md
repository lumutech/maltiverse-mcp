# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Raised the minimum Python to 3.11 (from 3.10). Python 3.10 reached end-of-life
  for security fixes in October 2026 and no longer receives OpenSSL/`ssl`
  backports; CI now tests 3.11–3.13.

## [0.1.0] - 2026-11-02

### Added
- Initial release: local stdio MCP server for the Maltiverse threat-intel API.
- Tools: `maltiverse_check_indicator`, `maltiverse_check_ip`,
  `maltiverse_check_hostname`, `maltiverse_check_url`, `maltiverse_check_sample`,
  and `maltiverse_search`.
- Concise/detailed response formats, typed structured output, cursor-style
  pagination for search, and output truncation to stay within client limits.
- Actionable tool errors for missing/invalid API keys, 404/422/429/5xx.

[Unreleased]: https://github.com/maltiverse/maltiverse-mcp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/maltiverse/maltiverse-mcp/releases/tag/v0.1.0
