# maltiverse-mcp

A local **stdio MCP server** that exposes the [Maltiverse](https://maltiverse.com)
threat-intelligence API to Claude Code and any other MCP client. Give it an IP,
domain, URL, or file hash and it returns Maltiverse's verdict, threat
attributions, and behaviour flags — or hunt the whole dataset with a search query.

All tools are **read-only**. The API key is supplied only through the
`MALTIVERSE_API_KEY` environment variable that `claude mcp add --env` injects —
there are no config files, no prompts, and no `--api-key` flag (which would leak
into shell history and `ps`).

## Tools

| Tool | What it does | Kind |
| --- | --- | --- |
| `maltiverse_check_indicator` | Look up any IoC (IP / domain / URL / hash); type auto-detected | read-only |
| `maltiverse_check_ip` | Reputation of an IPv4/IPv6 address | read-only |
| `maltiverse_check_hostname` | Reputation of a hostname/domain | read-only |
| `maltiverse_check_url` | Reputation of a full URL (hashed to Maltiverse's checksum) | read-only |
| `maltiverse_check_sample` | Reputation of a malware sample by MD5/SHA-1/SHA-256/SHA-512 | read-only |
| `maltiverse_search` | Search the IoC dataset with Elasticsearch query-string syntax (paginated) | read-only |

Each lookup accepts `response_format`: `concise` (default — verdict, threat
names, feeds, key flags) or `detailed` (adds full per-feed attributions).

## Install

```bash
pip install maltiverse-mcp
# or
uv tool install maltiverse-mcp
# or run with zero install
uvx maltiverse-mcp
```

Get a free API key from your [Maltiverse profile](https://maltiverse.com)
("Generate API Key").

## Claude Code setup

```bash
# pip install (the console script must be on PATH)
claude mcp add --scope user --transport stdio maltiverse \
  --env MALTIVERSE_API_KEY=YOUR_KEY -- maltiverse-mcp

# zero-install via uv
claude mcp add --scope user --transport stdio maltiverse \
  --env MALTIVERSE_API_KEY=YOUR_KEY -- uvx maltiverse-mcp

# if the script isn't on PATH (venvs, pyenv), use an absolute interpreter
claude mcp add --scope user --transport stdio maltiverse \
  --env MALTIVERSE_API_KEY=YOUR_KEY -- /abs/path/to/python -m maltiverse_mcp
```

Then:

```bash
claude mcp list          # shows: maltiverse  ✔ Connected
```

> **Argument order matters.** `--env` accepts multiple `KEY=value` pairs, so never
> put the server name *directly after* `--env`. Keep the name before `--env` (as
> above), or put another flag in between. The `--` separates Claude's own flags
> from the command that launches the server.

### Rotating the key

```bash
claude mcp remove maltiverse -s user
claude mcp add --scope user --transport stdio maltiverse \
  --env MALTIVERSE_API_KEY=NEW_KEY -- maltiverse-mcp
```

### Team setup (committed `.mcp.json`, no secret)

Commit this and let each developer provide the key via their own environment:

```json
{
  "mcpServers": {
    "maltiverse": {
      "type": "stdio",
      "command": "maltiverse-mcp",
      "env": { "MALTIVERSE_API_KEY": "${MALTIVERSE_API_KEY}" }
    }
  }
}
```

## Environment variables

| Variable | Required | Default | Purpose |
| --- | --- | --- | --- |
| `MALTIVERSE_API_KEY` | yes (for tool calls) | — | Bearer API key from your Maltiverse profile |
| `MALTIVERSE_BASE_URL` | no | `https://api.maltiverse.com` | Override the API base URL |
| `MALTIVERSE_TIMEOUT` | no | `30` | Per-request timeout in seconds |
| `MALTIVERSE_LOG_LEVEL` | no | `WARNING` | Logging level (logs go to stderr) |

The server starts fine **without** a key — it stays connected and its tools are
discoverable — but any tool call returns an actionable error telling you how to
set the key.

> **Security:** for `user`/`local` scope the key is stored by Claude Code in
> `~/.claude.json`. Don't commit that file, and don't commit a `.mcp.json` that
> contains the literal key — use `${MALTIVERSE_API_KEY}` expansion as shown above.

## Troubleshooting

```bash
claude mcp get maltiverse        # inspect config + connection status
```

- In a session, run `/mcp` to see server status and the tool list.
- Slow to start? `MCP_TIMEOUT=10000 claude` raises the startup timeout.
- Output truncated? Raise `MAX_MCP_OUTPUT_TOKENS` (responses default to ≤20 results).
- **"Failed to connect"** almost always means the `maltiverse-mcp` console script
  isn't on `PATH`. Use the absolute-interpreter form above
  (`-- /abs/path/to/python -m maltiverse_mcp`).

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
ruff check . && ruff format --check . && mypy src && pytest -q
```

Inspect it interactively with the MCP Inspector (set `MALTIVERSE_API_KEY` in its UI):

```bash
npx @modelcontextprotocol/inspector maltiverse-mcp
```

## License

MIT — see [LICENSE](LICENSE).
