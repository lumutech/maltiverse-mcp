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

## Claude Code setup (the `claude` CLI)

> **Claude Code ≠ Claude Desktop.** The `claude mcp` commands below configure
> **Claude Code** (the CLI / IDE extension) and write to `~/.claude.json`. They do
> **not** affect the **Claude Desktop** GUI app, which reads a different file — see
> [Claude Desktop app](#claude-desktop-app-the-gui) for that. If you add a server
> with `claude mcp add` and don't see it in the desktop app, this is why.

```bash
# pip install (the console script must be on PATH)
claude mcp add --scope user --transport stdio maltiverse \
  --env MALTIVERSE_API_KEY=YOUR_KEY -- maltiverse-mcp

# zero-install via uv
claude mcp add --scope user --transport stdio maltiverse \
  --env MALTIVERSE_API_KEY=YOUR_KEY -- uvx maltiverse-mcp

# if the script isn't on PATH (a project venv, pyenv, etc.), use an absolute path
claude mcp add --scope user --transport stdio maltiverse \
  --env MALTIVERSE_API_KEY=YOUR_KEY -- /abs/path/to/.venv/bin/maltiverse-mcp

# ...or point at a specific interpreter and run the module
claude mcp add --scope user --transport stdio maltiverse \
  --env MALTIVERSE_API_KEY=YOUR_KEY -- /abs/path/to/.venv/bin/python -m maltiverse_mcp
```

Then:

```bash
claude mcp list              # shows: maltiverse  ✔ Connected
claude mcp get maltiverse    # full config + connection status
# inside a `claude` session, run /mcp to see the server and its tools
```

> **Argument order matters.** `--env` accepts multiple `KEY=value` pairs, so never
> put the server name *directly after* `--env`. Keep the name before `--env` (as
> above), or put another flag in between. The `--` separates Claude's own flags
> from the command that launches the server.

### Choosing a scope

`--scope` decides **where** the server is registered and therefore where it shows up:

| Scope | Stored in | Visible in |
| --- | --- | --- |
| `user` | `~/.claude.json` | **every** Claude Code session, any directory (**recommended**) |
| `local` | `~/.claude.json` (per-project) | only sessions started **in that one directory** |
| `project` | committed `.mcp.json` | anyone who checks out the repo (see [Team setup](#team-setup-committed-mcpjson-no-secret)) |

If you added it with `--scope local` and it "disappeared", you were likely running
`claude` from a different directory. Re-add it with `--scope user`:

```bash
claude mcp remove maltiverse -s local   # drop the project-scoped one (if any)
claude mcp add --scope user --transport stdio maltiverse \
  --env MALTIVERSE_API_KEY=YOUR_KEY -- maltiverse-mcp
```

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

## Claude Desktop app (the GUI)

The desktop app does **not** read `~/.claude.json` and is **not** configured by the
`claude mcp` commands. It has its own config file:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

Edit that file by hand (create it if missing) and add a `maltiverse` entry under
`mcpServers`, **keeping any existing servers**:

```json
{
  "mcpServers": {
    "maltiverse": {
      "command": "/abs/path/to/.venv/bin/maltiverse-mcp",
      "env": { "MALTIVERSE_API_KEY": "YOUR_KEY" }
    }
  }
}
```

- Use an **absolute** `command` path — the desktop app does not inherit your shell
  `PATH`, so a bare `maltiverse-mcp` (or `uvx`) usually won't resolve. If you
  installed into a venv, point at `.venv/bin/maltiverse-mcp`; its shebang selects
  the right Python automatically. (On Windows use `.venv\\Scripts\\maltiverse-mcp.exe`.)
- **macOS: do not put the venv under `~/Documents`, `~/Desktop`, or `~/Downloads`.**
  The desktop app has no privacy (TCC) permission for those folders, so the spawned
  Python fails with `PermissionError: [Errno 1] Operation not permitted: .../pyvenv.cfg`
  and the server shows "Server disconnected". Install into a venv elsewhere (e.g.
  `~/.venvs/maltiverse-mcp`) and point `command` there — or grant the app access under
  System Settings → Privacy & Security → Files and Folders / Full Disk Access.
- This is plain JSON — there is no `--transport` / `--env` / `--` syntax here; use
  `command`, optional `args`, and `env`.
- After saving, **fully quit** the app (⌘Q on macOS / right-click → Quit in the tray
  on Windows — closing the window is not enough) and reopen it. The server appears
  under the tools/🔌 menu.

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
- **Claude Desktop shows "Server disconnected"** right after starting, with
  `PermissionError: ... Operation not permitted: .../pyvenv.cfg` in its logs — the
  venv is under a macOS-protected folder (`~/Documents`/`~/Desktop`/`~/Downloads`).
  See [Claude Desktop app](#claude-desktop-app-the-gui): install the venv elsewhere
  (e.g. `~/.venvs/maltiverse-mcp`) or grant the app Files-and-Folders access.

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
