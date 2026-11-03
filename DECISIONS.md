# Decisions & assumptions

Recorded while building `maltiverse-mcp` autonomously. Each entry is a choice
that wasn't fully pinned by the spec or the API.

## Verified SDK facts (not assumptions)
- `mcp` 2.3.0 is current on PyPI. `FastMCP` → `MCPServer` (imported from
  `mcp.server`); `mcp.server.fastmcp` is gone. `Context` is imported from
  `mcp.server.mcpserver`; `ToolError` from `mcp.server.mcpserver.exceptions`.
- mcp v2 depends on **`httpx2`** (`httpx2>=2.10.0`), not `httpx`. We use `httpx2`
  as our HTTP stack to avoid adding a second one. `httpx2` is an API-compatible
  successor (`AsyncClient`, `MockTransport`, `Timeout`, `HTTPStatusError`, …).
- `Annotated[CallToolResult, Model]` as a tool's return annotation both (a) lets
  us set `content` (text for the model) and `structured_content` (typed data for
  the app) independently, and (b) publishes `Model` as the tool's output schema.
  Verified empirically against mcp 2.3.0.

## Maltiverse API
- Base URL `https://api.maltiverse.com`; auth header `Authorization: Bearer <key>`.
  The key is a permanent API key generated in the Maltiverse profile page.
- Endpoints used (all GET, read-only): `/ip/{ip}`, `/hostname/{host}`,
  `/url/{sha256(url)}`, `/sample/{sha256}` (plus `/sample/md5|sha1|sha512/{h}`),
  and `/search?query=&from=&size=`. Confirmed live against the public API and the
  official `python-maltiverse` client source.
- A URL's id is the SHA-256 of the raw URL string (verified live). The
  `check_url` tool computes this; it also accepts a pre-computed 64-char checksum.

## Decisions
1. **Require the API key for all tool calls**, even though Maltiverse's read
   endpoints currently answer anonymously (free tier). Rationale: the spec's
   contract (and the definition-of-done) require a missing-key tool call to
   return the actionable `isError` message, and requiring a key gives consistent
   auth, higher rate limits, and matches the documented setup. Startup still does
   **not** require the key — the server connects and lists tools regardless.
2. **Read-only tool set only.** Maltiverse also has write endpoints (PUT/POST for
   tagging, comments, bulk upsert). These require elevated account permissions and
   are not needed for the server's purpose (agent enrichment/lookup), so they are
   intentionally omitted. If added later they must carry `destructive_hint=True`
   and say so in the description.
3. **Unified `IndicatorReport` output model** across IP/hostname/URL/sample rather
   than four divergent schemas — easier for an agent to consume; type-specific
   fields (ASN, filetype, …) are optional.
4. **A router tool (`maltiverse_check_indicator`)** auto-detects the indicator
   type. This is the workflow-shaped default; the type-specific tools remain for
   when the caller already knows the type.
5. **404 is surfaced as a tool error**, not an empty "clean" report, because for
   Maltiverse a 404 means "not in the database or malformed input" — the message
   says both and points at `maltiverse_search`.
6. **Retries**: bounded (2) exponential backoff on 429/5xx and transport errors
   for the GET-only (idempotent) surface; honours `Retry-After` on 429.
7. **Pagination** uses an integer `offset`/`next_offset` (ES `from`/`size`) rather
   than an opaque cursor, since Maltiverse search is offset-based.
8. **Mocking in tests** uses `httpx2.MockTransport` injected into the client, so
   no HTTP-mocking dependency is needed (`respx2` does not exist on PyPI).
9. **PyPI/import names**: distribution `maltiverse-mcp`, console script
   `maltiverse-mcp`, import package `maltiverse_mcp`, MCP server name `maltiverse`.
   The bare name `maltiverse` is the official client library, hence the `-mcp`
   suffix on the distribution.
