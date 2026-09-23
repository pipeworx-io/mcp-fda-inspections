# fda-inspections

FDA inspection outcomes, Form 483 citations, compliance actions and import
refusals, from the FDA Data Dashboard (Office of Inspections and
Investigations).

Part of [Pipeworx](https://pipeworx.io) — an MCP gateway connecting AI agents to 1663+ live data sources.

**This is not openFDA.** openFDA carries drug/device adverse events, labels,
recalls and warning letters. It does **not** carry inspection classifications,
483 observations, or border refusals — those live only in OII's own Data
Dashboard, on a different host with a different credential.

## Tools

| Tool | Answers |
|---|---|
| `fda_inspections` | Was this site inspected, and what was the outcome (NAI / VAI / **OAI**)? |
| `fda_483_citations` | *Why* was it cited — which CFR section, and what did the investigator write? |
| `fda_compliance_actions` | What enforcement followed — warning letter, injunction, seizure, debarment? |
| `fda_import_refusals` | What shipments were refused at the border, and on what charge? |
| `fda_firm_risk_profile` | All four at once for one manufacturer, with the FEI sites resolved. |

## Auth

The credential is a **pair**, not a single key:

```
Authorization-User: <the e-mail it was issued to>
Authorization-Key:  <the FDA-generated key>
```

Pass it as `_apiKey` in the combined form `"email:key"` (split on the first
colon). Platform secret: `PLATFORM_FDA_DASHBOARD_KEY`, same combined form, set
on **both** the gateway and registry-api workers.

Credentials are free: create an account in the OII Unified Logon application at
<https://www.accessdata.fda.gov/scripts/oul> and request Data Dashboard API
access. FDA mails the key to the address you register, and that address becomes
the `Authorization-User` value. The platform credential is set, so callers need
no key of their own.

Note that `datadashboard.fda.gov` serves a **403 to a default curl
User-Agent** — send a browser UA when reading the docs by hand. The API host
(`api-datadashboard.fda.gov`) has no such restriction.

## Request contract

Verified against the live endpoint rather than assumed — a malformed body
returns **400 and names the offending field**, a well-formed but unauthenticated
one returns **401**, which makes the shape testable without a credential.

- `POST https://api-datadashboard.fda.gov/v1/<resource>`
- Body: `{ start, rows, sort, sortorder, columns[], filters{} }`
- `sort` and `sortorder` are **required**, not optional.
- `start` is **1-based**.
- `rows` maxes at **5000**.
- `columns` is **required** — omitting it 400s and names the missing field.
- Filter values must be **arrays** — `{"State": ["California"]}`. A bare string 400s.
- Date ranges use **suffixed keys**: `InspectionEndDateFrom` /
  `InspectionEndDateTo`. There is no top-level date-range parameter, and the
  bare date fieldname is rejected as a filter key.
- Most string filters match `LIKE %term%` case-insensitively, so firm names are
  substring searches. `State` is the exception — see below.

## Gotcha: `State` is exact, and a wrong one looks like "never inspected"

`LegalName`, `FirmName` and `CountryName` are case-insensitive substring
matches. **`State` is exact and case-sensitive against the spelled-out name.**
`"CA"`, `"Ca"` and `"CALIFORNIA"` each return a clean `200` with
`resultcount: 0` — which reads as *this site was never inspected* rather than
*you passed the wrong argument*. Only `"California"` returns data.

The pack normalizes postal codes and casing (`normalizeState`), so callers may
pass either form. Foreign establishments carry `State: null`; filter those by
`country` instead.

## Gotcha: firm search is a substring, so it over-matches

`firm: "Intas"` also matches **Cintas Corporation**. `fda_firm_risk_profile`
returns every FEI it matched in `matched_establishments` precisely so this is
visible — read that list before quoting the aggregate counts, which are computed
over all matched rows.

## Gotcha: the name column is not uniform

`import_refusals` calls it **`FirmName`**. The other three resources use
**`LegalName`**. Sending the wrong one is rejected as an invalid fieldname, so
the pack encodes the name column per resource instead of assuming one.

## Quick Start

Add to your MCP client (Claude Desktop, Cursor, Windsurf, etc.):

```json
{
  "mcpServers": {
    "fda-inspections": {
      "url": "https://gateway.pipeworx.io/fda-inspections/mcp"
    }
  }
}
```

### What this endpoint actually serves

`tools/list` at `https://gateway.pipeworx.io/fda-inspections/mcp` returns the tools in the table
above **plus the shared Pipeworx meta-tools** — `ask_pipeworx`,
`discover_tools`, `search_within`, `remember`/`recall` and the rest of the
gateway-wide set. So the tool count you see is larger than this table: a
single-pack endpoint currently lists roughly 30 shared tools alongside the
pack's own. The connection's `initialize` response states its exact scope, and
is the authoritative answer for a given day.

This is deliberate, not multiplexing by accident. The meta-tools are what let a
scoped connection answer a question this pack does not cover — via
`ask_pipeworx`, which routes across the whole catalog — without you adding a
second MCP server. There is currently no way to mount a pack endpoint without
them; if the extra schemas cost you more context than the routing is worth,
connect to the full gateway once rather than to several pack endpoints.

Or connect to the full Pipeworx gateway to get every pack's tools listed
directly, instead of just this one's:

```json
{
  "mcpServers": {
    "pipeworx": {
      "url": "https://gateway.pipeworx.io/mcp"
    }
  }
}
```

Both URLs reach the same gateway and the same 1663+ data sources. The
only difference is which pack's tools are listed **directly**; `ask_pipeworx`
reaches all of them from either one.

## No MCP client? Call it over HTTP

```bash
curl -X POST https://gateway.pipeworx.io/v1/tools/fda_inspections \
  -H 'Content-Type: application/json' \
  -d '{"firm":"Intas","limit":25}'
```

No account needed for the first calls. Inspect any tool: `GET https://gateway.pipeworx.io/v1/tools/fda_inspections`. Find one: `POST https://gateway.pipeworx.io/v1/tools/search_packs` with `{"query":"..."}`.

## Standalone (no gateway account)

This package also runs as a local stdio MCP server — no Pipeworx account, no
gateway round-trip:

```json
{
  "mcpServers": {
    "fda-inspections": {
      "command": "npx",
      "args": ["-y", "@pipeworx/mcp-fda-inspections"]
    }
  }
}
```

Or run it directly to confirm it starts:

```bash
npx -y @pipeworx/mcp-fda-inspections
```

It speaks MCP over stdin/stdout and answers `initialize`/`tools/list`/`tools/call`
for **only** this pack's tools — none of the shared meta-tools the gateway
connection above adds. Same source, same tools, no ask_pipeworx routing.

## Using with ask_pipeworx

Instead of calling tools directly, you can ask questions in plain English —
this works on the pack endpoint above as well as on the full gateway:

```
ask_pipeworx({ question: "your question about Fda Inspections data" })
```

The gateway picks the right tool and fills the arguments automatically.

## More

- [Docs and guides](https://pipeworx.io/docs)
- [pipeworx.io](https://pipeworx.io)

## License

MIT
