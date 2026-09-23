interface McpToolDefinition {
  name: string;
  description: string;
  /** Human-facing one-liner (fleet #1967). Optional; consumers fall back to
   *  description. Kept in step with shared/src/types.ts — scripts/lib/
   *  check-inlined-types.mjs reports drift at publish time. */
  summary?: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, unknown>;
    required?: string[];
    anyOf?: Array<{ required: string[] }>;
    oneOf?: Array<{ required: string[] }>;
    allOf?: Array<{ required: string[] }>;
  };
  outputSchema?: Record<string, unknown>;
}

interface McpToolExport {
  tools: McpToolDefinition[];
  callTool: (name: string, args: Record<string, unknown>) => Promise<unknown>;
  meter?: { credits: number };
  cost?: Record<string, unknown>;
  provider?: string;
}

/**
 * The class routing tokens, and the two safe ways to wrap a message carrying one.
 *
 * A pack signals an error's class with a leading token — `user_error:`,
 * `upstream_down:`, `upstream_throttled:`, `not_found:`, `blocked_host:`. The
 * gateway's classifier anchors on `^`, and `stripClassPrefix` (which hides the
 * token from the caller) anchors on `^` too. So the convention has one failure
 * mode, and it is silent: a catch block that wraps the message —
 * `` `${slug}/${tool}: ${message}` `` — pushes the token off position 0. The
 * error then books as `error` ("Pipeworx has a defect") instead of as the
 * caller mistake it is, AND the raw token leaks into what the caller reads.
 *
 * Nothing about that fails loudly. The call still returns, the message still
 * reads plausibly, and the misclassification only shows up as a pack sitting on
 * the Problem Tools list for a bug it does not have. Found live in
 * `medicaid-intelligence` on 2026-08-21; the same wrapper template is copied
 * across 18 DMV packs, none of which emit a token *yet*.
 *
 * `scripts/check-error-class-prefix.mjs` is the gate that keeps this honest —
 * it fails any pack that both emits a token and wraps a caught message without
 * using one of the helpers below.
 */

/**
 * The canonical token set. `workers/gateway/src/error-class.ts` carries its own
 * copy on the read side (it is deliberately importable without pulling a pack
 * in); the gate asserts the two agree, because this list has already drifted
 * twice — `not_found:` and `blocked_host:` were honoured by the classifier and
 * not stripped, so both went out to callers verbatim for months.
 */
const CLASS_TOKENS = [
  'upstream_down',
  'upstream_throttled',
  'user_error',
  'not_found',
  'blocked_host',
  // `blocked_url:` is emitted at position 0 from five sites in ssrf.ts
  // (`assertPublicHttpUrl`, and every redirect hop in `safeFetch`) and was in
  // NEITHER reader — so it went to callers verbatim for its whole life. Caught
  // 2026-08-21 by a live n8n call, which answered a private instance_url with
  // "…host). blocked_url: refusing to fetch non-public or non-https URL".
  // Exactly the drift the gate now blocks.
  'blocked_url',
  // `auth_required:` joins the list 2026-08-29 (fleet #638). It exists for the
  // same reason `user_error:` does: a bare 401/403 in an upstream body matches
  // the `upstream_throttled` heuristic below before anything auth-specific, so
  // a pack that needs to say "this is a credential problem, not a rate limit"
  // has no wording-based route — only the explicit-prefix escape hatch works.
  // tiingo and open-sanctions both reached for it on their own, on the
  // (reasonable, but wrong at the time) assumption that any snake_case class
  // already meant something to the gateway. Neither shipped a leak from
  // MIS-CLASSIFICATION — the `error` field was already correct — the leak was
  // the literal token riding along in `message`, unstripped, because this list
  // didn't know the token either reader was seeing.
  'auth_required',
] as const;

const CLASS_PREFIX_RE =
  /^(?:upstream_down|upstream_throttled|user_error|not_found|blocked_host|blocked_url|auth_required)\s*:\s*/;

/**
 * Split a caught message into its leading routing token (possibly empty) and
 * the human-readable body, so a wrapper can put the token back on the front.
 *
 *   const { token, body } = splitClassPrefix(message);
 *   return { error: `${token}my-pack/${name}: ${body}` };
 *
 * The `${token}` must be the FIRST thing in the template — that is the whole
 * point, and it is what the gate checks.
 */
function splitClassPrefix(message: string): { token: string; body: string } {
  const token = message.match(CLASS_PREFIX_RE)?.[0] ?? '';
  return { token, body: message.slice(token.length) };
}

/**
 * Drop a leading routing token from a message that is about to become a
 * FRAGMENT of a larger one — a per-mirror failure joined into "all providers
 * failed (...)", say. Hoisting is wrong there: the fragment never reaches
 * position 0, so the token cannot route anything and would only leak. The outer
 * message declares its own class.
 */
function dropClassPrefix(message: string): string {
  return message.replace(CLASS_PREFIX_RE, '');
}
/**
 * FDA inspection outcomes, Form 483 observations, compliance actions and import refusals for drug, device and food establishments worldwide, from the FDA Data Dashboard (OII/ORA).
 *
 * Source: https://api-datadashboard.fda.gov/v1/<resource>  (docs:
 * https://datadashboard.fda.gov/oii/api/). This is the FDA Office of Inspections
 * and Investigations' OWN system — it is NOT covered by the universal
 * api.data.gov key, and openFDA does not carry inspection classifications,
 * 483 citations, or import refusals at all.
 *
 * Auth: combined credential. `_apiKey` = "email:key" split on the FIRST colon.
 * The DDAPI wants TWO headers — `Authorization-User` (the e-mail the credential
 * was issued to) and `Authorization-Key` (the FDA-generated key) — so a single
 * opaque key is not enough to call it. Credentials come from the OII Unified
 * Logon application; FDA mails the key back.
 *
 * Request shape (all verified against the live endpoint by iterative rejection —
 * a malformed body 400s and NAMES the offending field, a well-formed one 401s):
 *   POST, JSON body: { start, rows, sort, sortorder, columns[], filters{} }
 *   - `sort` + `sortorder` are REQUIRED, not optional.
 *   - `rows` maxes out at 5000.
 *   - `start` is 1-based, not 0-based.
 *   - filter VALUES must be arrays: {"State":["Texas"]} — a bare string 400s.
 *   - date ranges use suffixed keys: `<Field>From` / `<Field>To`. There is no
 *     top-level date-range parameter, and the bare date fieldname is rejected
 *     as a filter key.
 *   - MOST string filters match LIKE %term% case-insensitively (LegalName,
 *     FirmName, CountryName), so firm names are substring searches. `State` is
 *     the exception: exact and case-sensitive against the spelled-out name, so
 *     "CA" returns a clean zero-row 200. See normalizeState().
 */


const BASE = 'https://api-datadashboard.fda.gov/v1';
const TIMEOUT_MS = 20_000;
const MAX_ROWS = 5000;
const UA = 'pipeworx-mcp-fda-inspections/1.0 (+https://pipeworx.io)';

const KEY_DESC =
  'FDA Data Dashboard credential as "email:key" — the e-mail the credential was issued to, then the FDA-generated key, joined by a colon.';

/**
 * Per-resource shape. The name column is NOT uniform across resources:
 * import_refusals calls it `FirmName` while the other three use `LegalName`.
 * Sending the wrong one is rejected as an invalid fieldname, so it is encoded
 * here rather than assumed.
 */
type ResourceDef = {
  path: string;
  nameField: string;
  dateField: string;
  columns: string[];
};

const RESOURCES = {
  inspections: {
    path: 'inspections_classifications',
    nameField: 'LegalName',
    dateField: 'InspectionEndDate',
    columns: [
      'LegalName', 'FEINumber', 'City', 'State', 'CountryName',
      'InspectionEndDate', 'ClassificationCode', 'ProjectArea',
      'ProductType', 'FiscalYear', 'ZipCode',
    ],
  },
  citations: {
    path: 'inspections_citations',
    nameField: 'LegalName',
    dateField: 'InspectionEndDate',
    columns: [
      'LegalName', 'FEINumber', 'City', 'State', 'CountryName',
      'InspectionEndDate', 'ActCFRNumber', 'ShortDescription',
      'LongDescription', 'FiscalYear', 'ZipCode',
    ],
  },
  compliance: {
    path: 'compliance_actions',
    nameField: 'LegalName',
    dateField: 'ActionTakenDate',
    columns: [
      'LegalName', 'FEINumber', 'City', 'State', 'CountryName',
      'ProductType', 'ActionTakenDate', 'ActionType', 'FiscalYear', 'ZipCode',
    ],
  },
  refusals: {
    path: 'import_refusals',
    nameField: 'FirmName',
    dateField: 'RefusalDate',
    columns: [
      'FirmName', 'FEINumber', 'City', 'State', 'CountryName',
      'RefusalDate', 'ProductCode', 'ProductCodeDescription',
      'RefusalCharges', 'ZipCode',
    ],
  },
} satisfies Record<string, ResourceDef>;

type ResourceKey = keyof typeof RESOURCES;

// ---------------------------------------------------------------------------
// Credential

function credentials(args: Record<string, unknown>): { user: string; key: string } {
  const combined = typeof args._apiKey === 'string' ? args._apiKey.trim() : '';
  delete args._apiKey;
  const idx = combined.indexOf(':');
  const user = idx > 0 ? combined.slice(0, idx).trim() : '';
  const key = idx > 0 ? combined.slice(idx + 1).trim() : '';
  if (!user || !key) {
    throw new Error(
      'FDA Data Dashboard requires an API key. The credential is a PAIR — the e-mail it was issued to plus the FDA-generated key — passed as "email:key" via _apiKey. Request one through the OII Unified Logon application at https://datadashboard.fda.gov/oii/api/ (free; FDA mails the key back). Note this is a different credential from the api.data.gov key used by openFDA — it does not work here. Or [sign up](https://pipeworx.io/signup?via=auth_hint) to use the platform credentials.',
    );
  }
  return { user, key };
}

// ---------------------------------------------------------------------------
// Query

function clampLimit(v: unknown, dflt: number): number {
  const n = typeof v === 'number' ? Math.floor(v) : dflt;
  if (!Number.isFinite(n) || n < 1) return dflt;
  return Math.min(n, MAX_ROWS);
}

function isDate(s: string): boolean {
  return /^\d{4}-\d{2}-\d{2}$/.test(s);
}

/** Push a filter only when it has a value; DDAPI wants every value as an array. */
function put(filters: Record<string, string[]>, field: string, v: unknown): void {
  if (typeof v === 'string' && v.trim()) filters[field] = [v.trim()];
}

/**
 * `State` is the one filter DDAPI matches EXACTLY and case-sensitively, against
 * the spelled-out name — every other string filter is a case-insensitive
 * substring. So "CA", "Ca" and "CALIFORNIA" all come back as a clean 200 with
 * zero rows, indistinguishable from "this site was never inspected". Measured
 * 2026-08-29: only "California" returns data. Callers reach for the postal code
 * first, so normalize it here rather than leaving them a silent empty answer.
 */
const US_STATES: Record<string, string> = {
  AL: 'Alabama', AK: 'Alaska', AZ: 'Arizona', AR: 'Arkansas', CA: 'California',
  CO: 'Colorado', CT: 'Connecticut', DE: 'Delaware', DC: 'District of Columbia',
  FL: 'Florida', GA: 'Georgia', HI: 'Hawaii', ID: 'Idaho', IL: 'Illinois',
  IN: 'Indiana', IA: 'Iowa', KS: 'Kansas', KY: 'Kentucky', LA: 'Louisiana',
  ME: 'Maine', MD: 'Maryland', MA: 'Massachusetts', MI: 'Michigan',
  MN: 'Minnesota', MS: 'Mississippi', MO: 'Missouri', MT: 'Montana',
  NE: 'Nebraska', NV: 'Nevada', NH: 'New Hampshire', NJ: 'New Jersey',
  NM: 'New Mexico', NY: 'New York', NC: 'North Carolina', ND: 'North Dakota',
  OH: 'Ohio', OK: 'Oklahoma', OR: 'Oregon', PA: 'Pennsylvania',
  RI: 'Rhode Island', SC: 'South Carolina', SD: 'South Dakota', TN: 'Tennessee',
  TX: 'Texas', UT: 'Utah', VT: 'Vermont', VA: 'Virginia', WA: 'Washington',
  WV: 'West Virginia', WI: 'Wisconsin', WY: 'Wyoming',
  PR: 'Puerto Rico', VI: 'Virgin Islands', GU: 'Guam', AS: 'American Samoa',
};

function normalizeState(v: unknown): string | undefined {
  if (typeof v !== 'string' || !v.trim()) return undefined;
  const raw = v.trim();
  const abbr = US_STATES[raw.toUpperCase()];
  if (abbr) return abbr;
  // Title-case so "california" / "NEW JERSEY" still hit the exact match.
  const titled = raw.toLowerCase().replace(/\b[a-z]/g, (c) => c.toUpperCase());
  return Object.values(US_STATES).includes(titled) ? titled : raw;
}

async function query(
  res: ResourceKey,
  filters: Record<string, string[]>,
  limit: number,
  cred: { user: string; key: string },
  sortorder: 'ASC' | 'DESC' = 'DESC',
): Promise<Record<string, unknown>[]> {
  const def = RESOURCES[res];
  const body = {
    start: 1,
    rows: limit,
    sort: def.dateField,
    sortorder,
    columns: def.columns,
    filters,
  };

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  let r: Response;
  try {
    r = await fetch(`${BASE}/${def.path}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': UA,
        'Authorization-User': cred.user,
        'Authorization-Key': cred.key,
      },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (/abort/i.test(msg)) {
      throw new Error(`upstream_down: FDA Data Dashboard timed out after ${TIMEOUT_MS / 1000}s.`);
    }
    // `msg` is a caught message that can itself lead with a routing token;
    // wrapping it would push that token off position 0, where the gateway stops
    // seeing it. This message declares its own class, so strip the inner one.
    throw new Error(
      `upstream_down: could not reach FDA Data Dashboard — ${dropClassPrefix(msg)}`,
    );
  } finally {
    clearTimeout(timer);
  }

  const text = await r.text();

  if (r.status === 401 || r.status === 403) {
    // Deliberately no class prefix: `auth_required` is INFERRED from wording by
    // the gateway and is not a strippable token, so emitting it as a prefix
    // leaks the token to the caller.
    throw new Error(
      'FDA Data Dashboard returned 401 — the credential was rejected. It must be "email:key" and both halves must match what FDA issued; the e-mail is the Authorization-User, not a username you choose.',
    );
  }
  if (r.status === 429) {
    throw new Error('upstream_throttled: FDA Data Dashboard rate-limited the request (429).');
  }
  if (r.status === 400) {
    // The API names the offending field — surface it, it is the actionable part.
    throw new Error(`user_error: FDA Data Dashboard rejected the query — ${text.slice(0, 300)}`);
  }
  if (!r.ok) {
    throw new Error(`upstream_down: FDA Data Dashboard returned ${r.status}. ${text.slice(0, 200)}`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error('upstream_down: FDA Data Dashboard returned a non-JSON response.');
  }

  // Result rows arrive under `result`; tolerate a bare array.
  const rows = Array.isArray(parsed)
    ? parsed
    : ((parsed as Record<string, unknown>)?.result as unknown[]) ?? [];
  return (Array.isArray(rows) ? rows : []) as Record<string, unknown>[];
}

/** Shared date/geography filters, applied against the resource's own field names. */
function commonFilters(res: ResourceKey, args: Record<string, unknown>): Record<string, string[]> {
  const def = RESOURCES[res];
  const f: Record<string, string[]> = {};
  put(f, def.nameField, args.firm);
  put(f, 'State', normalizeState(args.state));
  put(f, 'CountryName', args.country);
  put(f, 'FiscalYear', args.fiscal_year);

  for (const [arg, suffix] of [['since', 'From'], ['until', 'To']] as const) {
    const v = args[arg];
    if (typeof v === 'string' && v.trim()) {
      if (!isDate(v.trim())) {
        throw new Error(`user_error: ${arg} must be YYYY-MM-DD — got "${v}".`);
      }
      f[`${def.dateField}${suffix}`] = [v.trim()];
    }
  }
  return f;
}

// ---------------------------------------------------------------------------
// Tools

const tools: McpToolExport['tools'] = [
  {
    name: 'fda_inspections',
    description:
      'FDA inspection results with their final classification — NAI (no action indicated), VAI (voluntary action indicated) or OAI (official action indicated, the serious one). Covers FDA-regulated establishments worldwide (drug, device, food, biologics), not just US sites. Search by firm name (substring), state, country, product type or date range. Source: FDA Data Dashboard (OII). This is inspection OUTCOME data — openFDA does not carry it.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        firm: { type: 'string', description: 'Firm legal-name substring, e.g. "Intas" or "Sun Pharma".' },
        state: { type: 'string', description: 'US state, as a postal code ("NJ") or full name ("New Jersey") — both work. Foreign sites carry no state; filter those by country.' },
        country: { type: 'string', description: 'Country name as FDA spells it, e.g. "India", "China".' },
        classification: {
          type: 'string',
          description: 'Final classification: NAI, VAI or OAI. OAI is the one that signals enforcement risk.',
        },
        product_type: { type: 'string', description: 'e.g. "Drugs", "Devices", "Foods", "Biologics".' },
        since: { type: 'string', description: 'Earliest inspection end date, YYYY-MM-DD.' },
        until: { type: 'string', description: 'Latest inspection end date, YYYY-MM-DD.' },
        fiscal_year: { type: 'string', description: 'FDA fiscal year, e.g. "2026".' },
        limit: { type: 'number', description: `Rows to return (default 50, max ${MAX_ROWS}).` },
        _apiKey: { type: 'string', description: KEY_DESC },
      },
    },
  },
  {
    name: 'fda_483_citations',
    description:
      'Individual Form 483 observations cited during FDA inspections — the specific CFR reference and what the investigator actually wrote. Use this to see WHY a site was cited, not just that it was. Search by firm, country, state or date range. Source: FDA Data Dashboard (OII).',
    inputSchema: {
      type: 'object' as const,
      properties: {
        firm: { type: 'string', description: 'Firm legal-name substring.' },
        state: { type: 'string', description: 'US state, as a postal code ("NJ") or full name ("New Jersey") — both work. Foreign sites carry no state; filter those by country.' },
        country: { type: 'string', description: 'Country name, e.g. "India".' },
        cfr: { type: 'string', description: 'CFR citation substring, e.g. "211.192".' },
        since: { type: 'string', description: 'Earliest inspection end date, YYYY-MM-DD.' },
        until: { type: 'string', description: 'Latest inspection end date, YYYY-MM-DD.' },
        fiscal_year: { type: 'string', description: 'FDA fiscal year, e.g. "2026".' },
        limit: { type: 'number', description: `Rows to return (default 50, max ${MAX_ROWS}).` },
        _apiKey: { type: 'string', description: KEY_DESC },
      },
    },
  },
  {
    name: 'fda_compliance_actions',
    description:
      'FDA compliance and enforcement actions taken against a firm — warning letters, injunctions, seizures, debarments — with the action type and the date taken. Search by firm, country, state, product type or date range. Source: FDA Data Dashboard (OII).',
    inputSchema: {
      type: 'object' as const,
      properties: {
        firm: { type: 'string', description: 'Firm legal-name substring.' },
        state: { type: 'string', description: 'US state, as a postal code ("NJ") or full name ("New Jersey") — both work. Foreign sites carry no state; filter those by country.' },
        country: { type: 'string', description: 'Country name.' },
        action_type: { type: 'string', description: 'Action type substring, e.g. "Warning Letter".' },
        product_type: { type: 'string', description: 'e.g. "Drugs", "Devices".' },
        since: { type: 'string', description: 'Earliest action date, YYYY-MM-DD.' },
        until: { type: 'string', description: 'Latest action date, YYYY-MM-DD.' },
        fiscal_year: { type: 'string', description: 'FDA fiscal year.' },
        limit: { type: 'number', description: `Rows to return (default 50, max ${MAX_ROWS}).` },
        _apiKey: { type: 'string', description: KEY_DESC },
      },
    },
  },
  {
    name: 'fda_import_refusals',
    description:
      'Shipments refused entry to the US by FDA at the border, with the refusal charges (the reason), product code and date. A leading indicator of supply risk for a foreign manufacturer. Search by firm, country, product or date range. Source: FDA Data Dashboard (OII).',
    inputSchema: {
      type: 'object' as const,
      properties: {
        firm: { type: 'string', description: 'Firm name substring (this resource keys on FirmName).' },
        state: { type: 'string', description: 'US state, as a postal code ("NJ") or full name ("New Jersey") — both work. Foreign sites carry no state; filter those by country.' },
        country: { type: 'string', description: 'Country of origin, e.g. "India".' },
        product: { type: 'string', description: 'Product-code description substring, e.g. "Antibiotic".' },
        since: { type: 'string', description: 'Earliest refusal date, YYYY-MM-DD.' },
        until: { type: 'string', description: 'Latest refusal date, YYYY-MM-DD.' },
        limit: { type: 'number', description: `Rows to return (default 50, max ${MAX_ROWS}).` },
        _apiKey: { type: 'string', description: KEY_DESC },
      },
    },
  },
  {
    name: 'fda_firm_risk_profile',
    description:
      'One-call FDA regulatory risk profile for a manufacturer: inspection history with the NAI/VAI/OAI split, the CFR sections it is most often cited under, compliance actions taken against it, and import refusals at the border. Resolves the firm name to its FDA establishment identifiers (FEI) so you can see whether several sites are involved. Use this for supplier due-diligence or to check a pharma name before an investment or sourcing decision.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        firm: { type: 'string', description: 'Firm name substring, e.g. "Intas".' },
        since: { type: 'string', description: 'Only count events on/after this date, YYYY-MM-DD.' },
        limit: { type: 'number', description: `Rows to scan per source (default 200, max ${MAX_ROWS}).` },
        _apiKey: { type: 'string', description: KEY_DESC },
      },
      required: ['firm'],
    },
  },
];

// ---------------------------------------------------------------------------

function tally(rows: Record<string, unknown>[], field: string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const r of rows) {
    const v = r[field];
    if (typeof v === 'string' && v.trim()) out[v.trim()] = (out[v.trim()] ?? 0) + 1;
  }
  return out;
}

function topN(counts: Record<string, number>, n: number): { value: string; count: number }[] {
  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([value, count]) => ({ value, count }));
}

async function riskProfile(
  args: Record<string, unknown>,
  cred: { user: string; key: string },
): Promise<unknown> {
  const firm = typeof args.firm === 'string' ? args.firm.trim() : '';
  if (!firm) throw new Error('user_error: firm is required.');
  const limit = clampLimit(args.limit, 200);
  const since = typeof args.since === 'string' ? args.since.trim() : '';
  if (since && !isDate(since)) {
    throw new Error(`user_error: since must be YYYY-MM-DD — got "${args.since}".`);
  }

  const build = (res: ResourceKey): Record<string, string[]> => {
    const def = RESOURCES[res];
    const f: Record<string, string[]> = { [def.nameField]: [firm] };
    if (since) f[`${def.dateField}From`] = [since];
    return f;
  };

  // One source failing must not blank the whole profile — a firm with no import
  // refusals is a normal, meaningful result, and so is a single resource being
  // briefly unavailable. Record why instead of dropping it silently.
  const keys: ResourceKey[] = ['inspections', 'citations', 'compliance', 'refusals'];
  const settled = await Promise.all(
    keys.map(async (k) => {
      try {
        return { k, rows: await query(k, build(k), limit, cred), error: null as string | null };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        // A rejected credential is fatal for every source, not a per-source gap.
        if (/returned 401/.test(msg)) throw err;
        return { k, rows: [] as Record<string, unknown>[], error: msg.slice(0, 200) };
      }
    }),
  );

  const by = Object.fromEntries(settled.map((s) => [s.k, s])) as Record<
    ResourceKey,
    { k: ResourceKey; rows: Record<string, unknown>[]; error: string | null }
  >;

  const insp = by.inspections.rows;
  const classes = tally(insp, 'ClassificationCode');

  // FEIs seen across every source, so multi-site firms are visible.
  const feis = new Map<string, string>();
  for (const s of settled) {
    for (const r of s.rows) {
      const fei = r.FEINumber == null ? '' : String(r.FEINumber).trim();
      const nm = (r.LegalName ?? r.FirmName ?? '') as string;
      if (fei && !feis.has(fei)) feis.set(fei, typeof nm === 'string' ? nm : '');
    }
  }

  const unavailable = settled.filter((s) => s.error).map((s) => ({ source: s.k, error: s.error }));

  return {
    firm_query: firm,
    since: since || null,
    matched_establishments: [...feis.entries()].map(([fei, name]) => ({ fei, name })),
    matched_fei_count: feis.size,
    inspections: {
      total: insp.length,
      by_classification: classes,
      oai_count: classes.OAI ?? 0,
      most_recent: (insp[0]?.InspectionEndDate as string) ?? null,
      countries: topN(tally(insp, 'CountryName'), 5),
    },
    citations: {
      total: by.citations.rows.length,
      top_cfr: topN(tally(by.citations.rows, 'ActCFRNumber'), 5),
    },
    compliance_actions: {
      total: by.compliance.rows.length,
      by_type: tally(by.compliance.rows, 'ActionType'),
      most_recent: (by.compliance.rows[0]?.ActionTakenDate as string) ?? null,
    },
    import_refusals: {
      total: by.refusals.rows.length,
      top_charges: topN(tally(by.refusals.rows, 'RefusalCharges'), 5),
      most_recent: (by.refusals.rows[0]?.RefusalDate as string) ?? null,
    },
    // Counts are over the rows scanned (`limit` per source), not necessarily the
    // firm's complete history — say so rather than implying a census.
    scanned_per_source: limit,
    truncated: settled.some((s) => s.rows.length >= limit),
    sources_unavailable: unavailable.length ? unavailable : undefined,
    source: 'FDA Data Dashboard (Office of Inspections and Investigations)',
  };
}

async function callTool(name: string, args: Record<string, unknown>): Promise<unknown> {
  const cred = credentials(args);

  const simple = async (res: ResourceKey, extra: (f: Record<string, string[]>) => void) => {
    const f = commonFilters(res, args);
    extra(f);
    const limit = clampLimit(args.limit, 50);
    const rows = await query(res, f, limit, cred);
    return {
      count: rows.length,
      truncated: rows.length >= limit,
      results: rows,
      source: 'FDA Data Dashboard (Office of Inspections and Investigations)',
    };
  };

  switch (name) {
    case 'fda_inspections':
      return simple('inspections', (f) => {
        put(f, 'ClassificationCode', args.classification);
        put(f, 'ProductType', args.product_type);
      });
    case 'fda_483_citations':
      return simple('citations', (f) => put(f, 'ActCFRNumber', args.cfr));
    case 'fda_compliance_actions':
      return simple('compliance', (f) => {
        put(f, 'ActionType', args.action_type);
        put(f, 'ProductType', args.product_type);
      });
    case 'fda_import_refusals':
      return simple('refusals', (f) => put(f, 'ProductCodeDescription', args.product));
    case 'fda_firm_risk_profile':
      return riskProfile(args, cred);
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

export default { tools, callTool, meter: { credits: 1 } } satisfies McpToolExport;
