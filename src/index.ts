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
 * SSRF guard for fetching user- or registry-supplied URLs.
 *
 * Workers that fetch URLs an attacker can influence (submission test_endpoint,
 * scraper introspect remote_url, gateway generate_llms_txt) must run the target
 * through this first. Cloudflare Workers don't route to RFC-1918 by default, but
 * the worker is still an open-fetch primitive against internal CF services,
 * cloud metadata endpoints, and tenant-private origins reachable from egress —
 * so we enforce https-only and block private / loopback / link-local / metadata
 * hosts before the fetch.
 */

// Hostnames that must never be fetched, regardless of resolution.
const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'metadata.google.internal',
]);

/** Parse a dotted-quad IPv4 string into its 4 octets, or null if not IPv4. */
function parseIpv4(host: string): [number, number, number, number] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!m) return null;
  const octets = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
  if (octets.some((o) => o > 255)) return null;
  return octets as [number, number, number, number];
}

/**
 * Expand an IPv6 literal to its 8 numeric groups, or null if it isn't one.
 *
 * Needed because you cannot pattern-match IPv6 as text: `::ffff:127.0.0.1`,
 * `::ffff:7f00:1` and `0:0:0:0:0:ffff:7f00:0001` are the same address, and
 * WHATWG URL rewrites whichever you typed into the compressed hex form. The
 * guard has to compare numbers, not strings.
 */
function expandIpv6(host: string): number[] | null {
  let h = host.split('%')[0]; // drop any zone id (fe80::1%eth0)
  if (!h.includes(':')) return null;

  // A trailing dotted quad (::ffff:127.0.0.1) is legal IPv6 text. URL normally
  // normalizes it away, but accept it so callers passing a raw hostname — not
  // one that round-tripped through URL — get the same verdict.
  const lastColon = h.lastIndexOf(':');
  const tail = h.slice(lastColon + 1);
  if (tail.includes('.')) {
    const o = parseIpv4(tail);
    if (!o) return null;
    const hi = ((o[0] << 8) | o[1]).toString(16);
    const lo = ((o[2] << 8) | o[3]).toString(16);
    h = `${h.slice(0, lastColon + 1)}${hi}:${lo}`;
  }

  const halves = h.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const back = halves.length === 2 ? (halves[1] ? halves[1].split(':') : []) : [];

  let groups: string[];
  if (halves.length === 2) {
    const fill = 8 - head.length - back.length;
    if (fill < 0) return null;
    groups = [...head, ...Array(fill).fill('0'), ...back];
  } else {
    groups = head;
  }
  if (groups.length !== 8) return null;

  const nums = groups.map((g) => (/^[0-9a-f]{1,4}$/.test(g) ? parseInt(g, 16) : NaN));
  return nums.some(Number.isNaN) ? null : nums;
}

/**
 * The IPv4 address embedded in an IPv6 literal, for the three prefixes that
 * carry one, or null. Each is a way to name an IPv4 destination in IPv6 syntax,
 * so each is a way to smuggle 127.0.0.1 or 169.254.169.254 past a v4-only check.
 */
function embeddedIpv4(g: number[]): [number, number, number, number] | null {
  const low32 = (): [number, number, number, number] => [g[6] >> 8, g[6] & 0xff, g[7] >> 8, g[7] & 0xff];
  const zeroTo5 = g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0;
  if (zeroTo5 && g[5] === 0xffff) return low32(); // ::ffff:0:0/96  IPv4-mapped
  if (zeroTo5 && g[5] === 0) return low32();      // ::/96          IPv4-compatible (deprecated)
  if (g[0] === 0x64 && g[1] === 0xff9b) return low32(); // 64:ff9b::/96 + /48  NAT64
  return null;
}

function isPrivateIpv4([a, b]: [number, number, number, number]): boolean {
  if (a === 10) return true;                         // 10.0.0.0/8
  if (a === 127) return true;                        // loopback
  if (a === 0) return true;                          // 0.0.0.0/8
  if (a === 169 && b === 254) return true;           // link-local / cloud metadata (169.254.169.254)
  if (a === 172 && b >= 16 && b <= 31) return true;  // 172.16.0.0/12
  if (a === 192 && b === 168) return true;           // 192.168.0.0/16
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
  if (a >= 224) return true;                         // multicast / reserved
  return false;
}

/** True if the URL is safe to fetch (https + public host). */
function isPublicHttpUrl(raw: string): boolean {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return false;
  }
  // https only — blocks http://, file://, gopher://, ftp://, data:, etc.
  if (u.protocol !== 'https:') return false;

  let host = u.hostname.toLowerCase();
  if (!host) return false;
  // URL.hostname returns IPv6 literals bracketed (e.g. "[fc00::1]"); strip them
  // so the prefix/equality checks below see the bare address.
  const isV6 = host.startsWith('[') && host.endsWith(']');
  if (isV6) host = host.slice(1, -1);

  if (BLOCKED_HOSTNAMES.has(host)) return false;
  // Any *.localhost / *.internal / *.local
  if (host.endsWith('.localhost') || host.endsWith('.internal') || host.endsWith('.local')) return false;

  // IPv6 literals: block loopback (::1), unspecified (::), unique-local (fc00::/7),
  // and link-local (fe80::/10).
  if (isV6 || host.includes(':')) {
    if (host === '::1' || host === '::') return false;
    if (host.startsWith('fc') || host.startsWith('fd')) return false; // unique-local
    if (host.startsWith('fe8') || host.startsWith('fe9') || host.startsWith('fea') || host.startsWith('feb')) return false; // link-local

    // An IPv6 literal can carry an IPv4 destination inside it (IPv4-mapped,
    // IPv4-compatible, NAT64). Decode it and apply the same v4 rules, so
    // [::ffff:169.254.169.254] is blocked exactly like 169.254.169.254.
    //
    // This previously matched on a dotted quad in the tail — which URL never
    // produces, since it serializes IPv6 in hex — so the check was dead code
    // and mapped loopback/metadata addresses passed (2026-08-01 review).
    const groups = expandIpv6(host);
    if (groups) {
      const v4 = embeddedIpv4(groups);
      if (v4 && isPrivateIpv4(v4)) return false;
    }
    return true;
  }

  const ipv4 = parseIpv4(host);
  if (ipv4) return !isPrivateIpv4(ipv4);

  return true;
}

/** Throws an Error with a stable code-ish message if the URL isn't safe to fetch. */
function assertPublicHttpUrl(raw: string): URL {
  if (!isPublicHttpUrl(raw)) {
    throw new Error(`blocked_url: refusing to fetch non-public or non-https URL`);
  }
  return new URL(raw);
}

// Path, query, fragment, userinfo, backslash, whitespace. Every one of these
// makes `https://${host}/api/...` mean something other than it reads as.
const HOSTNAME_FORBIDDEN = /[/?#@\\\s]/;

/**
 * Validate a caller-supplied HOSTNAME that a pack will interpolate into a URL
 * (`https://${host}/api/...`). Returns the normalized `hostname[:port]`.
 *
 * Use this instead of a hand-rolled strip-and-hope (fleet #214). Pinning the
 * scheme to https:// looks like protection and is not — the host segment is
 * still attacker-controlled, and two shapes walk straight past a protocol pin:
 *
 *   QUERY TRUNCATION  host = "evil.example/collect?x="
 *     `https://evil.example/collect?x=/api/v1/timelines/tag/x` — the API path
 *     the pack appended is now part of the QUERY STRING of an attacker's URL.
 *     The pack believes it called a Mastodon endpoint. It called whatever it
 *     was pointed at, and hands the body back to the caller.
 *
 *   USERINFO CONFUSION  host = "mastodon.social@evil.example"
 *     Everything before `@` is credentials, so this fetches evil.example while
 *     reading as legitimate in a log line or a code review.
 *
 * Stripping a leading `https://` and trailing slashes — the common shape in
 * these packs — defeats neither, and a `.replace(/\/.*$/, '')` that removes a
 * path still leaves `?`, `#` and `@` untouched (verified live against three
 * packs on 2026-08-10 before this landed).
 *
 * Rejects rather than sanitizes. A host with a path in it is not a typo we
 * should guess at, and silently truncating to `evil.example` would still fetch
 * a host the caller never legitimately meant.
 *
 * @param raw   the caller-supplied value; a leading scheme and trailing
 *              slashes are tolerated because callers habitually paste URLs.
 * @param label argument name, so the error tells the agent what to fix.
 */
function assertPublicHostname(raw: unknown, label = 'host'): string {
  const input = typeof raw === 'string' ? raw.trim() : '';
  if (!input) throw new Error(`blocked_host: ${label} is empty`);

  const stripped = input.replace(/^https?:\/\//i, '').replace(/\/+$/, '');
  if (!stripped || HOSTNAME_FORBIDDEN.test(stripped)) {
    throw new Error(
      `blocked_host: ${label} "${input}" must be a bare hostname — no path, query string, fragment, "@" or whitespace.`,
    );
  }

  let u: URL;
  try {
    u = new URL(`https://${stripped}/`);
  } catch {
    throw new Error(`blocked_host: ${label} "${input}" is not a valid hostname.`);
  }

  // Reuse the vetted private/loopback/link-local/IPv6-mapped logic rather than
  // re-deriving it per pack — the packs' inlined copies each missed something
  // different (CGNAT 100.64/10 in one, IPv4-mapped IPv6 in another).
  //
  // Runs BEFORE the parse-equality check below so the caller gets the
  // informative reason. [::ffff:169.254.169.254] canonicalizes to
  // [::ffff:a9fe:a9fe], which trips equality too — "non-public host" is the
  // answer worth giving.
  if (!isPublicHttpUrl(u.toString())) {
    throw new Error(`blocked_host: refusing to fetch non-public host "${input}"`);
  }

  // Last-resort catch-all: the parser must agree with what we were handed.
  // Anything that survives the character check but still reparses into a
  // DIFFERENT host is the class of trick this function exists to stop, so treat
  // disagreement as hostile rather than trying to enumerate the tricks.
  //
  // Two legitimate transformations are exempt, or this would reject real hosts:
  //   - IDN punycoding (münchen.de → xn--mnchen-3ya.de). Every attack shape
  //     above is ASCII, so skipping non-ASCII costs the guard nothing.
  //   - IPv6 canonicalization ([2001:0db8::1] → [2001:db8::1]). The address is
  //     already fully validated above, where it matters.
  const asciiOnly = !/[^\x20-\x7E]/.test(stripped);
  const isV6Literal = stripped.startsWith('[');
  const expected = stripped.toLowerCase().replace(/:\d+$/, '');
  if (asciiOnly && !isV6Literal && u.hostname !== expected) {
    throw new Error(
      `blocked_host: ${label} "${input}" did not parse as the hostname it appears to be (got "${u.hostname}").`,
    );
  }

  return u.host;
}

/**
 * Validate a single DNS LABEL that a pack interpolates before a FIXED suffix
 * (`https://${sub}.freshdesk.com`, `https://${region}.api.riotgames.com`).
 *
 * A different problem from assertPublicHostname, and stricter: because the
 * suffix is fixed, the only escape is a character that ends the label early, so
 * a positive charset is both sufficient and simpler than parsing. Do NOT swap
 * these two — validating a label with assertPublicHostname would accept dots
 * and a port, and validating a hostname with this would reject every real one.
 *
 * These packs send credentials, so a label that escapes the suffix is a key
 * leak, not just an SSRF.
 */
function assertHostLabel(raw: unknown, label = 'subdomain'): string {
  const v = typeof raw === 'string' ? raw.trim() : '';
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(v)) {
    throw new Error(
      `blocked_host: ${label} "${v}" must be a bare DNS label — letters, digits and hyphens only (e.g. "mycompany").`,
    );
  }
  return v.toLowerCase();
}

/**
 * Fetch a URL with SSRF protection that ALSO covers redirects.
 *
 * A plain `fetch(url)` uses `redirect: 'follow'`, which silently defeats an
 * `isPublicHttpUrl()` pre-check: a public URL can return a 3xx to a private /
 * loopback / metadata host and the runtime follows it without re-validation
 * (and a hostname can resolve to a private address regardless). safeFetch
 * validates the initial URL AND every redirect hop — it fetches with
 * `redirect: 'manual'`, re-runs isPublicHttpUrl on each `Location`, and
 * refuses to follow a hop to a non-public / non-https target.
 *
 * Throws `blocked_url: …` if the initial URL or any hop is unsafe, or if the
 * redirect budget is exceeded. Callers already wrap probes in try/catch, so a
 * blocked redirect flows through their normal failure path (submission stays
 * pending, monitor records a down check, introspection error, etc.).
 *
 * Method + body from `init` are preserved across hops (every hop is validated,
 * so re-issuing the request to a vetted public host is safe); any caller-set
 * `redirect` is overridden to 'manual'.
 *
 * Credential headers are DROPPED on a cross-origin hop. Built-in fetch does
 * this for you; a manual redirect loop has to do it by hand, and skipping it
 * turns "public host redirects us somewhere" into "public host harvests our
 * Authorization header" — the initial host chooses the Location, so it chooses
 * where the credential goes.
 */
const CREDENTIAL_HEADERS = ['authorization', 'cookie', 'x-api-key', 'proxy-authorization'];

/** Strip credential headers from `init`, used when a redirect crosses origins. */
function stripCredentials(init: RequestInit | undefined): RequestInit | undefined {
  if (!init?.headers) return init;
  const h = new Headers(init.headers as HeadersInit);
  let removed = false;
  for (const name of CREDENTIAL_HEADERS) {
    if (h.has(name)) {
      h.delete(name);
      removed = true;
    }
  }
  return removed ? { ...init, headers: h } : init;
}

async function safeFetch(
  raw: string,
  init?: RequestInit,
  opts?: { maxRedirects?: number },
): Promise<Response> {
  const maxRedirects = opts?.maxRedirects ?? 3;
  const origin = assertPublicHttpUrl(raw).origin;
  let target = assertPublicHttpUrl(raw).toString();
  let reqInit = init;
  for (let hop = 0; ; hop++) {
    const res = await fetch(target, { ...reqInit, redirect: 'manual' });
    const location = res.status >= 300 && res.status < 400 ? res.headers.get('location') : null;
    if (!location) return res;
    if (hop >= maxRedirects) throw new Error(`blocked_url: too many redirects (>${maxRedirects})`);
    let next: string;
    try {
      // Resolve relative Location against the current target before validating.
      next = new URL(location, target).toString();
    } catch {
      throw new Error('blocked_url: invalid redirect location');
    }
    if (!isPublicHttpUrl(next)) throw new Error('blocked_url: redirect to non-public URL');
    if (new URL(next).origin !== origin) reqInit = stripCredentials(reqInit);
    target = next;
  }
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
