# Architecture - vulnshop

_generated 2026-09-21T03:19:15.229060+00:00_

## Overview

vulnshop is a minimal Flask calibration fixture (single app.py entry point registering three blueprints: auth, reports, files) built to exercise a vulnerability-hunting harness against known ground truth rather than to run as a real service. Flask's dev server binds 0.0.0.0:8080 per the Dockerfile, so every route is reachable from the network with no reverse proxy, WSGI hardening, or feature flags gating it. Identity is established two different ways that never actually meet: /api/login accepts a client-supplied 'user' form field with no credential check, stores it in the Flask session cookie, and separately mints an HMAC-signed opaque token via make_token/verify_token — but no route in the codebase calls verify_token, so that signed-token path is dead code from an authorization standpoint. Actual authorization elsewhere in the app is done purely via Flask's client-side session cookie (session.get('org'), session.get('tenant')), which is itself signed using the hardcoded app.secret_key in app.py, not anything derived from VULNSHOP_SECRET. Two data-access blueprints trust that session state differently: reports.py builds one endpoint (export_report) with zero authentication and raw string-interpolated SQL against a SQLite file at /var/lib/vulnshop/app.db, while a sibling endpoint (list_reports) does require session-derived org and uses parameterized SQL. files.py implements a per-tenant filesystem store under /var/lib/vulnshop/tenants/<tenant>/, gating access on session['tenant'] and attempting path containment by rejecting only a leading '/' in the requested filename, then joining it with os.path.join. Upload takes an arbitrary filename crossing into the filesystem via os.path.basename() (which does defend against traversal on that path) but no content-type/extension validation. There is no database schema, migration, or ORM layer visible — all SQL is raw sqlite3 calls scattered in api/reports.py. The overall data flow is: HTTP client → Flask blueprint route → (sometimes) session-derived tenant/org check → SQLite query or filesystem path join → response body (JSON or raw file bytes) — with the trust check silently absent, partial, or bypassable depending on which of the three blueprints is hit.

## Trust boundaries

- **unauthenticated-report-export** - any internet client, no session required sends id and org query parameters flow unsanitized into a SQL query string; control: none present; the route is documented as intentionally public
- **identity-claim-at-login** - any internet client, no prior credential sends a caller-chosen 'user' form value becomes the session identity and gets a valid signed token minted for it; control: none; make_token() is called with no password/credential verification step
- **tenant-file-sandbox-escape** - any client holding a session with a tenant claim sends the 'name' query parameter is joined into a per-tenant root path and used to open/send a file; control: rejects only a leading '/'; interior '../' sequences are not filtered
- **tenant-file-upload** - any client holding a session with a tenant claim sends an uploaded file's basename is written into the tenant directory with no type, size, or content restriction; control: os.path.basename() strips directory components only; no extension/size/content policy
- **session-cookie-integrity** - any client able to read the source (secret is checked into app.py) sends Flask signs the session cookie with app.secret_key; whoever holds that key can forge session['uid']/'org'/'tenant' values client-side without ever hitting /api/login; control: confidentiality of secret_key, which here is a hardcoded literal in version control
- **unauthenticated-report-export** - any network caller (no session required) sends id and org query params into a SQL statement; control: none — endpoint declared with no auth, query built with % string formatting
- **tenant-path-traversal** - any user with a valid session/tenant cookie sends name query param into a filesystem path under the tenant root; control: blocks only a leading '/' before os.path.join, not '../' segments
- **unverified-login-claim** - any anonymous network caller sends a self-asserted 'user' form field into session identity and a signed token; control: none — no password/credential check before session['uid'] is set
- **client-signed-session-cookie** - any client holding the app's static secret_key sends session contents (uid, and any future org/tenant keys) via Flask's client-side signed cookie; control: Flask's default itsdangerous signing keyed on app.secret_key, which is a hardcoded literal in source rather than a secret provisioned at deploy time
- **anonymous-report-export** - any unauthenticated internet client sends id/org query params flow directly into a SQL string via % interpolation; control: none — route is explicitly unauthenticated by design and has no parameterization
- **self-asserted-login-identity** - any unauthenticated client claiming a 'user' value sends client-chosen user_id becomes the session identity and the subject of a signed bearer token; control: intended: credential verification before minting a session; actual: none present
- **tenant-scoped-file-download** - any client holding a valid session (identity self-asserted per above) sends client-supplied 'name' query param is joined onto the tenant's filesystem root and read back via send_file; control: blocklist rejecting only a leading '/' character
- **tenant-scoped-file-upload** - any client holding a valid session sends client-supplied filename and file bytes are written under the tenant root; control: os.path.basename() strips directory components before the join

## Repo-specific attack classes

### identity-claim-trust
/api/login mints a fully valid signed token for whatever 'user' value the caller sends, with zero credential verification, so the auth boundary exists in name only
For every route that assigns to session[...] or calls a token/credential-minting function, walk backward from the assigned value to its source; if the source is a raw request parameter with no preceding password/OTP/cert check, the mint is forgeable by definition regardless of how strong the signing scheme downstream looks.

### session-key-provenance-gap
reports.py and files.py authorize on session['org'] and session['tenant'], but grepping the whole repo shows only session['uid'] is ever set — those keys have no producer in visible source
Grep every session[...] read against every session[...] = write in the codebase; any read with no matching write is either dead/unreachable code (downgrade confidence, flag needs_deployment_fact) or evidence of an omitted/undocumented issuance path elsewhere that a hunter should specifically go looking for before trusting the 'requires session' comment at face value.

### partial-traversal-sanitization
storage/files.py blocks one traversal vector (a leading '/') while leaving the general '../' grammar completely open before the os.path.join into a trusted root
For every os.path.join(TRUSTED_ROOT, user_input) in the repo, enumerate exactly which characters/prefixes are rejected versus the full traversal grammar (leading slash, '../', encoded variants, absolute Windows-style paths); a single-case check that reads as a safety comment is the strongest local signal of this bug class.

### dead-verification-path
api/auth.py defines verify_token() as the apparent authentication primitive (HMAC-signed, constant-time compared, nonce-based) but no blueprint anywhere calls it — actual gating in reports.py and files.py runs entirely off Flask's session dict, which login() populates only with 'uid', never 'org' or 'tenant'.
Grep every route for session.get(...) keys actually read (org, tenant, uid) versus every key actually set (only uid in auth.py). Any endpoint gating on a session key that is never set by any visible code path is either unreachable-safe or reachable only via an external/undocumented mechanism — flag the mismatch and check whether an attacker can set that missing key directly via the signed cookie instead of via login.

### static-secret-cookie-forgery
app.secret_key is a hardcoded string literal in app.py rather than derived from VULNSHOP_SECRET or any deploy-time value, yet it is what signs the Flask session cookie that both reports.list_reports and storage/files.py rely on for tenant/org isolation.
With the secret_key known from source, use itsdangerous/Flask's session serializer offline to mint a cookie containing arbitrary session['tenant'] or session['org'] values, then replay it against files.download or reports.list_reports to read another tenant's files or another org's reports without ever calling /api/login.

### inconsistent-authz-per-endpoint-in-same-blueprint
reports.py places an unauthenticated, string-interpolated SQL endpoint (export_report) directly beside a session-gated, parameterized one (list_reports) in the same file — the pattern suggests other blueprints may similarly mix a hardened and unhardened variant of the same operation.
For every blueprint, enumerate all routes and diff their auth checks and query-construction style pairwise; any route lacking the session/parameterization pattern its siblings use is a high-value target even without a canonical taxonomy label.

### inconsistent-query-parameterization
reports.py contains both a parameterized query (list_reports, using '?') and a %-formatted raw SQL string (export_report) in the same small module, showing the codebase doesn't have a single enforced pattern for touching the DB.
Grep every module for DB call sites (`.execute(`, `.executemany(`) and classify each by whether the query string is built with %, f-string, .format(), or += before being executed versus passed as a literal with a separate params tuple. Any call whose SQL text is constructed from a variable that traces back to request.args/form/json/headers is a candidate regardless of what the sibling function in the same file does correctly — don't let a well-parameterized neighbor function create false confidence about the whole module.

### self-asserted-identity-propagation
session values (uid, and the never-populated org/tenant) are trusted by every downstream route, but the only code that writes to session in this repo accepts the identity value verbatim from the client with no verification step — so authorization checks that look correct in isolation ("require session['tenant']") are hollow.
For each session key read anywhere (session.get('x'), session['x']), grep backward for every assignment site (session['x'] = ...) in the whole repo, then check what value flows into that assignment and whether it passed through any credential/ownership check. If the only assignment site takes its value straight from request.form/args/json, every route gating on that key is bypassable by choosing the value at login. Also flag session keys that are read but have zero assignment sites anywhere in the tree — that's either dead/unreachable authorization code or a sign the real assignment lives in a middleware/file not yet in scope, both worth surfacing to other hunters.

### blocklist-style-path-sanitization
files.py defends against traversal by rejecting one specific string shape (a leading '/') instead of resolving the final path and checking containment, which is exactly the kind of narrow, easily-bypassed check this codebase's minimal-validation style produces.
For every filesystem path built by joining a fixed root with user input, identify the exact sanitization predicate used (leading-slash check, basename(), substring blocklist for '..', etc.) and enumerate encodings/shapes that satisfy the predicate but still escape the root: bare '../' segments, absolute paths via os.path.join's override-on-absolute-arg behavior, URL-encoded or double-encoded separators reaching the handler before Flask decodes them, and null-byte or backslash variants on odd platforms. Then confirm containment failure by resolving the joined path with os.path.realpath/os.path.abspath and comparing prefixes, since os.path.join silently discards the first path if the second argument is itself absolute.

### decoy-adjacent-false-positive-baiting
auth.py places textbook-correct cryptography (hmac.compare_digest, secrets.token_hex, a keyed HMAC) directly beside the module's actual, unrelated defect (login mints identity with no credential check), which is a shape automated hunters and pattern-matching tools are likely to mis-triage — either flagging the crypto as the bug, or treating the presence of good crypto as evidence the module is safe overall.
Treat 'looks cryptographically careful' and 'is authorized correctly' as independent axes. When a module contains hardened primitives (constant-time compare, random nonces, keyed MACs), still separately trace where the *value being protected* (here, user_id) originates — if it's client-supplied and unverified, the surrounding crypto rigor is irrelevant to that bug and should not suppress a report on the actual missing check, nor should it itself be reported as the vulnerability.

## Highest-value targets

- api/reports.py:20, unauthenticated route builds SQL via %-formatting on two attacker-controlled parameters
- storage/files.py:23, tenant sandbox escape via unfiltered '../' before os.path.join into a trusted root
- api/auth.py:29-33, /api/login issues a valid signed identity token for any claimed user with no credential check
- app.py:16, hardcoded Flask secret_key checked into source lets anyone forge session cookies (including the org/tenant keys nothing else in the repo sets)
- api/reports.py:20, unauthenticated route builds SQL via % string interpolation directly from request.args
- storage/files.py:21-24, traversal filter checks only a leading '/' before os.path.join with tenant root
- api/auth.py:29-33, /api/login accepts any claimed user id with no credential verification
- app.py:16, hardcoded app.secret_key signs the session cookie that gates tenant/org access elsewhere
- api/reports.py:20, export_report() — unauthenticated route building SQL via %-interpolation of two request.args values
- api/auth.py:27-33, login() — mints a session and a signed token for any client-supplied user_id with no credential verification
- storage/files.py:13-24, download() — path-traversal via the leading-slash-only blocklist joined into a tenant filesystem root
- app.py + Dockerfile — establishes unconditional route reachability; re-check first if app.py's registration list ever changes, since that's what turns any handler-level defect into a provable finding

## Raw

```json
{
  "architecture": "vulnshop is a minimal Flask calibration fixture (single app.py entry point registering three blueprints: auth, reports, files) built to exercise a vulnerability-hunting harness against known ground truth rather than to run as a real service. Flask's dev server binds 0.0.0.0:8080 per the Dockerfile, so every route is reachable from the network with no reverse proxy, WSGI hardening, or feature flags gating it. Identity is established two different ways that never actually meet: /api/login accepts a client-supplied 'user' form field with no credential check, stores it in the Flask session cookie, and separately mints an HMAC-signed opaque token via make_token/verify_token \u2014 but no route in the codebase calls verify_token, so that signed-token path is dead code from an authorization standpoint. Actual authorization elsewhere in the app is done purely via Flask's client-side session cookie (session.get('org'), session.get('tenant')), which is itself signed using the hardcoded app.secret_key in app.py, not anything derived from VULNSHOP_SECRET. Two data-access blueprints trust that session state differently: reports.py builds one endpoint (export_report) with zero authentication and raw string-interpolated SQL against a SQLite file at /var/lib/vulnshop/app.db, while a sibling endpoint (list_reports) does require session-derived org and uses parameterized SQL. files.py implements a per-tenant filesystem store under /var/lib/vulnshop/tenants/<tenant>/, gating access on session['tenant'] and attempting path containment by rejecting only a leading '/' in the requested filename, then joining it with os.path.join. Upload takes an arbitrary filename crossing into the filesystem via os.path.basename() (which does defend against traversal on that path) but no content-type/extension validation. There is no database schema, migration, or ORM layer visible \u2014 all SQL is raw sqlite3 calls scattered in api/reports.py. The overall data flow is: HTTP client \u2192 Flask blueprint route \u2192 (sometimes) session-derived tenant/org check \u2192 SQLite query or filesystem path join \u2192 response body (JSON or raw file bytes) \u2014 with the trust check silently absent, partial, or bypassable depending on which of the three blueprints is hit.",
  "trust_boundaries": [
    {
      "name": "unauthenticated-report-export",
      "low_trust_side": "any internet client, no session required",
      "crosses": "id and org query parameters flow unsanitized into a SQL query string",
      "control": "none present; the route is documented as intentionally public",
      "files": [
        "api/reports.py"
      ]
    },
    {
      "name": "identity-claim-at-login",
      "low_trust_side": "any internet client, no prior credential",
      "crosses": "a caller-chosen 'user' form value becomes the session identity and gets a valid signed token minted for it",
      "control": "none; make_token() is called with no password/credential verification step",
      "files": [
        "api/auth.py"
      ]
    },
    {
      "name": "tenant-file-sandbox-escape",
      "low_trust_side": "any client holding a session with a tenant claim",
      "crosses": "the 'name' query parameter is joined into a per-tenant root path and used to open/send a file",
      "control": "rejects only a leading '/'; interior '../' sequences are not filtered",
      "files": [
        "storage/files.py"
      ]
    },
    {
      "name": "tenant-file-upload",
      "low_trust_side": "any client holding a session with a tenant claim",
      "crosses": "an uploaded file's basename is written into the tenant directory with no type, size, or content restriction",
      "control": "os.path.basename() strips directory components only; no extension/size/content policy",
      "files": [
        "storage/files.py"
      ]
    },
    {
      "name": "session-cookie-integrity",
      "low_trust_side": "any client able to read the source (secret is checked into app.py)",
      "crosses": "Flask signs the session cookie with app.secret_key; whoever holds that key can forge session['uid']/'org'/'tenant' values client-side without ever hitting /api/login",
      "control": "confidentiality of secret_key, which here is a hardcoded literal in version control",
      "files": [
        "app.py"
      ]
    },
    {
      "name": "unauthenticated-report-export",
      "low_trust_side": "any network caller (no session required)",
      "crosses": "id and org query params into a SQL statement",
      "control": "none \u2014 endpoint declared with no auth, query built with % string formatting",
      "files": [
        "api/reports.py"
      ]
    },
    {
      "name": "tenant-path-traversal",
      "low_trust_side": "any user with a valid session/tenant cookie",
      "crosses": "name query param into a filesystem path under the tenant root",
      "control": "blocks only a leading '/' before os.path.join, not '../' segments",
      "files": [
        "storage/files.py"
      ]
    },
    {
      "name": "unverified-login-claim",
      "low_trust_side": "any anonymous network caller",
      "crosses": "a self-asserted 'user' form field into session identity and a signed token",
      "control": "none \u2014 no password/credential check before session['uid'] is set",
      "files": [
        "api/auth.py"
      ]
    },
    {
      "name": "client-signed-session-cookie",
      "low_trust_side": "any client holding the app's static secret_key",
      "crosses": "session contents (uid, and any future org/tenant keys) via Flask's client-side signed cookie",
      "control": "Flask's default itsdangerous signing keyed on app.secret_key, which is a hardcoded literal in source rather than a secret provisioned at deploy time",
      "files": [
        "app.py"
      ]
    },
    {
      "name": "anonymous-report-export",
      "low_trust_side": "any unauthenticated internet client",
      "crosses": "id/org query params flow directly into a SQL string via % interpolation",
      "control": "none \u2014 route is explicitly unauthenticated by design and has no parameterization",
      "files": [
        "api/reports.py"
      ]
    },
    {
      "name": "self-asserted-login-identity",
      "low_trust_side": "any unauthenticated client claiming a 'user' value",
      "crosses": "client-chosen user_id becomes the session identity and the subject of a signed bearer token",
      "control": "intended: credential verification before minting a session; actual: none present",
      "files": [
        "api/auth.py"
      ]
    },
    {
      "name": "tenant-scoped-file-download",
      "low_trust_side": "any client holding a valid session (identity self-asserted per above)",
      "crosses": "client-supplied 'name' query param is joined onto the tenant's filesystem root and read back via send_file",
      "control": "blocklist rejecting only a leading '/' character",
      "files": [
        "storage/files.py"
      ]
    },
    {
      "name": "tenant-scoped-file-upload",
      "low_trust_side": "any client holding a valid session",
      "crosses": "client-supplied filename and file bytes are written under the tenant root",
      "control": "os.path.basename() strips directory components before the join",
      "files": [
        "storage/files.py"
      ]
    }
  ],
  "areas": [
    {
      "name": "auth",
      "paths": [
        "api/auth.py"
      ],
      "why": "session/token issuance for every other authenticated route",
      "risk": "high"
    },
    {
      "name": "reports",
      "paths": [
        "api/reports.py"
      ],
      "why": "public and org-scoped report data access over SQLite",
      "risk": "high"
    },
    {
      "name": "tenant-file-storage",
      "paths": [
        "storage/files.py"
      ],
      "why": "per-tenant filesystem read/write reachable over HTTP",
      "risk": "high"
    },
    {
      "name": "app-wiring",
      "paths": [
        "app.py",
        "Dockerfile"
      ],
      "why": "establishes which routes are actually exposed in a real deployment",
      "risk": "low"
    },
    {
      "name": "auth / session issuance",
      "paths": [
        "api/auth.py"
      ],
      "why": "sole identity-establishing endpoint; mints both a Flask session and a separate HMAC token that nothing else in the codebase consults",
      "risk": "high"
    },
    {
      "name": "report export / query construction",
      "paths": [
        "api/reports.py"
      ],
      "why": "two endpoints in the same file take opposite approaches to SQL safety (raw string interpolation vs parameterized), and the unsafe one requires no session at all",
      "risk": "high"
    },
    {
      "name": "tenant file storage",
      "paths": [
        "storage/files.py"
      ],
      "why": "filesystem read/write scoped by session-derived tenant name, with incomplete traversal filtering on download and no content validation on upload",
      "risk": "high"
    },
    {
      "name": "app wiring / deployment surface",
      "paths": [
        "app.py",
        "Dockerfile"
      ],
      "why": "establishes that all three blueprints are unconditionally reachable on an exposed port with a static, source-committed secret_key",
      "risk": "medium"
    },
    {
      "name": "auth/session issuance",
      "paths": [
        "api/auth.py"
      ],
      "why": "sole place identity enters the system; every other blueprint's authorization decisions are downstream of what this endpoint puts in the session",
      "risk": "high"
    },
    {
      "name": "reports export/query construction",
      "paths": [
        "api/reports.py"
      ],
      "why": "two DB call sites in one module use different parameterization styles, one of them string-interpolated and unauthenticated",
      "risk": "high"
    },
    {
      "name": "app composition / deployment wiring",
      "paths": [
        "app.py",
        "Dockerfile"
      ],
      "why": "determines which routes are actually reachable in a given deployment; unconditional registration here is what makes every finding above provable rather than speculative",
      "risk": "medium"
    }
  ],
  "repo_specific_attack_classes": [
    {
      "name": "identity-claim-trust",
      "why_this_repo": "/api/login mints a fully valid signed token for whatever 'user' value the caller sends, with zero credential verification, so the auth boundary exists in name only",
      "methodology": "For every route that assigns to session[...] or calls a token/credential-minting function, walk backward from the assigned value to its source; if the source is a raw request parameter with no preceding password/OTP/cert check, the mint is forgeable by definition regardless of how strong the signing scheme downstream looks."
    },
    {
      "name": "session-key-provenance-gap",
      "why_this_repo": "reports.py and files.py authorize on session['org'] and session['tenant'], but grepping the whole repo shows only session['uid'] is ever set \u2014 those keys have no producer in visible source",
      "methodology": "Grep every session[...] read against every session[...] = write in the codebase; any read with no matching write is either dead/unreachable code (downgrade confidence, flag needs_deployment_fact) or evidence of an omitted/undocumented issuance path elsewhere that a hunter should specifically go looking for before trusting the 'requires session' comment at face value."
    },
    {
      "name": "partial-traversal-sanitization",
      "why_this_repo": "storage/files.py blocks one traversal vector (a leading '/') while leaving the general '../' grammar completely open before the os.path.join into a trusted root",
      "methodology": "For every os.path.join(TRUSTED_ROOT, user_input) in the repo, enumerate exactly which characters/prefixes are rejected versus the full traversal grammar (leading slash, '../', encoded variants, absolute Windows-style paths); a single-case check that reads as a saf
```