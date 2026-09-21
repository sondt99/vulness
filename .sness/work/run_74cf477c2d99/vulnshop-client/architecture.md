# Architecture - vulnshop-client

_generated 2026-09-21T03:18:43.715252+00:00_

## Overview

vulnshop-client is a minimal CLI utility, not a service: it has no listener, no HTTP server, and no authentication layer of its own. Its only entry point is client/cli.py, invoked as `python -m client.cli <report_id> <org> <name>` (or similar), which takes three positional argv values directly from whoever runs the process. main() passes report_id and org straight into fetch_report() in client/sync.py, which performs an unauthenticated GET to a hardcoded internal URL (http://vulnshop.internal/api/reports/export) with those two values as query parameters and no escaping or validation. The response body (JSON, coerced to a string) is then handed to cache_report(), which joins the third argv value (name) onto a fixed CACHE directory (/var/cache/vulnshop-client) with os.path.join and writes the response there, again with no sanitization. There is no local trust boundary check anywhere in this repo: cli.py trusts argv completely, sync.py trusts cli.py, and the write path trusts the name argument completely. The interesting trust boundary is not local, though: report_id and org are forwarded verbatim to the vulnshop server's export_report handler (an external repo dependency, declared in pyproject.toml), which the accompanying README states concatenates them directly into a SQL query. This makes vulnshop-client a pass-through amplifier: any injection payload placed in id or org by a local caller becomes a SQL injection attempt against the downstream vulnshop service. The client trusts vulnshop's response completely, and vulnshop trusts the client's input completely, and the caller of this CLI trusts nothing is checked by either. Because the fixture is deliberately small, essentially the entire codebase is attack surface: two functions, two untrusted inputs, one command injection-adjacent(path) sink and one cross-service injection-adjacent sink.

## Trust boundaries

- **cli-argv-to-http-params** - whoever invokes the CLI (local user, calling script, or any automation that shells out to this tool with attacker-influenced arguments) sends sys.argv[1] (report_id) and sys.argv[2] (org) flow unmodified into the HTTP query parameters of a GET to vulnshop.internal; control: none: no validation, allow-listing, or type coercion is applied to report_id or org before they leave this process
- **cli-argv-to-filesystem-path** - whoever invokes the CLI and controls sys.argv[3] (name) sends the `name` argument is joined with os.path.join(CACHE, name) and opened for writing; control: none: no basename() stripping, no rejection of '..' or absolute paths, no containment check that the resolved path stays under CACHE
- **client-to-vulnshop-injection-relay** - the same CLI caller, now acting through this client as an intermediary against a separate downstream service sends report_id and org cross from this repo into vulnshop's export_report handler, which per the README concatenates them into SQL; control: none in this repo; the client performs no escaping, and the downstream control (parameterized queries) is documented as absent on the vulnshop side, making this client a confirmed-reachable delivery path for that injection
- **remote-response-to-local-disk** - the vulnshop server (or anyone able to MITM/spoof http://vulnshop.internal, since the request is plain HTTP with no TLS and no response validation) sends the JSON response body from r.json() is stringified and written verbatim to the local cache file with no size limit, content validation, or schema check; control: none: no timeout-based size cap beyond the 10s connect/read timeout, no content-type or schema verification before persisting to disk
- **argv-to-http-query** - whoever invokes the CLI (or whatever builds its argv, e.g. a wrapper script/service) sends report_id and org argv values flow unmodified into HTTP query parameters sent to vulnshop's export endpoint, which concatenates them into SQL server-side; control: none: no allowlist, type check, or escaping before requests.get params
- **argv-to-filesystem-path** - whoever invokes the CLI sends the name argv value is joined into a filesystem path under the cache directory and then opened for writing; control: none: no basename() call, no traversal check, no extension/charset allowlist
- **http-response-to-local-trust** - the vulnshop.internal server (or anyone able to MITM/spoof it, since the request is plain HTTP with no TLS) sends the JSON response body is trusted and written verbatim to the local filesystem cache; control: none: no schema validation on r.json(), no TLS, no response size limit

## Repo-specific attack classes

### cross-repo-injection-relay
this fixture's entire purpose (per README) is to be a benign-looking intermediary that forwards unsanitised id/org straight into a documented SQL string-concatenation sink in a separate vulnshop package; the vulnerability is not locally exploitable in isolation but the reachability edge lives entirely here
trace report_id and org from sys.argv in client/cli.py:8 through fetch_report()'s params dict in client/sync.py:13 into vulnshop.api.reports.export_report; confirm no client-side quoting/escaping/allow-listing is ever applied, and treat this file as the 'last safe place' to stop an injection that actually lands one repo over

### cache-path-traversal-via-argv
cache_report() builds a filesystem path from an entirely caller-controlled `name` with plain os.path.join and no normalization, and cli.py hands argv[3] to it unchanged, so a name like ../../etc/cron.d/x or an absolute path escapes CACHE and can overwrite arbitrary files the process has permission to write
invoke the CLI (or call cache_report directly) with name values containing '../' sequences or an absolute path, and check whether the resulting write lands outside /var/cache/vulnshop-client; also check whether os.path.join short-circuits to an absolute path if name itself starts with '/'

### unbounded-response-persistence
fetch_report() has no size cap on r.json() and cache_report() writes the full stringified body to disk with no truncation, so a malicious or compromised vulnshop.internal response can be used to fill disk space or plant arbitrarily large/crafted content at a caller-influenced path
consider this only in combination with the path-traversal class above: a compromised/malicious server response combined with attacker-controlled `name` gives write-what-where onto the local filesystem of whatever runs this CLI

### cross-repo-taint-relay
This client exists purely to carry CLI-controlled id/org values across a process and network boundary into a sibling repo's SQL-building code; the vulnerability isn't in this repo's own query logic but in what it faithfully relays unmodified.
Treat report_id and org as tainted from client/cli.py:8 through client/sync.py:11-16, and correlate with vulnshop/api/reports.py:20 where the same two names are concatenated into a SQL string. A finding here should name both the local relay point and the remote sink it reaches, since neither file alone shows the full boundary crossing.

### cache-name-path-traversal
cache_report (client/sync.py:19-24) does os.path.join(CACHE, name) with name taken directly from argv[3] and never checked for '..', absolute-path prefixes, or embedded separators before the file is opened for write.
Invoke the CLI with a name containing '../' sequences or an absolute path and confirm the resulting open() call in cache_report escapes /var/cache/vulnshop-client, since os.path.join does not sanitize a second absolute-looking argument and simply discards the first.

### cross-repo-taint-passthrough
this entire repo exists as a feeder for a separate package (vulnshop); it does zero sanitization on the two argv values it forwards, so any injection sink in the dependency is reachable through here even though this repo alone shows no obvious injection syntax
Do not evaluate sync.py:fetch_report in isolation; treat report_id and org as tainted all the way into vulnshop.api.reports.export_report. Enumerate every parameter forwarded via requests.get(params=...) and cross-reference against the vulnshop package's handler for /api/reports/export to confirm whether it builds SQL, shell commands, or file paths from them. Any hunter who only reads this repo must flag the forward as 'unvalidated pass-through to external sink' rather than dismissing it as safe because no string concatenation happens locally.

### argv-as-untrusted-boundary
cli.py treats sys.argv positionally with zero validation, and in real deployments CLI argv is frequently populated by another process (cron wrapper, CI job, service orchestrator, message consumer) rather than a human, making argv itself a remote-influenceable channel here
Identify every place this CLI could realistically be invoked with attacker-influenced arguments (e.g. a batch job that maps ticket IDs or filenames to argv), then trace each of the three positional args (report_id, org, name) independently through fetch_report and cache_report to their respective sinks. Treat missing argv (IndexError) and adversarial argv (path traversal strings, SQL metacharacters, oversized strings) as two separate test dimensions.

### silent-cache-poisoning-via-trusted-response
cache_report writes whatever fetch_report returns without validating structure, size, or origin, and the fetch itself is plaintext HTTP to a bare hostname (vulnshop.internal) with no TLS/cert pinning, so the write sink's input isn't just attacker-controlled argv but also an unauthenticated network response
Model an on-path or DNS-spoofing adversary between the client and vulnshop.internal (justified since the URL is hardcoded http:// with no TLS). Check whether a malicious response body (arbitrary JSON, or a non-JSON body causing r.json() to raise) can corrupt the cache file at attacker-chosen paths when combined with the name traversal bug, effectively chaining a network MITM with the path-join bug to achieve writes outside the cache directory with attacker-chosen content.

## Highest-value targets

- client/sync.py, contains both the injection-relay sink (fetch_report) and the path-traversal sink (cache_report) in one 25-line file
- client/cli.py, the only place argv trust decisions are (not) made before reaching those sinks
- client/sync.py:9-16 (fetch_report), the sole network call and the point where CLI-controlled id/org enter the wire toward the unauthenticated, SQL-concatenating vulnshop export endpoint
- client/sync.py:19-24 (cache_report), the sole filesystem write and the point where an unsanitized name reaches open() for write
- client/cli.py:7-10 (main), the only place all three tainted values originate before being split across the network and filesystem sinks
- client/sync.py:cache_report, unsanitized os.path.join(CACHE, name) followed by open(path, 'w') — direct path traversal / arbitrary file write
- client/sync.py:fetch_report, report_id/org forwarded verbatim as query params into a cross-repo SQL-concatenation sink in vulnshop.api.reports.export_report
- client/cli.py:main, the only entry point and the origin of all taint into both sinks above

## Raw

```json
{
  "architecture": "vulnshop-client is a minimal CLI utility, not a service: it has no listener, no HTTP server, and no authentication layer of its own. Its only entry point is client/cli.py, invoked as `python -m client.cli <report_id> <org> <name>` (or similar), which takes three positional argv values directly from whoever runs the process. main() passes report_id and org straight into fetch_report() in client/sync.py, which performs an unauthenticated GET to a hardcoded internal URL (http://vulnshop.internal/api/reports/export) with those two values as query parameters and no escaping or validation. The response body (JSON, coerced to a string) is then handed to cache_report(), which joins the third argv value (name) onto a fixed CACHE directory (/var/cache/vulnshop-client) with os.path.join and writes the response there, again with no sanitization. There is no local trust boundary check anywhere in this repo: cli.py trusts argv completely, sync.py trusts cli.py, and the write path trusts the name argument completely. The interesting trust boundary is not local, though: report_id and org are forwarded verbatim to the vulnshop server's export_report handler (an external repo dependency, declared in pyproject.toml), which the accompanying README states concatenates them directly into a SQL query. This makes vulnshop-client a pass-through amplifier: any injection payload placed in id or org by a local caller becomes a SQL injection attempt against the downstream vulnshop service. The client trusts vulnshop's response completely, and vulnshop trusts the client's input completely, and the caller of this CLI trusts nothing is checked by either. Because the fixture is deliberately small, essentially the entire codebase is attack surface: two functions, two untrusted inputs, one command injection-adjacent(path) sink and one cross-service injection-adjacent sink.",
  "trust_boundaries": [
    {
      "name": "cli-argv-to-http-params",
      "low_trust_side": "whoever invokes the CLI (local user, calling script, or any automation that shells out to this tool with attacker-influenced arguments)",
      "crosses": "sys.argv[1] (report_id) and sys.argv[2] (org) flow unmodified into the HTTP query parameters of a GET to vulnshop.internal",
      "control": "none: no validation, allow-listing, or type coercion is applied to report_id or org before they leave this process",
      "files": [
        "client/cli.py",
        "client/sync.py"
      ]
    },
    {
      "name": "cli-argv-to-filesystem-path",
      "low_trust_side": "whoever invokes the CLI and controls sys.argv[3] (name)",
      "crosses": "the `name` argument is joined with os.path.join(CACHE, name) and opened for writing",
      "control": "none: no basename() stripping, no rejection of '..' or absolute paths, no containment check that the resolved path stays under CACHE",
      "files": [
        "client/cli.py",
        "client/sync.py"
      ]
    },
    {
      "name": "client-to-vulnshop-injection-relay",
      "low_trust_side": "the same CLI caller, now acting through this client as an intermediary against a separate downstream service",
      "crosses": "report_id and org cross from this repo into vulnshop's export_report handler, which per the README concatenates them into SQL",
      "control": "none in this repo; the client performs no escaping, and the downstream control (parameterized queries) is documented as absent on the vulnshop side, making this client a confirmed-reachable delivery path for that injection",
      "files": [
        "client/sync.py"
      ]
    },
    {
      "name": "remote-response-to-local-disk",
      "low_trust_side": "the vulnshop server (or anyone able to MITM/spoof http://vulnshop.internal, since the request is plain HTTP with no TLS and no response validation)",
      "crosses": "the JSON response body from r.json() is stringified and written verbatim to the local cache file with no size limit, content validation, or schema check",
      "control": "none: no timeout-based size cap beyond the 10s connect/read timeout, no content-type or schema verification before persisting to disk",
      "files": [
        "client/sync.py"
      ]
    },
    {
      "name": "argv-to-http-query",
      "low_trust_side": "whoever invokes the CLI (or whatever builds its argv, e.g. a wrapper script/service)",
      "crosses": "report_id and org argv values flow unmodified into HTTP query parameters sent to vulnshop's export endpoint, which concatenates them into SQL server-side",
      "control": "none: no allowlist, type check, or escaping before requests.get params",
      "files": [
        "client/cli.py",
        "client/sync.py"
      ]
    },
    {
      "name": "argv-to-filesystem-path",
      "low_trust_side": "whoever invokes the CLI",
      "crosses": "the name argv value is joined into a filesystem path under the cache directory and then opened for writing",
      "control": "none: no basename() call, no traversal check, no extension/charset allowlist",
      "files": [
        "client/sync.py",
        "client/cli.py"
      ]
    },
    {
      "name": "http-response-to-local-trust",
      "low_trust_side": "the vulnshop.internal server (or anyone able to MITM/spoof it, since the request is plain HTTP with no TLS)",
      "crosses": "the JSON response body is trusted and written verbatim to the local filesystem cache",
      "control": "none: no schema validation on r.json(), no TLS, no response size limit",
      "files": [
        "client/sync.py"
      ]
    }
  ],
  "areas": [
    {
      "name": "client-sync-fetch",
      "paths": [
        "client/sync.py"
      ],
      "why": "constructs the outbound request that carries caller-controlled id/org into vulnshop's SQL-concatenating endpoint",
      "risk": "high"
    },
    {
      "name": "client-cache-write",
      "paths": [
        "client/sync.py"
      ],
      "why": "unsanitised os.path.join(CACHE, name) write sink, reachable from CLI argv",
      "risk": "high"
    },
    {
      "name": "cli-entrypoint",
      "paths": [
        "client/cli.py"
      ],
      "why": "sole entry point; positional argv parsing with zero validation feeding both sinks above",
      "risk": "high"
    },
    {
      "name": "CLI argument ingestion",
      "paths": [
        "client/cli.py"
      ],
      "why": "Sole entry point; reads report_id, org, name from sys.argv with no parsing, type checks, or bounds, then fans them out to both the network call and the filesystem write",
      "risk": "medium"
    },
    {
      "name": "Remote report fetch",
      "paths": [
        "client/sync.py"
      ],
      "why": "fetch_report forwards report_id and org verbatim as query params to an internal HTTP endpoint with no encoding beyond requests' own param handling, and blindly trusts/parses whatever JSON comes back",
      "risk": "high"
    },
    {
      "name": "Local report cache write",
      "paths": [
        "client/sync.py"
      ],
      "why": "cache_report performs os.path.join(CACHE, name) with a fully caller-controlled name and writes attacker/remote-influenced body content to that path with no normalization or containment check",
      "risk": "high"
    },
    {
      "name": "cli entry / argv handling",
      "paths": [
        "client/cli.py"
      ],
      "why": "sole point where external input (argv) enters the program with no parsing/validation",
      "risk": "high"
    },
    {
      "name": "http fetch (cross-repo sink)",
      "paths": [
        "client/sync.py"
      ],
      "why": "forwards unsanitized identifiers into another repo's SQL-concatenating endpoint over plaintext HTTP",
      "risk": "high"
    },
    {
      "name": "local cache write",
      "paths": [
        "client/sync.py"
      ],
      "why": "unsanitized path join followed by an unconditional file write",
      "risk": "high"
    }
  ],
  "repo_specific_attack_classes": [
    {
      "name": "cross-repo-injection-relay",
      "why_this_repo": "this fixture's entire purpose (per README) is to be a benign-looking intermediary that forwards unsanitised id/org straight into a documented SQL string-concatenation sink in a separate vulnshop package; the vulnerability is not locally exploitable in isolation but the reachability edge lives entirely here",
      "methodology": "trace report_id and org from sys.argv in client/cli.py:8 through fetch_report()'s params dict in client/sync.py:13 into vulnshop.api.reports.export_report; confirm no client-side quoting/escaping/allow-listing is ever applied, and treat this file as the 'last safe place' to stop an injection that actually lands one repo over"
    },
    {
      "name": "cache-path-traversal-via-argv",
      "why_this_repo": "cache_report() builds a filesystem path from an entirely caller-controlled `name` with plain os.path.join and no normalization, and cli.py hands argv[3] to it unchanged, so a name like ../../etc/cron.d/x or an absolute path escapes CACHE and can overwrite arbitrary files the process has permission to write",
      "methodology": "invoke the CLI (or call cache_report directly) with name values containing '../' sequences or an absolute path, and check whether the resulting write lands outside /var/cache/vulnshop-client; also check whether os.path.join short-circuits to an absolute path if name itself starts with '/'"
    },
    {
      "name": "unbounded-response-persistence",
      "why_this_repo": "fetch_report() has no size cap on r.json() and cache_report() writes the full stringified body to disk with no truncation, so a malicious or compromised vulnshop.internal response can be used to fill disk space or plant arbitrarily large/crafted content at a caller-influenced path",
      "methodology": "consider this only in combination with the path-traversal class above: a compromised/malicious server response combined with attacker-controlled `name` gives write-what-where onto the local filesystem of whatever runs this CLI"
    },
    {
      "name": "cross-repo-taint-relay",
      "why_this_repo": "This client exists purely to carry CLI-controlled id/org values across a process and network boundary into a sibling repo's SQL-building code; the vulnerability isn't in this repo's own query logic but in what it faithfully relays unmodified.",
      "methodology": "Treat report_id and org as tainted from client/cli.py:8 through client/sync.py:11-16, and correlate with vulnshop/api/reports.py:20 where the same two names are concatenated into a SQL string. A finding here should name both the local relay point and the remote sink it reaches, since neither file alone shows the full boundary crossing."
    },
    {
      "name": "cache-name-path-traversal",
      "why_this_repo": "cache_report (client/sync.py:19-24) does os.path.join(CACHE, name) with name taken directly from argv[3] and never checked for '..', absolute-path prefixes, or embedded separators before the file is opened for write.",
      "methodology": "Invoke the CLI with a name containing '../' sequences or an absolute path and confirm the resulting open() call in cache_report escapes /var/cache/vulnshop-client, since os.path.join does not sanitize a second absolute-looking argument and simply discards the first."
    },
    {
      "name": "cross-repo-taint-passthrough",
      "why_this_repo": "this entire repo exists as a feeder for a separate package (vulnshop); it does zero sanitization on the two argv values it forwards, so any injection sink in the dependency is reachable through here even though this repo alone shows no obvious injection syntax",
      "methodology": "Do not evaluate sync.py:fetch_report in isolation; treat report_id and org as tainted all the way into vulnshop.api.reports.export_report. Enumerate every parameter forwarded via requests.get(params=...) and cross-reference against the vulnshop package's handler for /api/reports/export to confirm whether it builds SQL, shell commands, or file paths
```