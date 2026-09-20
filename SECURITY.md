# Security Policy

s-ness is a security tool. That cuts two ways: it has its own attack surface, and it can
be pointed at things it should not be pointed at. This document covers both.

## Reporting a vulnerability in s-ness

Please use a [private security advisory](https://github.com/sondt99/vulnnes/security/advisories/new).
Do not open a public issue.

Include the version, the affected component, and the smallest reproduction you can manage.
You will get an acknowledgement within 5 working days and a fix or a decision within 30.
If the issue is confirmed, you will be credited in the release notes unless you prefer not
to be.

### What we consider in scope

The harness runs untrusted target code and untrusted model output. Anything that breaks
one of these boundaries is in scope:

| Boundary | Why it matters |
|---|---|
| Sandbox escape | A PoC must not reach the host, the network, or the target source. |
| Target write | The harness is read only against targets. Any path that writes to one is a bug. |
| Secret exposure | API keys must never reach a prompt, an artifact, a report, or the event log. |
| Prompt injection to execution | Target source is untrusted input. Model output must not become a command. |
| Path traversal in promotion | Artifacts copied out of a sandbox must stay inside their assigned directory. |
| Findings database | Target controlled data is stored there. It must never be executed or interpolated. |

### Out of scope

- False positives and false negatives in findings. Those are accuracy bugs, and they have
  [their own issue template](.github/ISSUE_TEMPLATE/false_positive.yml).
- Model behaviour we do not control, such as a model refusing a prompt.
- Cost or rate limit exhaustion from running the harness without a budget.
- Findings produced by s-ness about *other* projects. Report those to the project that
  owns the code.

## Using s-ness responsibly

The harness is built for auditing code you own or are explicitly authorised to audit.

It is designed so that the honest path is also the easy one:

- Source inspection is read only. The harness never modifies a target.
- Execution happens in a container with no network, a read only target mount, dropped
  capabilities, and explicit CPU, memory, PID, and wall clock limits.
- Proofs of concept run against the original tree. A PoC that changed the source voids its
  own finding.
- There is no live probing anywhere in the codebase, and no feature request to add it will
  be accepted. If a decisive fact lives outside the repository, the finding is recorded as
  `needs_validation` with the missing fact named.

If you point this at infrastructure you do not own, that is your decision and your
liability, and the design will not help you hide it.

## Handling findings

Findings are unpatched vulnerability reports. Treat the run artifacts accordingly:

- `.sness/` is git ignored by default. Keep it that way.
- Do not paste findings into public issues. Reduce to a synthetic example first.
- Patches from the `fix` stage are proposals for human review. Nothing in the harness can
  merge them, and that gate is deliberate.
