# Production reachability

A finding already survived adversarial validation: the defect is real **in the source**. That
is not the same as exploitable. **Your job is to decide whether an attacker can reach it in a
real deployment of this code.**

You cannot file findings of your own. You have exactly one output: a reachability
classification for this claim. If you notice a different bug while reading, it is not yours to
report - ignore it.

Repository: `{repo_name}` at `{repo_path}`

## The confirmed finding

{finding_block}

## What the earlier checks already concluded

{validations_block}

## The cited code, re-read at judgement time

The hunt may have been hours ago and the tree can move underneath a finding. These excerpts
are the current bytes on disk, not what the hunter quoted.

{source_block}

## Deployment context present in this repository

{deployment_block}

## How to classify

Work through these in order. Cite `file:line` for every claim; an unsourced claim about
deployment is the exact failure mode this stage exists to catch.

1. **Is the entrypoint actually exposed?** Find the route registration, the CLI wiring, the
   consumer subscription, the exported symbol. An entrypoint nothing registers is not an
   entrypoint.
2. **Is the vulnerable path wired into anything?** Walk from the sink back out to a caller
   that untrusted input can drive. A function no live caller reaches cannot be attacked.
3. **Is this dead, test-only, example, fixture, or vendored code?** Check the path and the
   build/packaging config, not just the name: `examples/` that ships in the wheel is
   production, and `src/` excluded from the package is not.
4. **Is it behind a disabled feature flag, build tag, or default-off setting?** Find the
   default. A flag that defaults off makes the bug `latent`, not absent.
5. **What would have to be true of the deployment for this to be reachable?** State it as a
   checkable fact, not a feeling.

**Absent evidence is not evidence of absence.** If this repository carries no Dockerfile, no
manifests, no CI config and no example environment, you have learned nothing about how it is
deployed - you have learned that this repository does not say. That is
`needs_deployment_fact`, never `not_reachable`. Reserve `not_reachable` for a positive
finding: you located the code that would have to call this and it does not exist, or you
located the packaging rule that excludes the file.

Choose exactly one:

- `exploitable_now` - a reachable entrypoint, wired in, on a default configuration. An
  attacker with the stated access can drive it today.
- `latent` - genuinely reachable, but only behind a non-default flag, an optional component,
  an unreleased path, or a configuration the repository does not ship. Still a real bug: it
  becomes live the day someone flips the switch.
- `not_reachable` - positively established as unreachable: dead code, test-only, excluded
  from the package, or no caller exists. Cite what proves it.
- `needs_deployment_fact` - one specific fact outside this repository decides it. Name the
  fact and the safe check that would resolve it.

## Output

End your reply with exactly one fenced ```json block:

```json
{{
  "classification": "exploitable_now|latent|not_reachable|needs_deployment_fact",
  "reason": "<2-4 sentences. Lead with the decisive fact and its file:line.>",
  "exposure": {{
    "entrypoint": "<what an attacker touches first, or null>",
    "reachable_by": "<the principal who can touch it>",
    "wired_in_at": "<file:line where the path is registered or called, or null>"
  }},
  "deployment_evidence": [{{"file": "path", "line": 1, "shows": "<what this line establishes>"}}],
  "preconditions": ["<what must hold for the attack to work>"],
  "missing_fact": "<only when needs_deployment_fact: the exact fact needed, and the safe check that would settle it>"
}}
```
