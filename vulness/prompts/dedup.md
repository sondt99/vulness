# Do these collapse onto one fix?

A deterministic pre-pass grouped the findings below into one candidate cluster, using inverted
indexes over sink files, enclosing scopes, trust boundaries, entrypoints and rare title tokens.
**That index is a hint, not evidence.** It is tuned to over-offer, because a missed duplicate
costs a reviewer an hour and a wrong merge costs them a whole finding.

Repository: `{repo_name}` at `{repo_path}`

## The test

Two findings collapse when **one change, at one place, fixes both**. Not "they are similar",
not "they are the same attack class", not "they are in the same file".

- Two symptoms of one broken invariant are **one finding**. The same missing check reached
  through three different sinks is one bug with three routes.
- The same generic weakness at two independent places is **two findings**. Two handlers that
  each forgot to authorise are two fixes, even with identical titles.
- A finding that is a step inside another (the primitive and the exploit built on it) is
  **one finding** only if fixing the primitive closes the other. If both need separate
  repairs, keep them apart.
- When you cannot tell, keep them apart. Merging is destructive: the merged record disappears
  from the report, and a bug nobody reads is a bug nobody fixes.

**Which member survives is not your decision.** The harness keeps the highest-severity,
best-evidenced member of each group deterministically. Your job is only to say which findings
belong together, and to state the single fix that closes them.

## The cluster

{cluster_block}

## Output

Every id you return must come from the cluster above - do not invent, abbreviate or correct
one. A group needs at least two ids. Put every finding that stands on its own in `distinct`;
if none of them collapse, return an empty `groups` list and say so.

End your reply with exactly one fenced ```json block:

```json
{{
  "groups": [
    {{
      "finding_ids": ["<id>", "<id>"],
      "one_fix": "<the single change, at one place, that closes all of them>",
      "root_cause": "<the one broken invariant they share>",
      "reason": "<2-3 sentences: why one fix closes all of them, with file:line>"
    }}
  ],
  "distinct": [{{"finding_id": "<id>", "why_separate": "<the separate fix this one needs>"}}]
}}
```
