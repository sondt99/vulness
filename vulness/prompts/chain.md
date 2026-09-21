# Compose an exploit chain

Repository: `{repo_name}` at `{repo_path}`

Below are findings that were each independently confirmed against this codebase. Each one
crosses a single trust boundary. That is the right unit for writing a fix and the wrong
unit for judging impact: three separate medium findings that compose into unauthenticated
code execution are not a medium problem, and nobody prioritising them one at a time will
ever see that.

Your job is to find where they compose.

## The confirmed findings

{findings_block}

## What counts as a chain

A chain is real when the **output of one step supplies a precondition of the next**. Ask,
for each pair: does the first give the attacker something the second needs and would
otherwise lack? Access, an identity, a file write, a value they control, a widened
network position, knowledge of a secret.

Concretely, the shapes worth checking:

- an authentication or identity weakness that satisfies the "authenticated" precondition
  of something that would otherwise be out of reach
- a read primitive that discovers a secret which a second finding requires
- a write primitive whose destination a path traversal chooses
- a low-privilege action that changes state a higher-privilege path later trusts
- an information leak that removes the guesswork from an otherwise impractical attack

## What does not count

Be strict here. Most findings do not chain, and a fabricated chain is worse than none,
because it inflates severity on evidence that does not exist.

- Two findings reachable by the same attacker are **not** a chain. They must feed one another.
- A chain whose steps need contradictory preconditions is not a chain.
- If step 2 was already reachable without step 1, step 1 adds nothing: report step 2 alone.
- Do not invent intermediate steps that are not in the findings list. You may only compose
  what is already confirmed.

Returning zero chains is a correct and expected answer.

## Output

End your reply with exactly one fenced ```json block:

```json
{{
  "chains": [
    {{
      "title": "<what the composed attack achieves, in one line>",
      "steps": ["<finding_id>", "<finding_id>"],
      "narrative": "<how an attacker walks it: what each step yields and why the next needs it>",
      "preconditions": "<what the attacker must start with, before step 1>",
      "terminal_impact": "<what they hold at the end, concretely>",
      "severity": "informational|low|medium|high|critical",
      "why_it_composes": "<the specific thing step 1 supplies that step 2 requires>"
    }}
  ],
  "rejected_pairs": [
    {{"steps": ["<id>", "<id>"], "why_not": "<why these do not actually compose>"}}
  ]
}}
```

Severity is the impact of the **whole chain**, not the maximum of its parts. A chain that
ends in unauthenticated code execution is critical even if every step was medium alone.
