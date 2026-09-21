# Trace: does this defect escape the repository?

Source repository: `{repo_name}` at `{repo_path}`

A component flaw stops being a component flaw the moment another repository depends on it.
The manifests below already establish *that* these repositories are wired together. What a
manifest cannot say is whether a consumer ever reaches the defective code path, and that is
the only question you are here to answer.

You can read the source repository. The consumer repositories are **not** mounted for you -
reason about them from this repository's export surface and from the dependency declaration
quoted below, and say plainly when you cannot establish something rather than inventing it.

## Dependency edges the harness resolved

{dependency_block}

## Consumers of this repository

{consumer_block}

## Confirmed findings in this repository

Each already survived a deterministic file/line check and adversarial review on a different
model. Do not re-litigate them; take them as established.

{findings_block}

## Do this

1. Establish the **export surface**: what this repository exposes that a consumer imports,
   calls, subclasses, or links against. Point at files and lines. A helper a consumer
   cannot name is not export surface, however dangerous it is.
2. For each finding, decide whether its **root cause** reaches a listed consumer. A shared
   dependency edge is not enough. The consumer must be able to reach the defective path
   through the export surface, or be forced to reimplement the same broken assumption
   against it. If the defect sits behind an entry point only this repository calls, say so
   and move on - a propagation you cannot justify wastes a whole hunt task downstream.
3. Where it does reach, write a **lead** in the consumer's own terms: which of its call
   sites to attack and what to try there. The hunter who receives it will never have read
   this repository, so a lead that only makes sense from in here is worthless.

Prefer three defensible propagations to a dozen speculative ones.

## Output

End your reply with exactly one fenced ```json block:

```json
{{
  "export_surface": [
    {{
      "symbol": "<what a consumer names>",
      "file": "relative/path",
      "line": 42,
      "consumers_use_it_for": "<one line>"
    }}
  ],
  "propagations": [
    {{
      "finding_id": "<verbatim id from the findings above>",
      "consumer_repo": "<verbatim repo id from the consumer list above>",
      "reaches_consumer": true,
      "why": "<how the consumer reaches the defective path, through which exported symbol>",
      "where_to_look": ["<path or module in the CONSUMER repository>"],
      "attack_class": "kebab-case",
      "lead": "<2-3 sentences a hunter who has never seen this repository can act on>",
      "confidence": "low|medium|high"
    }}
  ],
  "notes": "<what you could not establish, and what would have let you>"
}}
```
