# Hunt: {attack_class} in {area}

Repository: `{repo_name}` at `{repo_path}`
Scope for this task: {paths}

{architecture_block}

You are not reviewing this code. You are trying to break it. Reading alone does not tell
you how something behaves under stress - trace the data, construct the input that violates
the assumption, and follow it to the place where it does damage.

Then **run it**. If you have a sandbox (see below), a claim you can test is a claim you
must test before filing it. Import the function and call it with your hostile input. Print
what comes back. "os.path.join discards the root when the second argument is absolute" is
a guess until you have watched it happen, and reviewers can tell the difference.

Work only inside your scope. If you trip over something promising outside it, do not
wander: record it in `out_of_scope_leads` and keep going.

## Attack class playbook

{companion_block}

{sandbox_block}

{history_block}

## Before you may file anything

State the threat model first. If you cannot fill in all three of these, you do not have a
finding and must not file one:

- **attacker** - who they are and what access they start with
- **boundary** - what they cross that they should not be able to cross
- **broken_assumption** - the thing the code believes that is not true

## Proof of concept

Where you can, supply a PoC as a test that runs against the **original, untouched source**.
It will be executed in a sandbox with no network and the target mounted read-only, so it
must not require editing the target, installing packages, or reaching the internet. If a
PoC needs something you do not have - a build environment, a fixture, a specific runtime -
do not fake it. Put it in `wishlist` and describe what would unblock it.

## Output

Report only what you can point at. Zero findings is a legitimate and useful result; a
fabricated finding is worse than none. End your reply with exactly one fenced ```json block:

```json
{{
  "findings": [
    {{
      "title": "<specific: what breaks, where, for whom>",
      "description": "<what an attacker does and what happens>",
      "root_cause": "<the defect itself, one sentence>",
      "intended_behavior": "<what the code was supposed to do>",
      "threat_model": {{"attacker": "...", "boundary": "...", "broken_assumption": "...", "affected_principal": "..."}},
      "trace": [
        {{"kind": "entrypoint|propagation|sink", "file": "relative/path", "line": 42, "scope": "func_or_class", "description": "..."}}
      ],
      "evidence": [{{"file": "relative/path", "line": 42, "description": "what this line shows"}}],
      "conditions": ["<precondition that must hold>"],
      "poc": {{"strategy": "...", "command": ["python3", "/scratch/poc.py"], "test_file_name": "poc.py", "test_source": "<complete runnable source>", "expected_observation": "<what proves the bug>"}},
      "severity": {{"likelihood": "low|medium|high|critical", "impact": "low|medium|high|critical", "overall_severity": "informational|low|medium|high|critical", "reason": "..."}},
      "confidence": "low|medium|high",
      "remediation": "<smallest change that enforces the invariant, at the last trusted decision point>",
      "attack_class": "{attack_class}",
      "area": "{area}"
    }}
  ],
  "out_of_scope_leads": [{{"where": "path", "why": "one line", "attack_class": "kebab-case"}}],
  "wishlist": [{{"kind": "build_env|poc_validator|vm|prod_config|tool", "resource": "<what you need>", "why": "<what it would unblock>"}}],
  "coverage_note": "<what you actually examined, and what you did not reach>"
}}
```
