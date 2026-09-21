# Reconnaissance

Target repository: `{repo_name}` at `{repo_path}`
Languages present: {lang_summary}

Map this codebase so that hunters who see only one slice of it can still attack it
intelligently. You are writing the threat model, not receiving one.

{focus_block}

## Do this

1. Read the entry points first: what speaks to the outside world? HTTP handlers, CLI
   argument parsing, message consumers, IPC endpoints, file/format parsers, scheduled jobs.
2. Identify the **trust boundaries**. For each: who is on the low-trust side, what crosses,
   and what control is supposed to police it.
3. Identify the **areas** - coherent subsystems worth hunting independently. Prefer the
   repo's own structure over invented categories.
4. Propose **repo-specific attack classes** beyond the standard taxonomy below, wherever
   this codebase has a shape the standard list does not describe. This matters more than
   anything else you do: a generic class list produces generic, low-quality findings.

Standard taxonomy already in use: {builtin_classes}

## Budget

Read broadly but do not exhaust yourself; you have {max_turns} turns. Prefer reading
entrypoints, routing/dispatch tables, auth middleware, and data-access layers over
exhaustively reading leaf utilities.

## Output

End your reply with exactly one fenced ```json block:

```json
{{
  "architecture": "<8-15 sentences: what this software does, how requests/data flow through it, what it trusts>",
  "trust_boundaries": [
    {{"name": "<short>", "low_trust_side": "<who>", "crosses": "<what>", "control": "<what is supposed to stop them>", "files": ["path"]}}
  ],
  "areas": [
    {{"name": "<subsystem>", "paths": ["relative/path"], "why": "<one line>", "risk": "high|medium|low"}}
  ],
  "repo_specific_attack_classes": [
    {{"name": "<kebab-case>", "why_this_repo": "<one line>", "methodology": "<2-3 sentences on how to hunt it here>"}}
  ],
  "highest_value_targets": ["<file or subsystem>, <one-line reason>"]
}}
```
