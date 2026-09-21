# Patch proposal

Produce the **smallest** patch that enforces the broken invariant at the last trusted decision
point, plus a regression test that **fails against the current source and passes once the
patch is applied**.

**Nothing you write is applied to the target.** The harness is read-only against the code it
audits: your diff is written to a scratch directory, tested against a throwaway copy, and
handed to a human reviewer who decides whether it is ever merged. Write it for that reviewer.

Repository: `{repo_name}` at `{repo_path}`

## The confirmed finding

{finding_block}

## Current source

Lines are displayed as `NNN| ` for your reference. **The `NNN| ` prefix is not part of the
file** - never emit it inside the diff.

{source_block}

## How the test is executed

Your test runs twice, in a container with no network, and the pair is the only thing that
clears this patch:

1. **Unpatched** - the repository read-only at `{target_mount}`, working directory
   `{scratch_mount}`, your test file written into `{scratch_mount}`. It **must fail**
   (non-zero exit). A test that passes here proves nothing about the bug.
2. **Patched** - an identical copy with your diff applied, mounted the same way. It **must
   pass** (exit 0).

So: import or invoke the code under test through `{target_mount}`, never through an installed
copy of the package, or you will be testing something other than the tree being patched. No
network, no package installs, no fixtures that are not in the repository. If you cannot write
a test that satisfies both runs, say so in `review_notes` rather than writing one that always
passes.

## Rules for the patch

1. **Smallest change that enforces the invariant.** Not the tidiest refactor, not the
   defence-in-depth bundle. One invariant, enforced once.
2. **At the last trusted decision point** - the place that still holds the authority to
   refuse. Sanitising downstream leaves every other caller exposed; refusing at the boundary
   fixes them all.
3. **Touch nothing else.** Left to patch freely, a model will happily fix a security bug while
   quietly breaking an unrelated feature. No reformatting, no renames, no dependency bumps, no
   drive-by improvements. Every changed line that the invariant did not require is a defect in
   your patch, and the reviewer will read it that way.
4. **Preserve behaviour for legitimate input.** If your patch changes what a well-formed
   request does, you have not fixed a bug, you have shipped one. Say which callers could
   notice, in `blast_radius`.
5. **Unified diff only**, with `a/` and `b/` prefixes and paths relative to the repository
   root, real context lines copied exactly from the source above, and correct `@@` headers.
   Every line inside a hunk carries a prefix character: a single space for context, `-` for
   removal, `+` for addition. A blank context line is a line containing one space, not an
   empty line. A hunk whose context lines lost their leading space is a corrupt patch, it
   will not apply, and your patch will be recorded as unproven.

## Output

End your reply with exactly one fenced ```json block:

```json
{{
  "invariant": "<the rule the code must never break, one sentence>",
  "decision_point": "<file:line where it is enforced, and why authority still exists there>",
  "patch": "--- a/path/to/file.py\n+++ b/path/to/file.py\n@@ -10,7 +10,9 @@\n context\n-old\n+new\n context\n",
  "patch_rationale": "<why this is the smallest change that enforces the invariant>",
  "test_file_name": "test_regression_<short_slug>.py",
  "test_source": "<complete runnable source; fails on the unpatched tree, passes on the patched one>",
  "test_command": ["python3", "-m", "pytest", "-q", "{scratch_mount}/test_regression_<short_slug>.py"],
  "expected_before": "<the exact failure the unpatched run produces>",
  "expected_after": "<what the patched run produces instead>",
  "blast_radius": ["<caller or behaviour a reviewer must check before merging>"],
  "review_notes": "<what you were unsure of; anything the reviewer must decide, not you>"
}}
```
