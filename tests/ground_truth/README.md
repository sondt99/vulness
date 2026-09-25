# Ground truth, deliberately outside the trees it describes

Every label here used to live in a `README.md` at the root of the fixture it describes, which
put the answer key inside the directory the harness audits. A hunter runs with `cwd` set to
the target repository and `Read`, `Grep` and `Glob` in its tool allowlist, so the model
scoring the fixture could read the table telling it which three lines are bugs, which one is
a decoy, and what severity to assign. Nothing excluded it: `_UNINTERESTING_SUFFIXES` in
`coverage/scope.py` drops `.md` from the changed-file list of a `--since` run and has no
bearing on what a tool may open.

That is not a calibration target, it is an open-book exam. `tests/test_decontamination.py`
fails if a label, or anything that reads like one, reappears inside a fixture.

## Schema

One file per target repository.

| Field | Meaning |
|---|---|
| `repo` | repo id as the harness records it |
| `path` | fixture path, relative to the project root |
| `labels[].id` | stable label id, referenced by scoring output |
| `labels[].kind` | `true_positive`, or `decoy` for code that must produce no finding |
| `labels[].file` | path relative to the repo root |
| `labels[].line` / `line_end` | the span a finding may anchor anywhere inside |
| `labels[].cwe` | matched loosely: a finding without a CWE still scores on location |
| `labels[].attack_class` | the coverage-grid axis this belongs to |
| `chains[]` | defects that only matter in sequence, scored separately from single findings |

`line_end` exists because a hunter may reasonably cite the incomplete check, the sink, or the
route that reaches both. Anchoring on one line and scoring the rest as misses would measure
citation style rather than detection.
