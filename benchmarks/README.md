# Imported benchmarks

Corpora built from published datasets, in the format `vulness bench` scores against. Each
file is a bundle: a JSON array of corpora rather than one per target, because SecBench.js
alone is 566 packages.

| Bundle | Source | Targets | Labels |
|---|---|---|---|
| `secbench-js.json` | [SecBench.js](https://github.com/cristianstaicu/SecBench.js) `sink_locations_*.txt` | 566 | 569 |
| `vul4j.json` | [Vul4J](https://github.com/tuhh-softsec/vul4j) `dataset/vul4j_dataset.csv` plus fix-commit patches | 126 | 486 |

Both are `closed_world: false`. A benchmark labels the one defect it was built around and
says nothing about the rest of the project, so a finding elsewhere is an unknown rather than
a false positive, and the scorer leaves it out of the precision denominator.

## Regenerating

Nothing here downloads on its own, so what a run was scored against is a file you can diff
rather than a fetch that may answer differently tomorrow.

```bash
# SecBench.js: the sink locations are the ground truth, already file:line.
mkdir -p /tmp/secbench && cd /tmp/secbench
for n in ace_breakout command-injection path-traversal prototype_pollution redos; do
  curl -sSLO "https://raw.githubusercontent.com/cristianstaicu/SecBench.js/master/sink_locations_$n.txt"
done
vulness corpus secbench --sinks /tmp/secbench -o benchmarks/secbench-js.json

# Vul4J: the CSV names a fix commit per entry; the labels come from its diff.
curl -sSL -o /tmp/vul4j.csv \
  https://raw.githubusercontent.com/tuhh-softsec/vul4j/main/dataset/vul4j_dataset.csv
mkdir -p /tmp/vul4j_patches
python - <<'PY' | xargs -n2 -P6 sh -c 'curl -sSL --max-time 30 -o "$0" "$1"'
import csv
for row in csv.DictReader(open("/tmp/vul4j.csv")):
    url = (row.get("human_patch") or "").strip()
    if url.startswith("https://github.com/"):
        print(f"/tmp/vul4j_patches/{row['vul_id']}.patch\n{url}.patch")
PY
vulness corpus vul4j --csv /tmp/vul4j.csv --patches /tmp/vul4j_patches -o benchmarks/vul4j.json
```

## What these do and do not measure

A label is where the fix landed, which is a proxy for where the bug lived and worth naming
as one. A fix commit can refactor, and a one-line change far from the root cause labels the
wrong place. It is still the only localisation either benchmark ships, and it is what the
literature scores against.

Scoring a run against these needs the targets checked out and buildable, which neither
bundle provides: Vul4J is Java with per-entry Maven and Gradle toolchains, SecBench.js is
npm packages at pinned versions. The corpora are ready; the build environments are the
remaining work, and they are the reason `RESEARCH.md` §4 called this the larger item.
