"""Turning a published benchmark into something this scorer can read.

Offline by construction: every input here is written to tmp_path. An importer that needs
the network to be tested is one nobody runs.
"""

from __future__ import annotations

import json
from pathlib import Path

from vulness.bench import dump_corpora, from_secbench_js, from_vul4j, load_corpora
from vulness.bench.importers import changed_source_spans

# The three spellings that actually appear upstream: spaced, unspaced, and indented.
SINKS = """\
pdfinfojs_0.3.6 > lib/pdfinfo.js:47:23
songcaihong_1.0.0>index.js:5:8
  mathjs_7.4.0 > lib/utils/object.js:131:17
not a sink line at all
"""


def _sinks(tmp_path: Path, stem: str, body: str = SINKS) -> dict[str, Path]:
    p = tmp_path / f"sink_locations_{stem}.txt"
    p.write_text(body)
    return {stem: p}


def test_secbench_parses_every_spelling_of_a_sink(tmp_path: Path) -> None:
    corpora = from_secbench_js(_sinks(tmp_path, "command-injection"))
    assert {c.repo for c in corpora} == {"pdfinfojs_0.3.6", "songcaihong_1.0.0", "mathjs_7.4.0"}
    label = next(c for c in corpora if c.repo == "pdfinfojs_0.3.6").labels[0]
    assert (label.file, label.line, label.cwe) == ("lib/pdfinfo.js", 47, "CWE-78")


def test_secbench_maps_each_class_to_a_weakness(tmp_path: Path) -> None:
    for stem, cwe in (
        ("path-traversal", "CWE-22"),
        ("prototype_pollution", "CWE-1321"),
        ("redos", "CWE-1333"),
        ("ace_breakout", "CWE-94"),
    ):
        corpora = from_secbench_js(_sinks(tmp_path, stem))
        assert corpora[0].labels[0].cwe == cwe, stem


def test_secbench_targets_are_open_world(tmp_path: Path) -> None:
    """A benchmark labels the one defect it was built around. Counting a finding elsewhere
    in a real npm package as a false positive marks a harness down for working."""
    assert all(not c.closed_world for c in from_secbench_js(_sinks(tmp_path, "redos")))


def test_secbench_ignores_junk_without_dropping_the_file(tmp_path: Path) -> None:
    corpora = from_secbench_js(_sinks(tmp_path, "redos", "garbage\n\n" + SINKS))
    assert len(corpora) == 3


# ------------------------------------------------------------------- vul4j

PATCH = """\
From abc Mon Sep 17 00:00:00 2001
diff --git a/src/main/java/x/Codec.java b/src/main/java/x/Codec.java
--- a/src/main/java/x/Codec.java
+++ b/src/main/java/x/Codec.java
@@ -174,6 +174,9 @@ public class Codec {
     safe();
+    check();
diff --git a/src/test/java/x/CodecTest.java b/src/test/java/x/CodecTest.java
--- a/src/test/java/x/CodecTest.java
+++ b/src/test/java/x/CodecTest.java
@@ -10,2 +10,20 @@ public class CodecTest {
+    assertThrows();
diff --git a/pom.xml b/pom.xml
--- a/pom.xml
+++ b/pom.xml
@@ -1,3 +1,4 @@
+<!-- bump -->
"""


def test_a_diff_yields_spans_for_source_only() -> None:
    spans = changed_source_spans(PATCH)
    assert spans == {"src/main/java/x/Codec.java": [(174, 182)]}


def test_test_and_build_files_are_not_labelled() -> None:
    """The regression test added by a fix commit is not where the vulnerability was. A
    corpus that says otherwise scores a harness for failing to flag its own test suite."""
    spans = changed_source_spans(PATCH)
    assert not any("test" in k.lower() or k.endswith(".xml") for k in spans)


def _vul4j(tmp_path: Path, *, with_patch: bool = True) -> tuple[Path, Path]:
    csv_path = tmp_path / "vul4j.csv"
    csv_path.write_text(
        "vul_id,cve_id,cwe_id,repo_slug,human_patch\n"
        "VUL4J-1,CVE-2017-18349,CWE-502,alibaba/fastjson,https://github.com/a/b/commit/abc\n"
        "VUL4J-2,CVE-2020-0001,CWE-22,other/proj,https://github.com/c/d/commit/def\n"
    )
    patches = tmp_path / "patches"
    patches.mkdir()
    if with_patch:
        (patches / "VUL4J-1.patch").write_text(PATCH)
    return csv_path, patches


def test_vul4j_builds_a_corpus_per_entry(tmp_path: Path) -> None:
    corpora = from_vul4j(*_vul4j(tmp_path))
    assert [c.repo for c in corpora] == ["VUL4J-1"]
    label = corpora[0].labels[0]
    assert (label.file, label.line, label.line_end, label.cwe) == (
        "src/main/java/x/Codec.java",
        174,
        182,
        "CWE-502",
    )
    assert "CVE-2017-18349" in label.note


def test_vul4j_skips_an_entry_with_no_patch(tmp_path: Path) -> None:
    """An entry emitted with no labels scores every run as perfect recall on it."""
    assert from_vul4j(*_vul4j(tmp_path, with_patch=False)) == []


# ------------------------------------------------------------------ bundles


def test_a_bundle_round_trips(tmp_path: Path) -> None:
    corpora = from_secbench_js(_sinks(tmp_path, "redos"))
    out = tmp_path / "bundle" / "secbench.json"
    out.parent.mkdir()
    assert dump_corpora(corpora, out) == 3
    assert json.loads(out.read_text())[0]["closed_world"] is False

    loaded = load_corpora(out.parent)
    assert set(loaded) == {c.repo for c in corpora}


def test_a_directory_may_mix_bundles_and_single_corpora(tmp_path: Path) -> None:
    """The fixture corpora stay one file each because people edit them; an imported
    benchmark is several hundred targets and cannot be."""
    dump_corpora(from_secbench_js(_sinks(tmp_path, "redos")), tmp_path / "bundle.json")
    (tmp_path / "single.json").write_text(
        json.dumps({"repo": "solo", "path": "x", "labels": [], "chains": []})
    )
    loaded = load_corpora(tmp_path)
    assert "solo" in loaded and "pdfinfojs_0.3.6" in loaded


def test_the_shipped_benchmark_bundles_load() -> None:
    directory = Path(__file__).resolve().parents[1] / "benchmarks"
    if not directory.is_dir():
        return
    loaded = load_corpora(directory)
    assert len(loaded) > 500, "the imported benchmarks should dwarf the fixtures"
    assert all(not c.closed_world for c in loaded.values())
    assert all(c.labels for c in loaded.values()), "a corpus with no labels scores nothing"
