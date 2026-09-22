# Research context

Collected 2026-09-22 to support `EVALUATION.md`. This is the outside view: what the
published record says about autonomous vulnerability discovery, and what each result implies
for this harness. Figures are quoted from the linked sources; where a number comes from a
secondary report rather than a primary paper it is marked.

---

## 1. Hybrid architectures beat LLM-only, decisively

The largest controlled evaluation of autonomous vulnerability discovery to date is DARPA's
AI Cyber Challenge. In the 2025 finals, seven cyber reasoning systems ran roughly 143 hours
fully autonomously over 53 challenge projects derived from critical infrastructure software.
Teams found 86% of the synthetic vulnerabilities, up from 37% at semifinals, and patched 68%,
up from 25%. Across 54 million lines of code they discovered 54 unique synthetic
vulnerabilities, patched 43, and found 18 real ones.

The [SoK](https://arxiv.org/html/2602.07666v2) analysing those systems is the directly useful
artifact. Its central finding:

- Parallel fuzzing found **54% of vulnerabilities (34 of 63)**, and the split by language was
  stark: **75% of C** versus **17% of Java**.
- LLM-based methods solved **22 additional** vulnerabilities fuzzing could not reach, winning
  on targeted detection, input-grammar obstacles, and logical constraints such as regex and
  encoding transformations.
- The two teams that leaned purely on one pipeline scored **lowest, 105.0 and 9.6**.
- The winner used an ensemble-first design: multiple independent bug-finding modules and
  eight patching agents with diverse strategies.

Two further results are worth internalising because they are about engineering, not models.
"Stability and accuracy were deciding factors", and the winner accumulated 80% more points
than second place largely through sustained availability after competitors failed. Separately,
"creating a technically advanced system and a well-engineered system are separate challenges":
several high-capability systems underperformed on infrastructure failures.

On patch quality, automated validation is not correctness: **45.6%** of one baseline's patches
"pass all automatic validation, yet contain semantic issues", and **37.7%** for another.

**Implication for vulness.** The harness is LLM-only. That is defensible for its target,
which is source-level reasoning over web application code rather than memory-safety bugs in C,
but it is the largest research-backed gap in the design. It also means the fail-to-pass gate
in `fixer.py` should not be read as proof of a correct patch.

## 2. The Semgrep paradox: static analysis belongs in the prompt, not in the toolbelt

Cloudflare reports that they "plumbed Semgrep all the way through, and the Hunters invoked it
zero times in a month of runs." The SoK explains why that shape fails: successful systems did
not offer static analysis as a tool an agent could choose. They **injected** its output,
alongside dynamic execution traces and CWE-specific guidance, directly into the prompt as
contextual enrichment.

This resolves the apparent contradiction between the blog and the literature, and it is a
cheap change. `PLAN.md` already anticipates the right shape: "Use as a *cell seeder*, never as
an agent tool."

## 3. Variant analysis is the tractable framing

Google's [Big Sleep](https://projectzero.google/2024/10/from-naptime-to-big-sleep.html),
formerly Project Naptime, found a stack buffer overflow in SQLite, reported as the first
real-world vulnerability discovered by an LLM agent. The methodological point is the framing
rather than the result: "the variant-analysis task is a better fit for current LLMs than the
more general open-ended vulnerability research problem. By providing a starting point, such as
the details of a previously fixed vulnerability, they remove a lot of ambiguity."

**Implication for vulness.** `weakness_digest()` and the `repo_maps` / `coverage_history`
tables are already the right substrate. A variant-analysis hunt kind, seeded from a confirmed
prior finding rather than from a cell, is a small addition on top of machinery that exists.

## 4. Benchmarks worth adopting

The current calibration target is two fixtures with a handful of planted defects. That cannot
measure precision or recall. Reproducible alternatives, roughly in order of fit:

| Benchmark | Content | Fit |
|---|---|---|
| [Vul4J](https://github.com/iris-sast/cwe-bench-java) | 79 reproducible Java vulnerabilities, each with a proof-of-vulnerability test | Best fit: the PoV tests map directly onto the PoC contract |
| CWE-Bench-Java | 120 Java vulnerabilities with build info; an [extended set](https://zenodo.org/records/18691625) has 130 across 12 CWEs and 103 projects | Good for recall, no PoV tests |
| [SecBench.js](https://arxiv.org/pdf/2607.02825) | 600 executable server-side JavaScript vulnerabilities across five classes | Closest to the web-application target |
| ARVO | C/C++ vulnerabilities harvested from OSS-Fuzz | Only if memory-safety becomes a target |
| CVE-Bench / LiveCVEBench / CVE-Genie | CVE reproduction at scale; CVE-Genie covers 841 CVEs over 267 projects and 141 CWEs | For end-to-end agentic evaluation |

For calibration against false positives specifically, note the published range: LLM agents
reduced a static-analysis false-positive rate above 92% down to **6.3%** on the OWASP Benchmark
in the best configuration, and a neuro-symbolic approach reports a **43.7%** false-positive
reduction with **11.2%** better recall than CodeQL, Joern and LLM-only pipelines. On raw
detection, one comparison puts Claude at 78.3% precision and 78.3% recall, and DeepSeek V3 at
72.3% precision with 84.7% recall, the latter detecting more but false-positiving more.

Cloudflare's own comparable figure is a validation rejection rate that fell from **40% to 11%**
while high-integrity findings rose from **35% to 58%**. A healthy adversarial validator rejects
somewhere in that band. This harness rejects 0%.

## 5. LLM judges do not spontaneously reject

Rejection has to be engineered and calibrated. The documented failure modes are position bias,
verbosity bias, and self-preference or self-enhancement bias, and the standard detection
technique is a swap test: present the same pair twice with the order reversed and check whether
the verdict flips. The consensus recommendation is that "most bias in LLM-as-judge is detectable
and mitigatable if the judge itself is treated as a system that needs testing."

**Implication for vulness.** `EVALUATION.md` §4 shows the zero-rejection rate here is
structural rather than bias, but the remedy is the same: the judge needs its own test suite.
Planted false positives in the fixtures, a non-zero rejection rate asserted as a test, and a
swap test over finding presentation order.

## 6. Exploit chains and primitive composition

`chain.py` has no counterpart in the reference architecture, and the outside record supports
the direction. Cloudflare's later Mythos work describes the frontier as "reasoning across
multiple small primitives, connecting them into working exploit paths, writing proof code,
compiling it, running it, learning from failure, and trying again" (secondary report).
Academically, [PrimSynth](https://arxiv.org/html/2609.02647v1) synthesises and validates
chainable exploit primitives for Linux kernel bugs, and
[Teams of LLM Agents can Exploit Zero-Day Vulnerabilities](https://aclanthology.org/2026.eacl-long.2.pdf)
reports multi-agent composition results.

The "latent primitive" idea, recording a dangerous capability that is currently unreachable so
a composer can find the half that never becomes a finding, is a genuine contribution. It is
undermined today only by the unstable fingerprint in `EVALUATION.md` §3.6.

## 7. Multi-run variance

Cloudflare reports that a single run finds only about half the bugs found across multiple runs,
and that the ones a single run finds skew simpler and less subtle (secondary report). This is
the argument for cross-run memory, which this harness already has, and against treating any
single run's output as a coverage claim.

## 8. Harnesses are themselves a target

This bears directly on `EVALUATION.md` §3.1. Agentic code-review tooling has a live record of
compromise through repository-controlled configuration:

- **CodeRabbit**, installed on over two million repositories, reached remote code execution
  through a malicious `.rubocop.yml` in a pull request, exposing API tokens, its PostgreSQL
  database, and write access to more than a million repositories.
- **Qodo Merge** leaked a GitHub token with write permissions via prompt injection in a PR
  comment, and on GitLab was induced to emit `/approve` quick-actions that were then executed
  with the tool's elevated permissions.
- **Claude Code** itself: [GHSA-ph6w-f82w-28w6](https://github.com/liatrio-labs/claude-code-gauntlet/blob/main/docs/research/artifacts/05-prompt-injection-vulnerabilities.md)
  (CVSS 8.7, disclosed July 2025, patched August 2025) exploited the hooks mechanism, where
  `.claude/settings.json` defines shell commands run on lifecycle events. Opening a repository
  containing a malicious settings file was sufficient for arbitrary code execution.
- **CVE-2025-53773**, remote code execution in GitHub Copilot via prompt injection that
  modified workspace settings to auto-approve tool calls.
- **CamoLeak** (CVE-2025-59145, CVSS 9.6), hidden Markdown comments instructing Copilot Chat to
  exfiltrate secrets from private repositories.

The generalisation, from [CSA's work on README injection](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_readme_instruction_injection_ai_coding_agents_20260317-csa-styled.pdf)
and [Palo Alto Unit 42](https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/), is that
any agent-readable file in a repository is an injection surface: `CLAUDE.md`, `AGENTS.md`,
`.claude/settings.json`, `.mcp.json`, linter configs.

**Implication for vulness.** Hooks and MCP servers are a different mechanism from tool
permissions, so `disallowedTools` does not contain them. This is the top item in the fix list.

## 9. Where Cloudflare has moved since the reference post

The [later post](https://blog.cloudflare.com/vulnerability-discovery-remediation/) adds
context-aware triage: findings are scored against production traffic, recent attack activity on
the specific endpoint, and WAF rules already blocking the attack. The framing is that source
alone "doesn't tell you whether that code is deployed. It doesn't tell you whether anyone is
actually hitting that route." Runtime evidence can raise a rating.

Note that post publishes no precision or scale figures, so it should be read as direction
rather than result.

**Implication for vulness.** `judge.py` asks the reachability question with no runtime signal
at all, only filesystem deployment artifacts. That is the largest capability gap against
current Cloudflare, and it is also the hardest to close without a production deployment to
observe.

---

## Sources

- [Build your own vulnerability harness](https://blog.cloudflare.com/build-your-own-vulnerability-harness/), Cloudflare
- [Context-aware vulnerability discovery and remediation](https://blog.cloudflare.com/vulnerability-discovery-remediation/), Cloudflare
- [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill)
- [SoK: DARPA's AI Cyber Challenge: Competition Design, Architectures, and Lessons Learned](https://arxiv.org/html/2602.07666v2)
- [AI Cyber Challenge results](https://www.darpa.mil/news/2025/aixcc-results), DARPA
- [Trail of Bits' Buttercup](https://blog.trailofbits.com/2025/08/09/trail-of-bits-buttercup-wins-2nd-place-in-aixcc-challenge/): 28 vulnerabilities, 19 patches, 90% accuracy at $181/point with non-reasoning models
- [From Naptime to Big Sleep](https://projectzero.google/2024/10/from-naptime-to-big-sleep.html), Google Project Zero
- [Sifting the Noise: LLM Agents in Vulnerability False Positive Filtering](https://arxiv.org/html/2601.22952v1)
- [Reducing False Positives in Static Bug Detection with LLMs](https://arxiv.org/pdf/2601.18844)
- [ZeroFalse: Improving Precision in Static Analysis with LLMs](https://arxiv.org/html/2510.02534)
- [Quantifying and Mitigating Self-Preference Bias of LLM Judges](https://arxiv.org/pdf/2604.22891)
- [Bias in the Loop: Auditing LLM-as-a-Judge for Software Engineering](https://arxiv.org/html/2604.16790v1)
- [PrimSynth: Discover, Validate, and Synthesize Exploit Primitives](https://arxiv.org/html/2609.02647v1)
- [Teams of LLM Agents can Exploit Zero-Day Vulnerabilities](https://aclanthology.org/2026.eacl-long.2.pdf)
- [cwe-bench-java](https://github.com/iris-sast/cwe-bench-java) and the [extended dataset](https://zenodo.org/records/18691625)
- [JavaVulBench](https://arxiv.org/pdf/2607.02825), which also surveys SecBench.js and Vul4J
- [FaultLine: Automated Proof-of-Vulnerability Generation using LLM Agents](https://arxiv.org/html/2507.15241v1)
- [README Injection: Repository Files Hijacking AI Coding Assistants](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_readme_instruction_injection_ai_coding_agents_20260317-csa-styled.pdf), CSA
- [Fooling AI Agents: Web-Based Indirect Prompt Injection Observed in the Wild](https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/), Unit 42
- [Prompt injection vulnerabilities in Claude Code](https://github.com/liatrio-labs/claude-code-gauntlet/blob/main/docs/research/artifacts/05-prompt-injection-vulnerabilities.md)
- [Your AI, My Shell: Prompt Injection Attacks on Agentic AI Coding Editors](https://arxiv.org/html/2509.22040v2)
- [google/oss-fuzz-gen](https://github.com/google/oss-fuzz-gen)
