# Feedback: sharpen the hunt that is still running

Run `{run_id}` has had {rejection_count} hunter findings thrown out so far. Each one cost a
hunt task and produced nothing. Your job is to stop the hunters that have not started yet
from repeating those mistakes - the run is still in flight, and what you write here is
appended to the prompts of tasks still sitting in the queue.

You are not re-judging the rejected findings. The rejection already happened. Treat it as
ground truth and work backwards to the hunter behaviour that caused it.

## Failure modes the harness clustered

Identical rejection reasons are collapsed; the count is how many findings died that way.

{modes_block}

## The rejections themselves

{rejections_block}

## Write the addendum

Name the *behaviours* behind these rejections, not the individual bugs. A failure mode is
something a hunter can catch itself doing - "quotes line numbers from memory instead of
re-reading the file before writing the trace", "names the attacker as a role instead of a
principal with stated access", "claims an impact the trace stops two hops short of".

Then write corrective guidance for the hunters still queued. It must be:

- **Specific to what went wrong here.** "Be careful" prevents nothing. If findings died on
  line numbers, say to re-open the file immediately before writing each trace step and to
  quote the line text alongside the number.
- **Actionable before filing**, not after. A hunter reads this at the start of its task.
- **Short.** At most {max_chars} characters. It is appended to an already long prompt, and
  every character you spend is context the hunt itself no longer has.
- **A tightening of the existing contract**, never a replacement for it. Do not restate
  rules the hunters already carry; add only what these rejections prove they are missing.

If the rejections are too few or too scattered to support a real pattern, say so in
`failure_modes` and keep the addendum to the one thing you can actually defend.

## Output

End your reply with exactly one fenced ```json block:

```json
{{
  "failure_modes": [
    {{
      "mode": "<the hunter behaviour, one line>",
      "count": 0,
      "evidence": "<the rejection reason that demonstrates it>",
      "fix": "<the instruction that would have prevented it>"
    }}
  ],
  "addendum": "<markdown, at most {max_chars} characters, imperative, addressed to a hunter about to start>"
}}
```
