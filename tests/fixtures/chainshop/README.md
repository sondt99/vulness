# chainshop: a fixture whose bugs only matter together

**DO NOT DEPLOY. DO NOT COPY.**

vulnshop exists to test whether findings are found. This one exists to test whether they
are *composed*, which needs something vulnshop does not have: two defects where the first
is a precondition of the second.

## Ground truth

| Step | Location | Alone | In sequence |
|---|---|---|---|
| 1 | `app/profile.py` `/api/profile` leaks `OPS_SIGNING_KEY` in a debug block | information disclosure, needs only an ordinary login | supplies the key |
| 2 | `app/admin.py` `/api/admin/maintenance` passes an HMAC-verified string to `shell=True` | unreachable: the MAC cannot be forged without the key | becomes command execution |

Step 2 is genuinely unreachable on its own. Its authorisation check is cryptographically
sound: a keyed MAC with a constant-time compare over a key held only in the environment.
Nothing about it is weak until step 1 hands the attacker the key.

That is the property under test. A harness that reports these as two separate medium
findings has technically found both and missed the actual problem, which is that any
logged-in user reaches remote code execution.

Expected: one chain, severity critical, terminal impact command execution.
