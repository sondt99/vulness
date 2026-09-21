# vulnshop: deliberately vulnerable calibration target

**DO NOT DEPLOY THIS. DO NOT COPY THIS CODE.**

Every defect here is intentional. This exists so s-ness can be measured against known
ground truth rather than judged on how convincing its output reads.

It is a fixture, not an application: no entry point, no dependencies installed, never
imported by the test suite. `pytest` does not execute it.

## Ground truth

| # | Location | Defect | Expected |
|---|---|---|---|
| 1 | `api/reports.py:20` | `"... WHERE id = '%s'" % report_id` on an unauthenticated route | true positive, critical |
| 2 | `storage/files.py:23` | rejects a leading `/` but not `../`, then joins into the tenant root | true positive, high |
| 3 | `api/auth.py:29` | `/api/login` mints a session and signed token for any claimed user, no credential check | true positive, critical |
| 4 | `api/auth.py:19` | `hmac.compare_digest`, `secrets` nonce, keyed MAC | **decoy: any finding here is a false positive** |

Defect 3 was not planted on purpose. It was written while building the fixture, found by
the harness, and confirmed by hand afterwards. It stays because an accidental bug is a
better test than a designed one.

## Running the calibration

```bash
sness run tests/fixtures/vulnshop -b 42 --gapfill 1
sness findings -v confirmed
```

A healthy run finds 1, 2 and 3, and says nothing about 4. Anything reported against the
`verify_token` / `make_token` path is a false positive worth an issue.

Coverage will read low because the grid is sized for real repositories. That is expected
on a 102 line target and is not a defect.
