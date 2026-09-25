# vulnshop

**DO NOT DEPLOY THIS. DO NOT COPY THIS CODE.**

A small Flask application used as a target by this project's test suite. It is not wired
into anything, has no dependencies installed, and is never imported: `pytest` does not
execute it.

What it is expected to contain, and what a run is expected to conclude about it, is
recorded in `tests/ground_truth/vulnshop.json`, deliberately outside this directory. See
`tests/ground_truth/README.md` for why.
