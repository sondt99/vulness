# vulnshop-client

**DO NOT DEPLOY. DO NOT COPY.**

A second target that declares a dependency on `vulnshop`, so the cross-repo trace stage has
a real edge to walk and the multi-repo path is exercised by something other than a mock.

Expectations live in `tests/ground_truth/vulnshop-client.json`, deliberately outside this
directory. See `tests/ground_truth/README.md` for why.
