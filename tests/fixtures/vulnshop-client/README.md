# vulnshop-client: consumer fixture

**DO NOT DEPLOY. DO NOT COPY.**

A second deliberately weak repository that declares a dependency on `vulnshop`. It exists
so the cross-repo trace stage has a real edge to walk, and so the multi-repo path is
exercised by something other than a mock.

Ground truth: `fetch_report` forwards caller-controlled `id` and `org` straight to the
vulnshop endpoint that concatenates them into SQL, so vulnshop's injection is reachable
from here. `cache_report` joins an unsanitised `name` into a path. Both are intentional.
