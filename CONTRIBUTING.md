# Contributing

Use synthetic data only. Keep the app local-first, avoid new external browser dependencies, and do not introduce cloud credentials, remote data collection, fixed signing keys or arbitrary path loading.

Use small changes with clear commits. Add focused tests for behavior changes, then run `make check`. For container changes, rebuild, run `scripts/check_container.py`, and scan the exact image. Do not suppress high/critical scan findings or bypass the inventory checks to obtain a passing result.

New input adapters should normalize into the canonical schema, include synthetic accepted/rejected fixtures and preserve explicit identity semantics. Describe compatibility truthfully; do not claim an external format has been tested without actual evidence.

Keep secrets, environment files, private reports, generated workspaces and local verification artifacts out of commits. Review the public screenshot and samples before pushing.
