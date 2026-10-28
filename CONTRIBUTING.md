# Contributing

Use Python 3.11+. Install `python -m pip install -e '.[test]'`, then run `python -m pytest`. UI changes should also pass `python tests/browser_smoke.py` after installing the browser extra and Chromium.

Install `.[docs]` and run `python tools/build_guides.py` after changing docs or source files linked from docs. Guide tests detect stale snapshots. Run `python tools/verify_examples.py` to compare five documented scenarios with the actual engine in a disposable database.

Keep parsing, detection, storage and HTTP concerns separate. Add a failing regression test for changed correlation semantics. Use synthetic events and documentation IP addresses. Do not submit production logs.

Detection changes must describe their correlation key, event-time window, threshold, evidence and false-positive tradeoffs. Preserve deterministic IDs and transaction boundaries where possible. Add a documented migration before changing persisted schemas incompatibly.

Run `python tests/docker_smoke.py` for packaging or storage changes. It creates and removes its own Compose project and volume. Do not run it against a production deployment.
