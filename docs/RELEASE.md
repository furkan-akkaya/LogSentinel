# Release preparation

Version 1.1.0 is prepared as a local source repository. No remote repository, push, tag or GitHub release was created during development. The original v1.0.0 ZIP is preserved.

Included release assets:

- Runnable FastAPI application and static UI.
- Dockerfile, Compose service, pinned runtime requirements and native instructions.
- Synthetic Linux/Windows samples, including equivalent XML and JSON exports.
- Automated tests and a GitHub Actions workflow.
- MIT license, contribution guide, security model and real browser screenshots.
- English portfolio description in the README.
- Offline project guides, five engine-verified scenarios, a synthetic SSH case study, and Turkish presentation text.

Before publishing your own copy:

1. Review the files and license attribution.
2. Keep only synthetic logs in the repository.
3. Run the commands in `docs/VALIDATION.md` on your target environment.
4. Create a GitHub repository and connect it to your local checkout.
5. Commit the reviewed source, push it, and inspect the configured CI results.
6. Add a `v1.1.0` release only after those checks pass.

For a fresh clone, generated guides are already included. After editing documentation or linked sources, install `.[docs]` and run `python tools/build_guides.py` before tests. Keep the checksum alongside the ZIP you distribute.

Suggested repository description:

> Local mini SIEM for Linux and Windows authentication logs, with five explainable detection rules, SQLite persistence, and Docker Compose deployment.

Suggested topics: `cybersecurity`, `siem`, `soc`, `log-analysis`, `fastapi`, `sqlite`, `mitre-attack`, `python`.

Use the actual screenshots under `docs/screenshots/` for the project page. Describe the app as a file-based portfolio project with automated correlation tests. Avoid claims about enterprise scale, production detection coverage, or verified account compromise.

## v1.2.0 local update

The October 29 update adds Detection Lab, retained manual Case Notes and dataset context. See [current validation](VALIDATION_V1_2.md) before publishing. No remote push, tag or GitHub release is implied by this local version update.
