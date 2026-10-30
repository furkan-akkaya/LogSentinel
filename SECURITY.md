# Security model

LogEssential is a single-user, local file-analysis tool. It has **no authentication or authorization**. Run it on a trusted workstation and keep the listening port bound to loopback. It is not suitable for a shared server, LAN service, or public deployment.

## Defaults

- Native instructions bind Uvicorn to `127.0.0.1`.
- Compose publishes only `127.0.0.1:8765` by default and uses a non-root UID, read-only root filesystem, dropped capabilities and `no-new-privileges`.
- No host folders, operating system logs, Docker socket, or privileged resources are mounted.
- Allowed HTTP hosts are local names. Cross-origin mutating requests are rejected when an Origin header is present.
- Request bytes are capped before multipart parsing. File size and record counts have additional limits.
- XML entities and DTD expansion are rejected using `defusedxml`.
- User-supplied SQL filter values are parameters. UI fields are HTML-escaped, including raw logs.
- CSP restricts scripts, styles and network requests to the app. No CDN or analytics scripts are included.
- Native FastAPI telemetry and exporter auto-configuration are explicitly disabled.
- New native data directories use owner-only permissions on POSIX; the database uses mode `0600`.
- Imported filenames are display metadata. They are not used to construct output paths.
- Explicit Windows channel/provider contradictions are rejected. Missing declarations remain compatible with simplified exports, so this does not authenticate an imported source.

SHA-256 event identities support duplicate control. They are not file signatures, source authentication, or evidence that data was collected from a real host. Generated documentation contains only repository source and synthetic examples.

These boundaries reduce browser-origin risks but do not restrict other local processes. Host validation and Origin checks are not user authentication. Do not place an unauthenticated reverse proxy in front of the service.

## Sensitive data

Raw logs can contain usernames, hostnames, IPs, terminal paths and other private data. They are stored in plaintext SQLite and returned through the local API. The app does not redact or encrypt them. Protect the data directory and Docker volume using operating system permissions and disk encryption. Do not commit actual security logs to a public repository.

The `.gitignore` excludes default databases, data directories, environment files and Python caches. It cannot recognize sensitive logs stored under arbitrary filenames. Review files before publishing. The bundled samples are entirely synthetic.

Stop the application before copying a SQLite database for backup. A live WAL database also needs its WAL state; copying only the main file while it is running can omit recent transactions. No online backup feature is provided.

## Responsible use and reporting

The app analyzes existing logs and does not launch attacks or collect credentials. Treat detections as triage leads. Thresholds and incomplete source context can produce false positives or missed detections.

For a vulnerability in your fork, use GitHub private vulnerability reporting if enabled. Avoid posting real log contents or secrets in public issues. No hosted reporting service or support commitment is provided by this repository.
