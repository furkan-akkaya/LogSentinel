# Technical design

## Components and ownership

| Module | Responsibility |
|---|---|
| `parsers.py` | Parse Linux text or Windows named fields; validate timestamps and normalize IPs |
| `detection.py` | Pure event-time correlation; return alert definitions and evidence IDs |
| `storage.py` | SQLite schema, deduplication, transactions and rule replay |
| `app.py` | Bounded imports, typed HTTP API, local-origin checks and static assets |
| `static/` | Dashboard, explorer, investigations and settings; no build step |

The browser reads the same persisted records used by the detection engine. There are no precomputed demo alerts. Demo files ship inside the Python package so wheel and Docker installations work outside the repository.

An example-driven [walkthrough](learning/HOW_IT_WORKS.md), [scenario guide](INDEX.md), and [synthetic case report](reports/SSH_CASE_STUDY.md) explain these modules with actual demo records.

## Normalized event

Each event contains `id`, UTC `timestamp`, `source`, `event_type`, `host`, `user`, nullable `source_ip`, source `raw`, parser `metadata`, and ingestion `filename`.

Event types are `ssh_failure`, `ssh_success`, `sudo_failure`, `windows_failure`, and `windows_success`. Linux usernames retain case. Windows correlation case-folds host, account, and domain names. IPv4-mapped IPv6 addresses normalize to IPv4.

The SHA-256 identity covers normalized timestamp, source, event type, host, user, IP, and metadata. Raw formatting and upload filename do not participate. Windows metadata includes record ID and channel; Linux metadata includes PID and source port when available. Equivalent Windows XML and JSON records therefore deduplicate when the same identity fields are supplied.

When a source omits a unique record identifier, genuinely separate events with identical normalized fields can collapse. Missing optional metadata in a different export can also prevent deduplication. This is a documented file-analysis tradeoff, not a universal event identity scheme. The first imported raw representation and filename are retained.

## Correlation semantics

Rules sort by normalized event time and event ID, independent of upload order. Every import replays all stored events, so failures and successes can arrive in different files and different orders. Missing correlation identities never form a shared "unknown" group.

Failure thresholds use a rolling lookback of `window_seconds`; the lower time boundary is inclusive. After a threshold fires, its evidence expands inside an episode anchored at the first evidence record. An episode lasts at most one configured window. A long burst can produce multiple bounded episodes; nearby episodes can share boundary evidence. A successful authentication ends the current failure episode for that identity.

Success-after-failure rules require at least `success_threshold` matching failures inside the lookback. Only failures with timestamps **strictly earlier** than the success qualify. Equal-time records cannot prove ordering. A success consumes earlier failures, so another success does not repeatedly alert on the same earlier sequence. Equal-time failures can still qualify for a later success.

SSH password and keyboard-interactive failures count toward rules. Public-key failures remain searchable but do not count as password guessing. Successful public-key authentication can follow password failures and trigger the success rule. These are review signals. A user mistyping their own password can produce the same sequence.

Linux sudo PAM records identify the invoking user using `ruser`, then `logname`. A missing invoking user excludes the record from correlation. The PAM `user` field stays as target account metadata. Summaries such as "3 incorrect password attempts" are stored but excluded from correlation because they may duplicate PAM records. Each PAM record counts once; the app does not assume an aggregate message contains three independent events.

Windows domain and logon type are required and included in the key. Different logon types are deliberately not joined. Events with absent network data remain visible but do not trigger these rules. This reduces false joins at the cost of missed detections for incomplete exports.

## Transactions and replay

An import opens `BEGIN IMMEDIATE`, inserts unique events, checks the local cap, runs detection and updates alerts, then commits. A failure rolls back the entire operation. Concurrent writes serialize through SQLite. WAL enables readers while a writer is active. The connection has a 30-second busy timeout.

Alert IDs hash rule, correlation identity, and episode anchor (or success event ID). Reimporting the same events yields the same IDs. Existing investigation status survives replay when an alert ID still exists. Importing earlier evidence or changing thresholds can change episode anchors, remove alerts, or create new ones with `new` status. There is no audit history or persistent suppression engine.

Version 1.1 stores the applied threshold and time window inside each new alert body. Detail explanations derive counts and the effective correlation identity from linked events. No second threshold constant exists in the UI. Legacy alert bodies use the configuration previously committed with their detection results; reads do not rewrite them.

Offline HTML guides are built from Markdown using a development-only renderer. Generated source views include an explicit repository-source allowlist determined by documentation links. The production service serves packaged static files and needs no renderer or CDN. Guide tests check source drift and local links.

Setting changes and replay use one transaction. A process restart reuses persisted events, settings, alerts and investigation statuses. There is no schema migration framework in version 1; future incompatible schemas must introduce explicit migrations.

## Resource limits

- 5 MiB UTF-8 file; request envelope limit adds 64 KiB for multipart fields.
- 20,000 nonempty records per file; 64 KiB per record.
- 50,000 persisted events per database.
- List responses default to 50 records and cap at 200.
- Rule window: 10–3,600 seconds. Thresholds: 2–100 records.

The dataset is loaded in memory for replay, and search uses SQLite substring scans. Raw content is not indexed as full text. Run one worker and keep datasets small. Limits constrain typical use; they are not a substitute for access control against hostile local clients. No high-volume or production capacity claim is made.

## Technology choices

FastAPI provides typed inputs and OpenAPI with a small Python service. SQLite avoids server dependencies and supports transactions. Static JavaScript and CSS keep installation independent of Node.js. Docker Compose packages the same application; its named volume owns the database. Python's `defusedxml` parser rejects DTD/entity expansion. The API documentation is local HTML, avoiding CDN dependencies.
