# Follow-up to the earlier review

The earlier review is evidence to verify, not an implementation specification to copy blindly. This release retains the file-based scope and does not add assessment flows.

| Earlier finding | Current treatment |
|---|---|
| Explicit Application channel or unrelated provider could produce Security alerts | Rejected before normalization; XML Provider attributes reach the same validation; import reports the rejection |
| Missing provider/channel accepted by simplified exports | Retained compatibility, explicitly documented; source authenticity remains unverified |
| SHA-256 described as duplicate control | Preserved; walkthrough states that it is not a signature or source authentication |
| Windows Status/SubStatus not normalized | Still a limit; inspect raw records if fields exist; 4625 is not labeled a proven bad password |
| UI did not show Windows domain and logon type | Effective matching identity now displays both |
| Alert explanation omitted exact threshold and identity | New alerts store parameter snapshots; detail API derives counts from actual evidence |
| Investigation status can disappear during replay | Preserved behavior; settings UI, docs, and a regression test state the limit |
| Password spraying and distributed attempts are not aggregated | Preserved scope; explicit negative tests and scenario limitations |
| Technical narrative was missing | Walkthrough, five measured scenarios, one synthetic case study, and portfolio text added |

The original 67-test suite was run at the start of this follow-up. Its clean demo again produced 85 events and five alerts. Later counts in [VALIDATION](VALIDATION.md) refer to the updated suite.

The update preserves normalized IDs for existing valid samples. Provider validation does not add fields to event identity metadata. Stored historical records are not deleted or silently reparsed. New-import validation therefore does not certify historical records.

Existing alert bodies can lack the new parameter snapshot. Their detail view uses the stored configuration, which the prior version committed atomically with alerts. This is read-only compatibility; it does not rewrite case status.

The app still lacks durable case history, binary EVTX support, live collection, authentication, and production-scale validation. The release does not claim to resolve those limits.

## Follow-up · October 29, 2026

Version 1.2 adds isolated engine replay, manual Case Notes and explicit dataset context. Earlier findings above describe v1.1; current capabilities and remaining limits are recorded in [the learning workspace](LEARNING_WORKSPACE.md) and [v1.2 validation](VALIDATION_V1_2.md).
