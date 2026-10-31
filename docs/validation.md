# Verification record and live Splunk acceptance guide

## Current record — updated 28 October 2026

| Stage | Evidence | Status |
| --- | --- | --- |
| Synthetic generation | Fixed anchor generated 88 events; JSONL and manifest checker passed | Local pass |
| Unit and reference checks | 36 tests passed on Python 3.12.15, including five dashboard regression checks | Local pass |
| Expected findings | Independent Python evaluation gives the results below | Local reference pass |
| Enterprise simulation | Live ingestion gate: 50,000 raw/unique events, 20 accounts, 300 ARNs, 50,000 parsed timestamps, zero time delta; live detector gives five matching actions and three candidates | Local and Splunk pass |
| Teaching SPL execution and ingestion | User confirmed ingestion and teaching panel results in Splunk Enterprise 10.6.1.1 (build b2ae2962645c) | User-verified on the main fixture |
| Enterprise lookup deployment | Three fictional CSVs installed after approval; exact action-key/UTC-interval matches verified live for Pat-admin | Splunk pass |
| Enterprise dashboard | Saved Studio JSON matches the portable artifact; overview, all three candidate drilldowns, initial state, raw evidence and global filter verified | Splunk pass on 10.6.1.1 |
| Teaching dashboard | User-built dashboard preserved; not exported as part of enterprise delivery | Separate teaching artifact |
| GitHub Actions | Workflow prepared for Python 3.10 and 3.12 | Not executed on GitHub |
| AWS export/live ingestion | No AWS operations executed | Unverified |

Python reference tests establish intended behavior. They do not prove SPL syntax, Splunk window semantics, add-on behavior, data parsing, or Dashboard Studio compatibility.

The live enterprise checks establish those results for the fixed fixture, not every edge case listed later. See [setup_enterprise.md](setup_enterprise.md) and [completion_walkthrough.md](completion_walkthrough.md) for the exact checks, limitations and root-cause fixes. Actual result extracts are under `docs/examples/` and screenshots under `docs/screenshots/`. Summary cards: 50,000 events / 20 accounts / 300 principals / 195 failed sign-ins / 3 candidates. Timeline counts: Alex 9, Pat-admin 9, Jordan 7.

Teaching validation uncovered duplicate JSON fields from redundant `| spath`; the configured JSON source type already extracts fields. Repository searches now use `aws:cloudtrail:demo` without this redundant extraction. The login trend also uses `fixedrange=false` so the axis follows the event range. The user verified these corrections in the teaching dashboard.

## Local commands

```sh
python3 -m unittest discover -s tests -v
python3 scripts/generate_events.py --anchor 2026-10-25T12:00:00Z --force
python3 scripts/check_data.py data/synthetic_cloudtrail.jsonl --manifest data/synthetic_cloudtrail.manifest.json
python3 scripts/expected_results.py data/synthetic_cloudtrail.jsonl
```

Run these from the project root. The checker is for this synthetic schema, with intentionally omitted credential fields. It is not a full CloudTrail validator or a general secret scanner.

## Ingestion acceptance

Use a private, user-controlled demo index. Check event preview for 88 separate JSON events. Extract `_time` from `eventTime`; the fixed fixture spans 2026-10-25 02:00–10:50 UTC. Include all of this interval in the search time picker.

Run this first, with the configured index and sourcetype:

```spl
index=aws_security_demo sourcetype=aws:cloudtrail:demo
| stats count as indexed_records dc(eventID) as unique_events
```

Expected on first upload: 88 indexed records and 88 unique events. If raw count exceeds 88 but unique count is 88, an identical upload may have been repeated. If unique count exceeds 88, isolate the run before comparing results. Do not erase shared data.

Check time extraction:

```spl
index=aws_security_demo sourcetype=aws:cloudtrail:demo
| eval timestamp_delta=abs(_time-strptime(replace(eventTime,"Z$","+0000"),"%Y-%m-%dT%H:%M:%S%z"))
| stats count as events count(timestamp_delta) as parsed_times max(timestamp_delta) as maximum_seconds_difference
```

Expected: parsed time count equals event count, and maximum difference is zero. Then check:

```spl
index=aws_security_demo sourcetype=aws:cloudtrail:demo
| dedup eventID
| stats count by eventName
```

Expected: ConsoleLogin 66; ListUsers 18; AttachUserPolicy 2; CreateAccessKey 2.

## Search acceptance

All counts below assume a single generated run and the full event time range. `sort 0` retains all rows in this small demo; it is not a production scaling recommendation.

| File | Expected result | Important check |
| --- | --- | --- |
| `01_failed_login_by_user.spl` | Two rows: six failures from 203.0.113.77/account 111122223333; five from 198.51.100.88/account 444455556666 | Despite the inherited filename, grouping is account/IP, with observed usernames as context. |
| `02_success_without_mfa.spl` | One row, alex in account 111122223333 | Result is Success and MFAUsed is No. |
| `03_iam_policy_change.spl` | Four rows: two alex, two pat-admin | Caller and target differ; the two policies are AdministratorAccess and ReadOnlyAccess. |
| `04_investigation_timeline.spl` | 88 rows unfiltered | Append `\| search account_id="111122223333" actor="alex"` before the `sort` command to inspect nine core events. Do not permanently hardcode it in the dashboard. |
| `05_login_trend.spl` | Success/failure series totaling 66 ConsoleLogin events | Counts must match the raw event breakdown for the same seed/run. |
| `06_suspicious_sequence.spl` | Two rows, both alex targeting svc-analytics | Policy attachment 360 seconds and key creation 420 seconds after the qualifying login. |
| `07_identity_context.spl` | Observed account/actor combinations enriched where the lookup has a matching row | Unmatched identities show “No context in demo lookup”; this does not mean benign. |
| `08_raw_evidence.spl` | 88 rows unfiltered, including eventID and original JSON | Confirm original fields behind the summarized findings. |

Upload `lookups/demo_identity_context.csv` as a lookup table file in the same app context as the searches. The lookup filename in search 07 is literal. Confirm read permissions for the intended demo user; do not make private data public. The approved-change description is fictional context, not an automatic suppression rule.

## Sequence semantics and edge cases to verify live

The sequence search requires an IAMUser identity with an ARN, consistent recipient account/principal/source IP, at least five failures in the 15 minutes preceding a successful no-MFA sign-in, then a successful sensitive API event within 900 seconds after that sign-in. It emits one row per qualifying API event, not one row per incident. It does not require the API target to equal the caller.

Run separate synthetic variants in an isolated time range/index to verify these cases before marking search 06 validated:

- Four failures: no sequence result. Exactly five: qualifies.
- Same sequence crossing a quarter-hour boundary: rolling sequence qualifies even if the fixed-bucket failure panel does not.
- API event exactly 900 seconds after login: qualifies; 901 seconds: does not.
- Failed authentication exactly at the rolling lookback boundary: verify Splunk's `streamstats time_window` inclusivity against the intended reference behavior and adjust the query if needed.
- MFAUsed=Yes: no sequence match. A denied API call remains in the IAM/timeline views but cannot be a successful sequence change.
- Different recipient account, principal ARN, or source IP: no strong sequence match.
- Masked failed usernames with no ARN: preserve the failure burst but do not assert a principal-linked sequence.
- Repeated event IDs: deduplication prevents inflated panel results for identical uploads. It does not remove indexed copies.

Same-second ordering: the search sorts successful logins before failures at the same timestamp, so same-second failures cannot count toward that login. The independent reference also requires failures to precede the login strictly. Verify this ordering live before extending to higher-volume telemetry.

Search 06 filters to the chosen dashboard time range before computing its history. Narrow ranges can hide preceding failures/sign-ins. Include the full story or provide a deliberate lookback strategy when productionizing.

## Record the live result

Before the dashboard stage, record:

- Enterprise or Cloud, exact version/build, installed AWS add-on version (or absent).
- Index/sourcetype and parsing settings, Splunk profile timezone, search interval, and generation seed/anchor.
- Actual count/result for every query, timestamp-check result, and any query corrections.
- Lookup availability and app permissions.

Do not commit credentials, session URLs containing tokens, internal hostnames, or screenshots of unrelated account data. A public verification record can describe versions and counts without naming the private instance.
