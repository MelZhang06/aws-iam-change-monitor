# Enterprise IAM-user simulation

This is a bounded educational simulation, not real customer data, not a statistically calibrated enterprise model, and not a performance certification. All event identities use `IAMUser`. Deliberately modelled legacy automation users are not an AWS identity-management recommendation. Assumed roles, role chaining, and Identity Center are outside this version's scope.

## Generated and locally verified

Fixed anchor: **2026-10-28T00:00:00Z**, seed **41**.

| Property | Result |
| --- | --- |
| Total events | 50,000 |
| Fictional AWS accounts | 20 |
| Distinct caller ARNs | 300; names repeat across accounts |
| Event types | 11 across IAM, EC2, S3, STS and console sign-in |
| JSONL size | Approximately 31.85 MB |
| UTC event range | 21 Oct 2026 00:00:11 through 27 Oct 2026 23:59:47 |
| Melbourne event range | 21 Oct 2026 11:00:11 through 28 Oct 2026 10:59:47 AEDT |
| Sequence-matching actions | 5 |
| Queue candidates | 3; two High by the demo rule, one Review |
| Unit tests | 36 passed on Python 3.12.15 |

Live Splunk verification is now complete for this fixture in Enterprise 10.6.1.1: ingestion and timestamps, three candidates/five actions, all three drilldowns, context matching and global time filtering. Search latency and production throughput have **not** been benchmarked. The existing 88-event fixture remains available. No AWS API calls were performed. See [the setup guide](setup_enterprise.md) and [work log](completion_walkthrough.md).

The event mix contains normal read operations, MFA-protected logins, occasional failed authentication and denied APIs, ordinary administration, different account activity volumes, Melbourne working-hour patterns, quieter weekends, and around-the-clock automation. Office users share source addresses within an account; automated users have a separate shared source address. Regional EC2 calls span three regions; most IAM/global calls use us-east-1. Exact mix and daily counts are recorded in `examples/enterprise_expected_results.json`.

The model is intentionally simplified: human activity samples office-hour distributions rather than reproducing full browser sessions; background actions are not a complete application workflow. Deliberate scenarios use a known chronology. All IPs are documentation addresses, so geolocation is not meaningful.

## Scenario contract

Times below use the fixed anchor and Melbourne AEDT.

| Case | Evidence | Expected sequence/queue outcome |
| --- | --- | --- |
| alex, account 111122223333 | Six failures, no-MFA sign-in, administrator policy and cross-user key creation; sign-in 26 Oct 13:07 | Two actions; one High candidate |
| jordan, account 900000000001 | Five failures, no-MFA sign-in and cross-user key creation; sign-in 24 Oct 13:07 | One action; one Review candidate |
| pat-admin, account 777788889999 | Six failures, no-MFA sign-in, administrator policy and cross-user key creation; sign-in 23 Oct 13:07 | Two actions; one High candidate that has fictional approved-change context |
| casey | Isolated failures | No full-sequence candidate |
| taylor | No-MFA sign-in followed by denied access changes | Denials visible in detail; no successful-change candidate |
| morgan | Failure burst followed by an MFA-protected login and access changes | Visible activity; no no-MFA sequence candidate |

The approved lookalike deliberately remains in the queue. The raw rule cannot determine authorisation. A matching change record is supporting evidence to inspect, not automatic suppression or proof of safety. Absence from this specific queue means the rule did not match; it does not mean the identity is safe.

Manifest scenario names and expected outcomes are kept separate from ingested events. Detection evaluation uses the event evidence, not scenario labels. The manifest lists evidence IDs for each case, enabling precise verification.

## Files and reproducibility

Generated files, kept out of git by the existing `data/*` rule:

- `data/enterprise_cloudtrail.jsonl`: upload only this as event data.
- `data/enterprise_cloudtrail.manifest.json`: counts, hash and scenario ground truth; do not ingest.
- `data/enterprise_cloudtrail.accounts.csv`: fictional account ownership and environment context.
- `data/enterprise_cloudtrail.identities.csv`: fictional principal-ARN ownership context.
- `data/enterprise_cloudtrail.approved_changes.csv`: narrowly scoped, time-bound fictional change records.

Regenerate the fixed file set from the project root (overwrites this enterprise output set only):

```sh
python3 scripts/generate_enterprise.py --anchor 2026-10-28T00:00:00Z --force
python3 scripts/check_data.py data/enterprise_cloudtrail.jsonl --profile enterprise --manifest data/enterprise_cloudtrail.manifest.json
python3 scripts/verify_enterprise.py data/enterprise_cloudtrail.jsonl
python3 -m unittest discover -s tests -v
```

Omit `--anchor` for a seven-day window ending at the current UTC minute. Changing the anchor changes timestamps and IDs; keep runs isolated. `--count` accepts 1,000 to 1,000,000 events, but only the default 50,000-event file has been generated and fully checked at this stage. A larger requested count increases local resource use and ingestion volume; measure file size before import.

The local reference evaluator establishes intended findings. It does not execute SPL or establish Splunk streamstats boundary behaviour. Regenerated scenarios move with the anchor; use the manifest for their precise dates.

## Import gate: preserve the existing teaching demo

1. Keep the current dashboard and index `aws_security_demo` unchanged. Create a separate **events** index named `aws_security_enterprise_demo` in Settings > Indexes > New Index.
2. Upload `data/enterprise_cloudtrail.jsonl` once using Add Data > Upload. Reuse the already configured `aws:cloudtrail:demo` source type, host `synthetic-enterprise-demo`, and the new index. Verify one event per line and `eventTime` timestamps in the preview. Do not select the manifest or CSVs as event data.
3. In Search & Reporting, select **All time** for this bounded fixture and run the ingestion gate below.
4. Only after that passes, duplicate the working dashboard and change each copied data source's index to `aws_security_enterprise_demo`. Verify all panel counts against the enterprise manifest rather than the teaching expectations.
5. The finished enterprise implementation is in `dashboards/aws_enterprise_identity_investigation.json` and `spl/enterprise/`. Install all three fictional lookups before importing it. Expect three candidates and five matching actions. The demo priority rule remains visible.
6. The verified enterprise drilldown uses hidden account, principal ARN, source IP and candidate-window fields. It intersects the selected window with the global filter. The original account/username-only teaching drilldown should not be reused unchanged for enterprise data.

Initial ingestion gate (no extra `spath`: the configured source type already extracts JSON fields):

```spl
index=aws_security_enterprise_demo sourcetype=aws:cloudtrail:demo
| eval parsed_utc=strptime(replace(eventTime,"Z$","+0000"),"%Y-%m-%dT%H:%M:%S%z")
| eval time_difference_seconds=abs(_time-parsed_utc)
| stats count as events dc(eventID) as unique_events dc(recipientAccountId) as accounts dc(userIdentity.arn) as caller_principals count(parsed_utc) as parsed_timestamps max(time_difference_seconds) as maximum_time_difference_seconds
```

Expected: **50,000 events, 50,000 unique events, 20 accounts, 300 caller principals, 50,000 parsed timestamps, zero timestamp difference**. If counts exceed these, check for repeat imports or multiple runs before proceeding. No index deletions are needed.

Preserve the chart correction:

```spl
index=aws_security_enterprise_demo sourcetype=aws:cloudtrail:demo eventName=ConsoleLogin
| dedup eventID
| eval login_result='responseElements.ConsoleLogin'
| timechart span=1h fixedrange=false count by login_result
```

Choose a one-hour span to make the week-long overview readable; the investigation timeline still retains precise timestamps. Once a specific historical window is established, use that explicit window rather than routinely searching an unbounded production index.

## Context enrichment gate

Account enrichment keys on `account_id`. Identity enrichment keys on both `account_id` and `principal_arn`. Approved-change matching must include account, caller ARN, affected user, action, policy ARN when applicable, and the event timestamp within the approval interval. Key-creation rows legitimately have no policy ARN.

Merely looking up an administrator's username is not approval for all their activity. Context missing from the lookup should be shown as unknown. When verifying the approved lookalike, confirm the exact records and validity interval, then compare with alex's elevated changes, which have no matching approval.

## Sources for additional background-event schemas

- [AWS: read-only management events and ListBuckets](https://aws.amazon.com/blogs/compute/introducing-support-for-read-only-management-events-in-amazon-eventbridge/)
- [AWS: S3 CloudTrail event categories](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html)
- [AWS: CloudTrail event field interpretation](https://aws-samples.github.io/cloud-operations-best-practices/docs/recipes/AWS%20CloudTrail/CloudTrail%20Security/event-fields/)

These are schema references. This generator does not reproduce complete service response bodies or credential-bearing fields.
