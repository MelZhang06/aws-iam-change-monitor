# Reproduce the enterprise investigation demo

Tested locally on Splunk Enterprise **10.6.1.1 (b2ae2962645c)** on macOS ARM and Python **3.12.15**, 28 October 2026. No AWS add-on, Enterprise Security, cloud account or real credentials are needed. Other Splunk versions and Splunk Cloud have not been tested.

## 1. Generate and check

Use Python 3.10 or later. On a Mac with multiple Python versions, check `python3 --version` or use `python3.12` explicitly. From the project root:

```sh
python3.12 scripts/generate_enterprise.py --anchor 2026-10-28T00:00:00Z --force
python3.12 scripts/check_data.py data/enterprise_cloudtrail.jsonl --profile enterprise --manifest data/enterprise_cloudtrail.manifest.json
python3.12 scripts/verify_enterprise.py data/enterprise_cloudtrail.jsonl
python3.12 scripts/build_enterprise_dashboard.py
python3.12 -m unittest discover -s tests -v
```

`--force` replaces the enterprise JSONL and its associated generated CSV/manifest files. It does not change Splunk data. The dashboard builder writes the portable definition, seven enterprise searches and three fictional lookup files. Regenerate all of these together if the anchor changes. The 88-event teaching generator is separate.

Expected: 50,000 events, 20 accounts, 300 principals, three candidates, five qualifying actions. The complete fixture has 195 failed console sign-ins; only a subset belongs to qualifying sequences. Expected outcomes are evaluated from evidence, not hidden labels in the events.

## 2. Create the index and source type

In Splunk Web, **Settings → Indexes → New Index**, create an events index named `aws_security_enterprise_demo`.

Use **Settings → Add Data → Upload** for `data/enterprise_cloudtrail.jsonl`. Configure a source type named `aws:cloudtrail:demo`, one JSON object per line, UTC timestamps from `eventTime`. The source type used in the verified instance has:

```ini
[aws:cloudtrail:demo]
INDEXED_EXTRACTIONS = json
KV_MODE = none
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TIMESTAMP_FIELDS = eventTime
TIME_FORMAT = %Y-%m-%dT%H:%M:%SZ
TZ = UTC
```

These are configuration values for a controlled demo, not instructions to overwrite shared system configuration. Reuse the existing source type if it is already configured. Choose host `synthetic-enterprise-demo` and index `aws_security_enterprise_demo`. Submit **once**. Upload only the JSONL as event data; keep manifests and context CSVs separate.

In Search & Reporting, choose **All time** and run the ingestion gate in [enterprise_simulation.md](enterprise_simulation.md). Require 50,000 raw events, 50,000 unique IDs, 20 accounts, 300 caller ARNs, 50,000 parsed timestamps and zero `_time` difference. Do not add redundant `spath` to searches when this source type already extracts JSON.

## 3. Install the fictional lookup files

In **Settings → Lookups → Lookup table files → Add new**, upload these into the **search** app, keeping the exact destination filenames:

- `lookups/enterprise_accounts.csv`
- `lookups/enterprise_identities.csv`
- `lookups/enterprise_approved_changes.csv`

The searches reference CSV filenames directly, so named lookup definitions and automatic lookups are unnecessary. Keep access limited to the intended demo audience. Filesystem installation is an alternative for a local Enterprise administrator; it was used in the verified Mac instance after explicit approval, without overwriting files:

```sh
cp -n lookups/enterprise_accounts.csv lookups/enterprise_identities.csv lookups/enterprise_approved_changes.csv /Applications/Splunk/etc/apps/search/lookups/
```

This path is specific to the verified Mac installation. It is not a Splunk Cloud installation procedure. Verify availability in Search & Reporting with `| inputlookup enterprise_accounts.csv` (20 rows), `| inputlookup enterprise_identities.csv` (300) and `| inputlookup enterprise_approved_changes.csv` (42).

## 4. Import the dashboard

1. In Search & Reporting, open **Dashboards → Create New Dashboard**.
2. Title it **AWS Enterprise Identity Investigation**, choose **Dashboard Studio**, **Grid** and private permissions for the demo.
3. Enter Edit mode and use the top-toolbar **Source code** button.
4. Replace the definition with `dashboards/aws_enterprise_identity_investigation.json`.
5. Click **Apply**, **Save**, then reload the dashboard. Reloading removes the editor's old in-memory time selection.

The saved default is the fixed fixture's UTC week, **21 Oct 00:00 through 28 Oct 00:00**, displayed as **21 Oct 11:00 through 28 Oct 11:00 AEDT**. Existing `form.global_time.*` URL parameters override defaults; remove stale query parameters or explicitly choose the desired range. **All time** also works for this isolated fixture.

Expected summary: **50,000 / 20 / 300 / 195 / 3**. The cards mean events, accounts, principals, failed sign-ins and candidates. The timeline chart uses one-hour buckets and `fixedrange=false`; the global picker actually controls every index search.

## 5. Verify interactions

| Queue row | Timeline events | Qualifying actions | Change context |
| --- | ---: | ---: | --- |
| alex, 111122223333 | 9 | 2 | No matching approval |
| pat-admin, 777788889999 | 9 | 2 | DEMO-CHG-approved-lookalike matches both actions |
| jordan, 900000000001 | 7 | 1 | No matching approval |

Select a **queue row**, not an arbitrary repeated username in another panel. The queue passes hidden account, principal ARN, source IP and start/end epoch fields as tokens. Detail SPL uses string-escaped tokens and intersects the candidate's 30-minute window with the global filter. Raw JSON and event IDs remain available in a separate paginated evidence panel.

Before a selection, the dashboard prompts **Choose a queue row** and hides empty details. Changing to **Last 24 hours** on the validation date excluded all three cases: the candidate card became zero and older detail panels disappeared. The exact recent-window event count changes with wall-clock time. Restore the fixture week or All time before presenting.

## Repeat runs and troubleshooting

- More than 50,000 raw events but exactly 50,000 IDs usually indicates repeated ingestion. Deduplication protects finding counts but does not reclaim storage. Do not delete a shared index to reset a demo.
- A narrow range may cut off the failures needed to qualify a sequence. No result is not evidence that an identity is safe.
- Blank details before selection are intentional. After selection, check global time, lookup app context and source-type field extraction before editing SPL.
- If every chart ignores the picker, inspect per-source `queryParameters` for an overriding `earliest` or `latest`. `fixedrange=false` only controls timechart's axis; it does not repair a search-time override.
- A missing approval is shown as unknown authorisation, not a confirmed unauthorised act. The approved comparison remains in the queue.

For production, replace full-window sorting/streamstats and the bounded approval join with a designed scheduling, summary/acceleration and change-context strategy. The live checks cover this 50,000-event fixture, not production throughput or every timestamp boundary. No performance SLA is claimed.
