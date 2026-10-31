# What was completed and how it was verified

Work completed locally on 28 October 2026 for portfolio and teaching use. Publication remains with the project owner. This document records the actual implementation and its limits, rather than a proposed future dashboard.

## 1. Preserve the starting point

The 88-event teaching dataset and its dashboard were kept separate from the larger simulation. The enterprise dataset uses `aws_security_enterprise_demo`, the existing custom JSON source type `aws:cloudtrail:demo`, and a dedicated Dashboard Studio dashboard. No re-import or deletion of event data was performed during the dashboard work.

The user's original one-chart enterprise dashboard definition was copied from Studio and saved in `docs/backups/enterprise_dashboard_before.json` before replacing it. The original teaching searches remain in `spl/`; enterprise searches are in `spl/enterprise/`.

## 2. Independently verify the uploaded data in Splunk

A read-only live search verified:

| Check | Actual result |
| --- | ---: |
| Indexed events | 50,000 |
| Unique event IDs | 50,000 |
| AWS accounts | 20 |
| Caller principal ARNs | 300 |
| Parsed event timestamps | 50,000 |
| Maximum `_time` versus UTC `eventTime` difference | 0.000000 seconds |

This checks ingestion rather than assuming a successful upload proves timestamp parsing. The fixed UTC event range is 21 Oct 2026 00:00:11 through 27 Oct 23:59:47. Melbourne displays 21 Oct 11:00:11 through 28 Oct 10:59:47 AEDT.

## 3. Execute the detection before building dependent panels

The live sequence search produced **five action findings**, grouped into **three queue candidates**. These agree with the independently evaluated fixture. MFA-protected, denied-change and isolated-failure controls do not enter this particular queue.

| Caller / account | Demo priority | Actions | Scoped timeline | Context |
| --- | --- | ---: | ---: | --- |
| alex / 111122223333 | High | 2 | 9 | No matching approval |
| pat-admin / 777788889999 | High | 2 | 9 | Both actions match the approved exercise |
| jordan / 900000000001 | Review | 1 | 7 | No matching approval |

The detector uses observed events and explicit conditions, not scenario names, a malicious flag, a known username or an IP blacklist. High is an educational rule, not a production risk score. Account criticality is shown as context and is not silently included in priority.

## 4. Add context that answers an investigation question

Three generated fictional CSVs supply 20 account records, 300 identity records and 42 action-specific change records. They were copied to the local Search app lookup folder after explicit approval. No existing lookup file was overwritten, no permissions were broadened and no restart was needed.

Account enrichment uses account ID. Identity enrichment uses account ID and principal ARN. Approval matching uses account, caller ARN, affected user, API action, policy ARN when relevant, and UTC validity bounds. Missing policy values on key creation are normalised consistently for matching.

More than one change record can have the same action keys at different times. The query considers all matching records, checks each interval, then reduces back to one row per event ID before counting actions. This preserves five qualifying actions even when an intermediate join has six rows. Pat-admin's ordinary maintenance outside the selected interval cannot approve the exercise accidentally.

The join is applied only after sequence reduction. This is a transparent bounded demo design, not a claim that joins or full-window streamstats are suitable for arbitrary production volume.

## 5. Build the working dashboard

The dashboard contains five summary cards, an hourly success/failure chart, the three-candidate queue, an explicit selection prompt, account/ownership context, a chronological timeline, per-action change context and paginated raw JSON with event IDs.

The summary cards read **50,000 events, 20 accounts, 300 IAM principals, 195 failed sign-ins and three candidates** for the complete fixture. Four cards reuse one transforming overview search through `ds.chain`; the candidate count reuses the queue. No severity is inferred from chart colour. The final saved Studio export was compared structurally with the generated JSON and matched exactly: 14 visualizations and 12 data sources.

The default is an absolute fixture week so the GitHub example will still work after the events age out of Last 24 hours. The chart uses one-hour buckets for readability and `fixedrange=false` to avoid forced empty buckets outside the event range.

Queue clicks pass account, principal ARN, source IP and candidate time bounds through hidden fields. Names repeat across accounts, so a username-only drilldown would be insufficient. All token strings in detail SPL use the Splunk string-escaping filter. The detail view is limited to the candidate's 30-minute interval and the global time filter.

Long event IDs were moved out of the timeline display into the raw-evidence panel to keep the investigation chronology readable. The evidence remains accessible and exportable.

## 6. Problems, root causes and resolutions

| Problem | Root cause established | Resolution and verification |
| --- | --- | --- |
| Picker showed Last 24 hours while the original chart displayed a week | Per-source `queryParameters.earliest="0"` overrode the global earliest token | Removed the override; all index searches inherit global bounds. Last 24 hours yielded 3,556 events, zero candidates and no older detail tables during the live test. |
| Empty chart padding seen in the earlier teaching stage | `timechart` can extend buckets to the effective selected search window | Retained `fixedrange=false`. This is distinct from a data source ignoring the picker; the two issues require different fixes. |
| Editor still displayed the previous range immediately after changing defaults | Editing a default did not reset existing in-memory token state | Saved and reloaded. The fixed-week default then produced the expected full-fixture metrics. URL `form.*` parameters can also override defaults. |
| Initial detail panels displayed unset-token errors | Click-dependent tokens had no default values | Added nonmatching sentinel defaults and hid empty detail panels. Initial view now displays a selection prompt without those errors. |
| Selected evidence could survive a change to an unrelated global time window | The first draft's detail sources used their own candidate-range query parameters | Removed those overrides and intersected candidate filters with inherited global bounds. The live restricted-window test hid Jordan's older evidence. |
| Local CSV upload could not complete through the Chrome extension | Extension lacked file-URL access | Did not enable broader extension access. Used an explicitly approved copy of only the three generated CSVs into the local Splunk lookup folder. Live searches verified enrichment. |
| Some browser actions reported a timeout even though Studio changed view | The UI transitioned before the interaction response completed | Read the new visible state before acting again; did not repeat mutations blindly. Saved-state confirmation and result tables were the verification signals. |
| Source-code button locator became ambiguous | Studio exposed both the main toolbar button and a sidebar section with that name | Targeted the observed toolbar `data-test="source-button"`; verified that the full-dashboard editor opened. |
| Event IDs made timeline rows harder to scan | UUIDs wrapped across lines alongside investigative fields | Kept IDs in the raw-evidence panel and enlarged the timeline. Readable labels distinguish caller, affected user, action, outcome and MFA. |
| One ad-hoc artifact-check harness could not import the builder's sibling module | `runpy.run_path` does not add the script directory to the import path as direct CLI execution does | Corrected the harness import path. Direct documented CLI execution, regeneration consistency and all 36 tests passed. No product behavior change was needed. |

The earlier redundant `spath` issue is also documented in `validation.md`: JSON fields were already extracted by the configured source type, so adding a generic extraction created duplicate values. Enterprise searches reuse the verified extraction rather than repeating it.

## 7. Verification and delivery

Local tests: **36 passed on Python 3.12.15**. Five new artifact regressions guard against time overrides, incomplete drilldown identity, unsafe initial selection, broken chained-source references and incomplete approval matching. They do not pretend to execute SPL or render Studio.

Live Splunk checks covered ingestion/timestamp consistency, the full-fixture summary, the three candidate rows, all three drilldowns, both approved actions, raw evidence access, initial state and the global time filter. Actual screenshot and visible-result extracts are in `docs/screenshots/` and `docs/examples/`.

Final consistency checks passed: the 11 generated dashboard/search/lookup artifacts rebuild without content drift; the saved Studio export matches the portable definition; all three deployed lookup CSVs match the repository copies; local Markdown links resolve; both the 88-event and 50,000-event fixtures pass their manifest/schema validators. License selection remains with the project owner; no license file was added without their choice.

Portable output includes the Studio JSON, seven enterprise SPL files, three fictional CSVs, a deterministic builder, setup guide, presenter walkthrough, sample investigation and this work log. The existing GitHub Actions workflow now builds the enterprise dashboard and checks for generated-file drift after the data checks. GitHub Actions itself has not run because this project has not been published by the agent.

## What remains outside the completed demo

No GitHub repository was created or published. No real AWS connection, IAM changes, key creation, SOAR action or email/message was performed. The project owner will publish and record their own narration. The repository does not include a video recording.

Role sessions, IAM Identity Center, live ingestion, real customer telemetry, production SIEM coverage, scheduling/lookback design, performance certification and exhaustive live SPL boundary tests remain separate work. Missing candidates do not establish safety. Do not present this fixture as an official Splunk detection pack or claim measured MTTR improvement.

## Documentation consulted for implementation

- [Dashboard Studio: setting tokens on a visualization click](https://help.splunk.com/en/splunk-enterprise/create-dashboards-and-reports/dashboard-studio/9.0/add-dashboard-interactions/setting-tokens-on-a-visualization-click)
- [Dashboard Studio: tables and hidden internal fields](https://help.splunk.com/en/splunk-enterprise/create-dashboards-and-reports/dashboard-studio/10.2/visualizations/table)
- [Dashboard Studio: visibility conditions and chained data-source examples](https://help.splunk.com/en/splunk-enterprise/create-dashboards-and-reports/dashboard-studio/10.2/make-dashboards-dynamic-and-interactive/specify-visibility-conditions-for-panels-and-other-dashboard-elements)

The JSON was subsequently applied and saved in the actual 10.6.1.1 instance; documentation examples alone were not treated as runtime proof.
