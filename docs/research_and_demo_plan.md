# AWS CloudTrail investigation demo: research and delivery plan

Research reviewed: 25 October 2026. **Historical design plan:** the current implementation and live verification are recorded in [completion_walkthrough.md](completion_walkthrough.md) and the README. Original three-account assumptions and pending-status statements below describe the initial planning stage, not the completed enterprise fixture.

## Positioning

**From suspicious sign-ins to an evidence-backed AWS investigation with Splunk.**

Build a 15-minute technical teaching demonstration and a reproducible public portfolio project. The audience is a fictional cloud/security team investigating activity across three AWS accounts. Its problem is the manual work of connecting authentication events to subsequent permission changes and identifying the affected identity.

The value hypothesis is that a shared investigation view can reduce the time and steps needed to answer who acted, what changed, and what to investigate next. Measure this in a controlled exercise; do not claim customer ROI or production detection accuracy.

Use Splunk Platform, SPL1, raw JSON field extraction, and Dashboard Studio for the core. Enterprise Security, SOAR, Security Lake, and federated search are optional discussion topics with separate dependencies.

## Research and how it informs the design

These are official detection references and vendor-authored investigation examples, not evidence that a named customer achieved a particular outcome.

| Source | Relevant finding | Design implication |
| --- | --- | --- |
| [Splunk AWS detection catalog](https://research.splunk.com/detections/platforms/aws/) | Includes several AWS telemetry types and both native CloudTrail and ASL content. | Choose CloudTrail-specific references and inspect prerequisites individually. |
| [High number of failed authentications from IP](https://research.splunk.com/cloud/f75b7f1a-b8eb-4975-a214-ff3e0a944757/) | Published prose describes 20 or more failures in five minutes, while the displayed SPL uses ten-minute buckets and `>20`. | Keep a clearly labeled educational threshold of at least five failures per fixed 15-minute bucket. Document that this is an adaptation, not the published rule. |
| [Unusual number of failed authentications from IP](https://research.splunk.com/cloud/0b5c9c2b-e2cb-4831-b4f1-af125ceb1386/) | Uses statistical comparison and a minimum activity condition. | Defer anomaly detection: the small starter dataset is better suited to transparent thresholds. |
| [Successful single-factor authentication](https://research.splunk.com/cloud/a520b1fe-cc9e-4f56-b762-18354594c52f/) | Examines successful console access with `MFAUsed=No`; supplied SPL uses macros and normalized fields. | Extract raw `responseElements.ConsoleLogin` and `additionalEventData.MFAUsed`; describe the observation as MFA not used for this sign-in. |
| [CreateAccessKey](https://research.splunk.com/cloud/2a9b80d3-6340-4345-11ad-212bf3d0d111/) | Current hunting logic focuses on successful key creation by one named IAM user for another. It does not evaluate target permissions. | Add a synthetic cross-user key creation event after the policy attachment. Separate caller from target, and investigate permission context independently. |
| [Stop logging CloudTrail](https://research.splunk.com/cloud/8a2f3ca2-4eb5-4389-a549-14063882e537/) | A defense-evasion reference with specific success and user-agent filters. | Reserve for an optional second scenario. A denied attempt must not be labeled logging disabled. |
| [Lantern: detecting privilege escalation](https://lantern.splunk.com/Security_Use_Cases/Anomaly_Detection/Detecting_privilege_escalation_in_your_AWS_environment) | Describes CloudTrail investigation patterns and distinguishes the ES deployment from using the concepts with platform SPL. | Make the core runnable without ES and document the production expansion separately. |
| [Lantern: investigating cloud identity takeover](https://lantern.splunk.com/Security_Use_Cases/Threat_Hunting/Investigating_security_incidents_across_Amazon_S3_and_Snowflake_with_federated_search/Investigating_a_cloud_identity_takeover_with_federated_search_across_Amazon_S3_and_Snowflake) | Demonstrates moving from an unusual login into IAM API history and then identity context, including allowed and denied actions. | Organize panels around investigation questions. Use a local fictional ownership lookup in the MVP; keep federation out of the core setup. |
| [Splunk .conf24 PLA1261B, slide 17](https://conf.splunk.com/files/2024/slides/PLA1261B.pdf) | A vendor demo starts with IAM login failures and investigates across indexed and historical cloud data. | Use the login spike as an entry point; discuss retention and historical investigation as architecture tradeoffs. This older deck is not a current feature guarantee. |
| [AWS CloudTrail investigation guide, Part 1](https://aws.amazon.com/blogs/security/incident-response-guide-for-aws-cloudtrail-investigations-part-1/) | AWS describes cross-account and stolen-console-credential investigations, emphasizing identity/session context. | Explain the limits of IP/time correlation and what evidence would support a stronger attribution. This is an AWS investigation source, not a Splunk customer case study. |

Additional schema references: [AWS console sign-in events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-aws-console-sign-in-events.html), [CloudTrail data events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html), and [IAM Identity Center investigation fields](https://docs.aws.amazon.com/singlesignon/latest/userguide/sso-cloudtrail-use-cases.html).

## Core story and evidence

Retain the starter's eight-event sequence: six failed logins associated with alex, one successful sign-in with `MFAUsed=No`, and alex attaching `AdministratorAccess` to `svc-analytics` thirteen minutes after the first failure. Add one synthetic successful `CreateAccessKey` call by alex for `svc-analytics` at minute fourteen. Never create real credentials or permissions for this story.

The presenter investigates three questions:

1. Why does this sign-in activity deserve attention?
2. What permission or access changes followed, and who was affected?
3. What evidence and business context are needed before deciding on a response?

Keep evidence and interpretation separate:

- A failure burst is suspicious activity, not proof that passwords were guessed successfully. One user's repeated failures do not establish password spraying.
- `MFAUsed=No` describes this sign-in; it does not prove an MFA device was disabled.
- Alex is the caller; `svc-analytics` is the permission/key target. Do not say alex granted themselves administrator privileges.
- A policy attachment is evidence of a permission change. Effective access also depends on other policy controls; do not infer every action is now permitted.
- Same account, identity, IP, and nearby timestamps support an investigative relationship. They do not uniquely identify a person or prove the same authenticated session.
- Failed-login usernames may be masked. Use an account/IP pivot when principal identity is missing and label the weaker attribution.
- An IAM-user scenario is deliberately narrow. Role sessions and Identity Center require different identity handling; do not claim full AWS identity coverage.

## Dataset design

Keep a small, explainable dataset rather than adding many attack techniques. Add realistic normal API activity across all three fictional accounts, plus two controls: an approved cross-user administration action and an isolated failed-login burst with no sensitive follow-on actions. These provide meaningful false-positive discussions.

Use correct event sources per service, explicit errors for denied calls, `principalId`, and `userAgent` where appropriate. Add an optional masked-username fixture and a denied IAM call. The existing generator currently assigns every non-login event to IAM; extend that before adding STS, EC2, or CloudTrail service events.

Store a fictional account/identity ownership lookup with environment, owner, and expected administrative activity. A matching approved-change record adds context, not automatic proof of safety. Keep labels and expected outcomes in a separate scenario manifest so detections do not depend on a hidden malicious flag or hardcoded username.

Provide both a fixed UTC anchor for reproducible examples and a relative-to-now mode for live presentations. Make event IDs deterministic for the same seed and anchor. Keep synthetic fixtures publishable while private AWS exports remain ignored. Do not put secrets or usable credentials into fixtures.

## Dashboard and investigation flow

One overview with a linked investigation section is enough. Use a persistent synthetic-data label and filters for time, account, principal, and source IP. Use actual screenshots after validation rather than presenting mockups as a working integration.

| View | Question answered | Required evidence |
| --- | --- | --- |
| Authentication trend and failure bursts | What changed, and where should I start? | Success/failure counts; account/IP grouping; stated threshold/window. |
| Successful sign-ins without MFA | Which sign-ins need closer review? | Raw result, MFA value, principal, account, IP, and timestamp. |
| Sensitive IAM changes | Who acted on whom? | Caller, target, policy ARN, action outcome, account, source IP, event ID. |
| Selected investigation timeline | What happened before and after? | Chronological events with errors and raw-event drilldown; no fixed alex filter. |
| Identity/account context | Is this activity expected for this identity? | Fictional ownership and approved-change context, with source clearly labeled. |

Add correlation only after these searches work: failures before a successful no-MFA sign-in, followed by sensitive IAM activity within an explicitly defined interval. Require account/principal consistency where identity is known; use source IP as supporting context. Test ordering, duplicate event IDs, missing fields, and interval boundaries. A fixed `bin` bucket is not a sliding window: add a test crossing a quarter-hour boundary and document the difference.

Do not use geolocation maps with documentation-only IP addresses. Defer S3 exfiltration: object-level `GetObject` activity is a data event, and trails/event data stores do not log data events by default; AWS documents additional charges. Absence of those records cannot establish that no data was accessed.

## Fifteen-minute teaching script

| Time | Presenter action | Customer-value connection |
| --- | --- | --- |
| 0–2 min | Ask how the team investigates cross-account IAM activity and which step takes longest. Confirm the assumed pain. | Tailor the demonstration to investigation effort. |
| 2–3 min | Show the synthetic-file architecture and optional live ingestion path. Explain scope and provenance. | Establish feasibility and clear dependencies. |
| 3–5 min | Start at a failure burst and inspect the underlying events. | Prioritize activity needing review. |
| 5–8 min | Pivot to the successful no-MFA sign-in and subsequent policy/key changes. | Connect authentication to possible access expansion. |
| 8–11 min | Show caller versus target, chronological evidence, and fictional ownership/change context. | Scope the affected identity and assess whether activity was expected. |
| 11–13 min | Compare a benign control. Explain attribution, MFA, policy, and data coverage limits. | Demonstrate tuning judgment and avoid overstating certainty. |
| 13–15 min | Propose a customer-controlled validation and ask what evidence would meet their decision criteria. | Agree on a measurable next step. |

Suggested opening: “You mentioned that connecting sign-ins to IAM changes takes several manual searches. I will show how an analyst can follow that evidence in one investigation view.”

Suggested close: “For a technical validation, we could agree on representative cases and measure time to identify the actor, affected identity, and relevant changes, while tracking false positives and missing telemetry.”

Compare manual searches and the dashboard on the same dataset and task. Record measured task duration and steps, with the limitations of a rehearsed synthetic exercise. Keep scenario duration, event timestamps, ingestion latency, and analyst investigation time as separate metrics.

## GitHub delivery and acceptance criteria

1. **Foundation:** generator CLI, timestamp/JSONL checker, deterministic fixtures, scenario manifest, stronger tests, and CI using the standard library test suite. Include tests for chronology, MFA value, target identity, service source, errors, account isolation, masked identities, threshold boundaries, and duplicate IDs.
2. **Searches:** document each SPL query's purpose, inputs, expected result, false positives, and adaptation from cited research. Verify extraction and timestamps in a real Splunk instance. Add account identity to failure aggregation. Do not assume uploaded JSON creates every add-on alias or macro.
3. **Dashboard:** export a working Dashboard Studio JSON definition from the selected Splunk version. Validate imports, empty states, tokens, time/account filters, drilldowns, and expected result counts. Record the exact tested Splunk and add-on versions and execution date.
4. **Presentation:** add an architecture diagram, complete presenter script, short sample investigation report, and discussion questions. Explain why Splunk helps with shared investigations and additional context while acknowledging AWS-native investigation options.
5. **Portfolio:** README quickstart, actual dashboard screenshot, short recorded walkthrough, sample results, source attribution, dependency notes, and a clear matrix of locally tested versus Splunk-validated versus future work. Choose a license for original work and check licenses before copying upstream content or datasets. Publish synthetic evidence only.

Release acceptance: a fresh reader can generate/check data, ingest it with documented parsing, import the dashboard, reproduce documented findings, and follow the same investigation. Include a safe repeat-run procedure so re-uploading data does not silently inflate findings. Run local tests in CI; describe separate manual Splunk verification honestly.

Optional later work: a separate denied `StopLogging` scenario; assumed-role/Identity Center investigations; live ingestion architecture and cost controls; ES correlation/risk workflows; historical federated searches. Each should have its own telemetry, permissions, and product prerequisites.

Current validation status: the starter's three local tests passed during the initial review. No Splunk searches, dashboard, AWS export, or live ingestion integration have been executed as part of this research. No expanded scenario has been implemented yet.
