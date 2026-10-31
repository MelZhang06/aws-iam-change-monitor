# Fifteen-minute teaching walkthrough

## Preparation

Start the local Splunk instance, open the enterprise dashboard and restore the fixture week or All time. Confirm the five cards read **50,000 / 20 / 300 / 195 / 3**. Begin with no row selected, or deliberately choose Alex before presenting and say that you have preselected the example. Test all three queue selections. Keep the synthetic-data statement visible.

## 0–2 minutes: discover the investigation problem

Ask: “When you investigate suspicious AWS access across accounts, how do you connect sign-in history, IAM changes and ownership? Which step takes the most time?”

Reflect the answer in plain language. For this fictional prospect, the assumed problem is the work of connecting related events, not the absence of CloudTrail logging. Ask what would count as a useful validation: finding the caller and affected identity, preserving evidence, reducing manual pivots, or finding missed cases.

## 2–4 minutes: establish scope and normal activity

“This is a reproducible synthetic dataset: 50,000 management events over a week, across 20 fictional accounts and 300 IAM principals. It includes ordinary read activity, office-hour sign-ins, automation and comparison cases. No real credentials or AWS permission changes were used.”

Show the cards and hourly chart. Explain quieter nights/weekends without claiming the simulation is a validated model of customer behavior. The 195 failures are observations; the three candidates require a more specific sequence. Volume makes the investigation setting more credible, but does not itself establish detection quality.

## 4–7 minutes: prioritize and select Alex

Explain the queue rule: at least five failures for the same account/principal/source in the preceding 15 minutes, a successful sign-in without MFA, then successful IAM changes within 15 minutes. High is an explicit demo rule requiring an AdministratorAccess attachment and cross-user access-key creation for the same affected user. It is not an ES risk score.

Select Alex in account 111122223333. “We have reduced the material to review to a few candidate sequences. This is not proof of compromise; it is a starting point with supporting evidence.”

## 7–10 minutes: inspect the nine events

Read the timeline: six failures at 13:00–13:05 AEDT on 26 October; success without MFA at 13:07; AdministratorAccess attachment at 13:13; key creation at 13:14. Alex is the caller. **svc-analytics is the affected identity**. Do not say Alex granted themselves administrator access.

Show the account and owner. Inspect the raw JSON/event ID for either change in the evidence panel (later rows are on page 2). `MFAUsed=No` describes this sign-in; it does not show that MFA was disabled. The policy attachment does not by itself establish every effective permission under SCPs, boundaries or other applicable controls.

Explain why the drilldown uses account + principal ARN + source + time. Usernames repeat across accounts. A shared IP or a nearby event alone is insufficient to attribute a person or authenticated session.

## 10–12 minutes: compare Pat-admin and Jordan

Select Pat-admin. Show the same suspicious pattern and the matching **DEMO-CHG-approved-lookalike** records for both changes. Approval includes a fictional MFA exception. It is displayed as evidence to verify, not used to suppress the finding automatically. Explain that the join checks action/policy/target keys and UTC time validity, not simply whether the caller is an administrator.

Select Jordan. Five failures, one no-MFA login and one cross-user key creation produce seven timeline events and one qualifying action. It is Review because it lacks the paired AdministratorAccess attachment required by the demo's High rule. Review does not mean safe.

## 12–15 minutes: discuss limits and agree on validation

“This first version deliberately models IAM users. Real enterprise role sessions and Identity Center need a separate attribution design. Production deployment also needs telemetry coverage, scheduled lookback, performance and alert-tuning validation.”

The demonstrable benefit is the workflow: queue → scoped timeline → ownership/change context → raw evidence. Do not claim a percentage improvement in MTTR or false positives without measuring it.

Propose a controlled evaluation using agreed representative cases and analysts. Measure time and manual pivots needed to identify actor/target/actions, expected-case coverage, false positives, and missing telemetry. Distinguish investigation time from the event sequence duration and ingestion latency.

## Questions to prepare for

**Why not just AWS-native tools?** CloudTrail Event History or Lake can investigate AWS activity. This demo shows a shared Splunk investigation workflow and CSV context enrichment. Combining additional telemetry and workflow integrations would be a separate customer-specific validation, not something this fixture proves.

**Why no roles yet?** Role sessions require resolving the session issuer, assumed-role session and possibly the originating human. Treating an ARN as a username would lose that distinction. A separate tested role scenario is the next extension.

**Will the search scale?** Only this 50,000-event fixture was tested. The current full-window sort and streamstats, plus an approval join applied after reduction to five actions, are deliberately transparent. Production scheduling, acceleration, limits and time boundaries need a measured design.

**Does a matching change make it benign?** No. Verify the approval's scope, authenticity and exception conditions with the owner. The queue retains it so the analyst can make that distinction.

**What did the workshop inspire?** Clear audience questions, useful visual summaries, common-field pivots and lookup enrichment. The enterprise version applies those ideas to identity investigation using original synthetic logs.

## Optional recording outline

Record your own 3–5 minute walkthrough: overview (30 sec), Alex's evidence (90 sec), Pat-admin comparison (45 sec), limits and validation proposal (45 sec). No recording is included in this repository. Screenshots are from the running local dashboard, not mockups.
