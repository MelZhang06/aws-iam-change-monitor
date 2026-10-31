# Historical Design Review — High-Risk Policy and Access-Key Changes to a Production Service Identity

Original proposal date: 28 October 2026. This document records the design before implementation. Statements about unimplemented capabilities describe that review stage, not the current repository. The current app, actual results, and operating instructions are documented in the [completion record](change_monitor_completion.md) and [operating guide](change_monitor_v2.md).

This is a fictional enterprise scenario grounded in documented AWS mechanisms. It is not a reconstruction of a customer incident and makes no claim about how frequently this exact event sequence occurs. The first section provides a narrative; the appendix addresses questions about authorization, identity, evidence, and false positives.

## Scenario overview

### Business problem

Security and cloud-platform teams need to establish why a high-risk policy was attached to a production service identity, which AWS identity performed the action, whether a newly created access key was within approved maintenance scope, and which questions remain unanswered.

This investigation direction is consistent with AWS guidance on suspicious credentials and IAM changes, which includes reviewing permission/policy modifications and new access keys. That supports the investigation approach; it does not establish this story as an actual customer case. [AWS CloudTrail investigation guide](https://aws.amazon.com/blogs/security/incident-response-guide-for-aws-cloudtrail-investigations-part-1/)

### Operating model and investigation trigger

**The primary scenario is proactive detection followed by human verification.** It does not assume data exfiltration has already happened or require an analyst to watch a dashboard continuously.

The proposed enterprise path is: AWS API activity → CloudTrail management-log delivery → continuous Splunk ingestion → a match from an enabled scheduled detector → a Triggered Alert and notification through a configured channel → an event-scoped investigation → human verification and a response decision.

The explicit trigger is a **successful `AttachUserPolicy` whose `policyArn` matches a configured high-risk policy, AdministratorAccess in this example, and whose target maps to a production service identity**. A missing production mapping should produce a result requiring more context, rather than silently treating the event as normal. The initial notification must not wait for key creation or complete change records.

An initial alert should say that a production service identity received a high-risk policy and requires review. It should include the account, target, caller role/session, policy ARN, event time, event ID, and evidence link. It must not claim confirmed exfiltration or attacker privilege escalation. Later key events or change records can add investigation context. Automatically updating a persistent case requires a separate implementation; dashboard queries alone do not provide it.

The demo can initially use native Splunk Triggered Alerts as its visible entry point. Proving external notification delivery requires separately configuring and testing that channel. Email, Slack, ServiceNow, ES notables, and SOAR cannot be listed as implemented integrations unless they are actually connected and tested. An alert record is not a complete case-management system with assignment, response, and audit history.

A five-minute schedule was an example parameter in the proposal, **not a guarantee of an alert within five minutes of an event**. CloudTrail log delivery to S3 typically takes about five minutes without that time guarantee; ingestion and scheduling add further delay. Lookbacks, late-event handling, cross-run deduplication, and failure monitoring must be tested during implementation. The implemented local app uses a one-minute schedule, as described in the operating guide. [CloudTrail log delivery](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/get-and-view-cloudtrail-log-files.html), [Splunk scheduled alerts](https://help.splunk.com/en/splunk-enterprise/alert-and-respond/alerting-manual/9.0/create-alerts/create-scheduled-alerts)

**At the time of this proposal, the earlier demo had static uploaded data, manual searches, and an investigation dashboard, but no verified scheduled detection/notification workflow or continuous AWS ingestion.** A new version needed a verifiable automatic match → alert entry point → human review path before it could be described as proactive monitoring. Synthetic incremental replay must remain explicitly labeled as simulated ingestion, not real-time AWS collection.

### Enterprise and system assumptions — explicitly fictional

An enterprise has multiple AWS member accounts and an established path for centralizing CloudTrail management events in Splunk. Employees use federation and temporary role credentials. An external reporting tool awaiting replacement cannot use temporary role credentials, so production retains the IAM service user `svc-report-export`. The user has no console-login configuration and normally only reads specified reporting data.

Long-term credentials are a documented legacy exception with an owner and migration plan, not the recommended architecture for a new system. AWS favors temporary credentials for people and workloads while documenting exceptions for workloads that cannot support roles and some third-party clients. [AWS IAM best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)

Cloud-platform maintainers use a `LegacyIdentityMaintainer` role inside the member account. It already has authority to manage designated legacy service users, but its policy-attachment authorization is too broad and does not sufficiently restrict attachable policies. This is a preventive-control gap to investigate and correct, not authority invented for an attacker.

### What the analyst sees first

A scheduled rule raises an alert that AWS-managed AdministratorAccess was successfully attached to a production service user. The analyst enters review from that alert. **Previous sign-in failures, MFAUsed=No, and concurrent key creation are not required.** The dashboard provides investigation; the scheduled search and trigger conditions provide discovery.

The proposed timeline below uses illustrative UTC times, not timestamps from the later validation run:

| Time | Proposed CloudTrail fact | Supported conclusion |
| --- | --- | --- |
| 10:00 | A temporary LegacyIdentityMaintainer session calls ListAccessKeys for svc-report-export | The session queried the target's keys; a configuration snapshot is needed to establish the pre-existing key count |
| 10:03 | The same temporary credential successfully calls AttachUserPolicy for that user with AdministratorAccess | A high-risk managed policy was attached; this alone does not establish that the caller personally escalated privileges or obtained every effective permission |
| 10:05 | The same temporary credential successfully calls CreateAccessKey for the target | A key was created for that user; use or leakage of the key is not established |

The caller role, target user, and policy are three distinct objects. All target IAM changes take place inside the role's member account. An investigation spanning accounts does not mean a role can bypass AssumeRole and directly modify an IAM user in another account.

### Why investigate when a change record exists?

A maintenance change authorizes the specified role, target, and time window for creating a replacement key and deactivating the old key after application cutover validation. **It does not authorize AdministratorAccess or a change to the user's permission scope.**

Show two action-level conclusions:

- `CreateAccessKey`: action, target, account, caller role, and time match the recorded maintenance scope; review of the overall activity is still required.
- `AttachUserPolicy`: outside that record's approved scope; verify with the system owner.

Finding a change record does not automatically clear the activity. Failing to find a match does not automatically establish an attack. The source, status, version, and coverage of the change record also need reliable evidence.

### Normal control and investigation output

Use a separate approved key rotation as the normal control: create a replacement key, validate cutover in the external system, deactivate the old key, and remove it under the maintenance process. No high-risk policy is attached. Key creation remains searchable audit evidence; its existence alone does not make the activity an intrusion. The implemented fixture does not include external application cutover proof.

The analyst's output identifies the account and service identity, caller role/session, confirmed API actions, action-specific approval matches, unresolved attribution and usage, and questions for the owner. The initial conclusion is: **a production identity received a high-risk policy; the associated maintenance approval covers only some actions, so change scope needs verification**.

Human review can close an authorized change that meets controls, escalate a confirmed out-of-scope action for remediation, or retain a case pending evidence. Even an approved change may expose an excessive-permission control problem. A technical rule match, a business need to act, and a confirmed security incident are separate judgments.

Do not decide in advance that the cause is credential theft, employee malice, or operational error. Any later owner confirmation or attack evidence must be supplied as a visible evidence source, not added through narration.

### Suggested demonstration opening

> Our customer needs to review permission changes across multiple AWS accounts. A maintenance approval allows a reporting service's key to be rotated, but during that workflow AdministratorAccess is also attached to the service identity. I will show how a high-risk change initiates an investigation, how we identify the caller session and affected identity, and how we compare each action with approved scope while preserving original evidence. We distinguish confirmed operations from questions that still need verification.

## Technical review appendix

### 1. Why could AWS authorize these calls?

Provide time-scoped configuration evidence for the fictional environment rather than saying only that the caller is an administrator:

| Object | Required fictional assumption | Handling when the assumption is missing |
| --- | --- | --- |
| Caller role | Existing policy permits iam:AttachUserPolicy, iam:CreateAccessKey, and required query/rotation actions on designated service users | Do not generate unexplained successful calls; check the caller policy against the request |
| Attachable-policy scope | Legacy delegation does not sufficiently restrict policy ARNs, technically allowing AdministratorAccess attachment | If effective authorization permits only a read-only policy, generate a rejected attempt instead |
| Restrictions at call time | No applicable explicit deny blocks the call; caller boundaries, session policies, and applicable SCPs allow the particular actions | Preserve a rejection result and do not describe target permissions as changed |
| Target IAM user | Already exists, has a limited reporting baseline, and has a documented exception, purpose, and owner | Without historical baseline evidence, confirm the attachment without asserting a complete read-only-to-admin permission transition |
| Key quota | The target has only one total access key before creation | If it already has two, explain prior cleanup or generate a quota failure |

AttachUserPolicy operates on a specified user and managed policy. CreateAccessKey creates a key for the specified user; a new key defaults to Active. An IAM user can have at most two access keys. [AttachUserPolicy API](https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachUserPolicy.html), [CreateAccessKey API](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateAccessKey.html), [Access-key quota and management](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html)

Policy conditions can restrict attachable policy ARNs. Insufficient restrictions on legacy delegation are therefore a specific, reviewable control gap, not a general failure of AWS authorization checks. [AWS policy access control](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_controlling.html)

Separate caller authorization from target effective permissions. **A target user's permissions boundary can constrain the effective permissions after attachment; it does not automatically deny another caller's AttachUserPolicy request.** A successful AdministratorAccess attachment does not bypass all SCPs, boundaries, or explicit denies. [AWS permissions boundaries](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)

The demo does not need to deploy a real overprivileged role or create a real key. Synthetic events and configuration snapshots express the assumptions. Claiming that AWS authorization semantics were tested would require a separately authorized, isolated AWS validation; this project does not make that claim.

### 2. Why include a role, and how is complexity controlled?

The earlier version modeled employees as IAM users and centered the story on failed logins, which did not naturally represent enterprise federation and MFA. The redesign adds one necessary distinction: **the caller is an AssumedRole session, and the affected object is a legacy IAM service user**. The initial version does not add role chaining, full Identity Center correlation, or every enterprise identity pattern.

CloudTrail records role sessions and their issuers. Properly configured sourceIdentity can help attribution, but a session name alone is not an independently verified employee identity. [CloudTrail identity fields](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html), [AWS source identity](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_monitor.html)

Retain the recipient account, complete role/session ARN, session issuer ARN, principalId, temporary accessKeyId when present, event ID, UTC time, and sourceIdentity when present. Linking activity to the same temporary credential does not prove that the same person performed it; another person could use the credential.

A repeated session name or shared IP is insufficient by itself to identify the same session. When credential identifiers or source evidence are inadequate, state the limitation rather than silently treating matching usernames as the same person. All demo identifiers are fabricated placeholders; no secret key or session token is stored.

### 3. Why is MFA failure no longer the story?

This scenario does not infer the legitimacy of a permission change from an assumed authentication result. Employee federation is background context. Without IdP/authentication logs, the demo does not claim verified MFA use. The target service user has no console-login configuration; its key is for programmatic access.

MFA, authentication, API authorization, and business approval are different layers. A session that completed MFA can still make an operational mistake, exceed approved scope, or be misused. The investigation concerns those possibilities; it does not demonstrate MFA bypass.

### 4. Evidence capabilities and gaps

| Question | Required evidence | Wording when evidence is missing |
| --- | --- | --- |
| Which AWS identity performed the action? | CloudTrail userIdentity, issuer, and temporary-credential/session fields | Attribute to the role/session, not a verified employee |
| Was the policy actually attached? | Target userName, policyArn, API outcome, and configuration state after the call when needed | Distinguish completion, rejection, and uncertainty; absence of errorCode is not a universal success definition for every event type |
| Were permissions limited to reporting before attachment? | A permission baseline/configuration snapshot with an applicable validity period | Confirm the new attachment without claiming a complete before/after permission evaluation |
| Was the new key used? | Actual logs correlating the created key ID with later calls, after verifying field availability | Created; usage not established |
| Were reporting objects read or data exported? | Relevant service data events and application logs | Do not infer exfiltration or its absence from management events, ListBuckets, or missing records |
| Was the action approved? | Versioned/status-bearing/time-scoped change records and owner verification | Matching, partially matching, or unknown; do not automatically infer benign or malicious intent |
| Did normal rotation cut over successfully? | External application verification records | Old-key deactivation alone does not establish successful application cutover |

The first phase adds no new-key usage or S3 object-reading plot. Those remain follow-up questions rather than unverified log associations invented to complete the story.

### 5. Proposed detection and queue design

These were design requirements at review time. See the operating guide for the implemented SPL contract.

- A successful configured high-risk policy attachment independently enters priority review. The transparent demo policy list does not claim to cover every dangerous policy.
- Search a defined window around the same account and target for context such as key creation. **A correlation window is not proof of causation**, and a fixed order is not required to alert.
- Target-level evidence may include different sessions, but callers must remain separate. Credential/session fields support session-level correlation; source IP is neither the sole nor a mandatory identity key.
- Key creation belongs in audit/review evidence, without labeling all normal rotations as attacks. Production context, high-risk policy, baseline differences, and approval scope help order review.
- Distinguish no change record, unavailable change source, and incomplete approval scope. Low priority or no rule match does not establish safety.
- Scope matching includes at least account, target ARN, caller role/controlled execution channel, action, policy ARN when applicable, status, and UTC validity. A key-creation match cannot approve policy attachment. Retain original records for human verification.
- Begin with explainable priority rather than an uncalibrated production risk score. Validate late arrival, deduplication, lookbacks, and window boundaries in actual SPL.

### 6. Required controls and edge cases

| Case | Expected behavior |
| --- | --- |
| Successful AdministratorAccess attachment without key creation or failed sign-ins | Still detect the high-risk change |
| Approved key rotation with an additional AdministratorAccess attachment | Show partial action-level scope coverage; do not clear the whole workflow |
| Normal key rotation without permission expansion | Retain audit and approval evidence without calling it an intrusion |
| The same change ID used for a different account, target, or time | Do not accept the scope match |
| Multiple sessions in one account, or matching usernames across accounts | Do not merge identities incorrectly; separate target association from caller attribution |
| Policy call rejected with AccessDenied | Show an unsuccessful attempt, not a target permission change |
| Successful attachment to a bounded target | Show attachment and boundary context without claiming unrestricted administrator privileges |
| A user already has two keys and another is created | Do not generate a quota-inconsistent successful event |
| Key creation without correlated usage logs | Keep usage unknown |
| Missing change data or a configuration snapshot outside its validity period | Show insufficient evidence rather than invent context |

Also validate the proactive path: new events match without a manual search click; normal rotation does not match this administrator-policy rule; overlapping lookbacks do not repeatedly notify on the same event ID; the first alert precedes delivery of follow-up key events; late events are handled or coverage limits are explicit; and detector/source failures are not interpreted as no risk. Searching a fixed historical file is not a substitute for these acceptance tests.

### 7. Splunk's value and limits

The demonstration centralizes searches across accounts and connects changes, target identity, session, ownership, and approval scope in a reviewable investigation path. CSV context explicitly simulates a CMDB/change system; it does not establish ServiceNow, IdP, or other enterprise-platform integration.

AWS-native tools can also investigate CloudTrail. A reason to use Splunk should follow the customer's existing platform, cross-source context, and investigation workflow, not an assertion that AWS tools cannot perform this work. Splunk Lantern provides relevant investigation ideas; the proposal does not implement all of its product capabilities. [Splunk Lantern: AWS privilege investigation](https://lantern.splunk.com/Security_Use_Cases/Anomaly_Detection/Detecting_privilege_escalation_in_your_AWS_environment)

Reviewable outcomes are identifying a role/session and target, separating completed/rejected calls, identifying partial approval coverage, and retaining event IDs and original logs. Any claimed reduction in investigation time requires a defined comparison task and measurement. Event intervals cannot substitute for MTTR.

### 8. Retained foundations and implementation gates

| Retain | Replace or redesign |
| --- | --- |
| JSONL, UTC validation, deduplication, original evidence, lookups, and interaction foundations | Five failures plus a sign-in without MFA as a necessary alert condition |
| Account/target/time-scoped investigation | Modeling all employees as IAMUser; role fields need explicit handling |
| Reproducible synthetic data, background activity, and controls | Describing a created key as already used, persistent, or leaked |
| Clear separation of evidence and interpretation | Treating a high-risk workflow as entirely normal because a change record exists |

**Implementation sequence:** review the proactive trigger and authorization assumptions; build small event samples, configuration snapshots, and action-level approvals; check AWS fields and API outcome semantics; implement and test scheduling, deduplication, alert entry, and human review; then expand volume and dashboard presentation after controls pass. The earlier 36 tests validated only the older contract and could not automatically validate this design.

No Splunk changes, AWS resources, real IAM calls, or verification messages were performed during that proposal stage. References supported the design mechanisms, while exact event shapes, available correlation fields, and the proposed permission model still required implementation checks. Later local implementation and its measured results are documented separately in the completion record.
