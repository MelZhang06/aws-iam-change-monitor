# Presenter Walkthrough — Approximately 10 Minutes

## 1. Business problem — 1 minute

> Maintenance teams and automation change IAM every day in production. We need to identify changes that exceed the intended business scope and give analysts the evidence to review them. This demo starts with one observable fact: AdministratorAccess was successfully attached to a production service identity.

Explain the legacy reporting system's exception for a long-term key; new systems should favor temporary credentials. The maintainer calls APIs through a temporary role session. The demo does not treat a session name as a verified employee identity or use a role call's MFA field as proof about upstream authentication.

## 2. Normal background and detection entry point — 2 minutes

Show read-only IAM management activity across 20 fictional accounts. The generated history contains 50,000 events; the eight-day chart rolls forward with time. Normal key rotation does not match this policy rule. That establishes only that this rule did not match, not that every operation was safe.

Run `normal`, confirm ingestion, and wait for automatic scheduling. Then run `policy`. No new key has been created yet, but an alert should already appear. A scheduled detector initiates the investigation; an analyst does not have to spot the event by chance in a large table.

## 3. Verify evidence from the alert — 3 minutes

Show the rule's Enabled, Scheduled, Add to Triggered Alerts, and Log Event settings. Open the delivered alert queue and select the target identity. Check the account, original event ID, policy ARN, API result, role ARN, temporary credential, and original event.

Run `followup`, refresh the investigation page, and reselect the alert. Compare actions against the recorded scope: key creation can match the rotation approval, while the AdministratorAccess attachment has no corresponding approved scope. API authorization, recorded change approval, and business justification are separate questions.

## 4. Analyst conclusion and action — 2 minutes

> We have confirmed the policy attachment and that it is outside the scope of the supplied rotation approval. We need the service and platform owners to check for other approvals, explain any operational error, and establish which controls constrain effective permissions. We have not established key use, data exfiltration, or theft of the maintainer's identity.

If the organization confirms an out-of-scope change, authorized staff handle policies and credentials under its response process and examine related API use, workload activity, and data-access records. This project does not automatically remediate real IAM or persist SOC assignment/closure state.

## 5. Engineering credibility — 2 minutes

Show duplicate suppression, the AccessDenied negative control, a newly ingested event with a timestamp two hours earlier, missing asset context, and the permissions-boundary case. Explain that scheduling uses an ingestion lookback while investigation uses the original event window.

The demo validates detection and delivery on a small synthetic dataset in one Splunk instance. It does not establish a production latency SLA, complete IAM policy evaluation, or real AWS integration. Production work would also require source health, delay/backlog monitoring, backfill, historical asset versions, and case/notification integrations.
