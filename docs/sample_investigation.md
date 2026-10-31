# Sample investigation: Alex / account 111122223333

**Synthetic exercise; preliminary finding, not a confirmed incident.** Evidence was verified in Splunk Enterprise 10.6.1.1 on 28 October 2026. All names, account numbers, IPs, ownership and approvals are fictional.

## Trigger and scope

The investigation queue matched six failed console sign-ins followed by a successful sign-in with `MFAUsed=No`, then two successful IAM changes. Scope: `arn:aws:iam::111122223333:user/alex`, source `203.0.113.77`, account `111122223333`. The drilldown spans 01:52–02:22 UTC on 26 October (12:52–13:22 AEDT), intersected with the global time filter.

The affected identity is **svc-analytics**, distinct from caller Alex. Account context identifies `demo-production-01`, owned by fictional Cloud team 1. Alex's expected activity is read operations and console access.

## Observed evidence

| UTC time, 26 Oct | AEDT | Observation | Event ID |
| --- | --- | --- | --- |
| 02:00–02:05 | 13:00–13:05 | Six ConsoleLogin failures | Six separate IDs in raw evidence |
| 02:07 | 13:07 | ConsoleLogin Success, MFAUsed No | c00c5e85-0e73-560b-b367-618c5ef6bb46 |
| 02:13 | 13:13 | AttachUserPolicy, target svc-analytics, AdministratorAccess | e30a0064-fc2a-5c74-9afb-3f54059e09c3 |
| 02:14 | 13:14 | CreateAccessKey, target svc-analytics | 7088fe65-638e-51a4-93b3-0cf9e713d3e2 |

The changes occur 360 and 420 seconds after the qualifying login. Both have no matching action-and-time approval in the fictional change register. Credential values are deliberately absent from the dataset.

## Assessment

The combination warrants investigation under the educational High rule. It could represent suspicious access expansion, but the evidence does not prove the caller was compromised or that the actions were unauthorised. A missing register entry is not proof that no approval exists.

The data shows MFA was not used for the sign-in; it does not show MFA configuration was disabled. Policy attachment alone does not prove effective permissions under every applicable AWS policy control. Shared identity/time/IP does not conclusively identify a human or a single authenticated session. No geolocation conclusion is possible from the documentation address.

## Recommended investigation steps

Confirm ownership and intended maintenance with Cloud team 1; verify change records and the MFA exception process; inspect applicable IAM policies and additional activity by the affected identity; preserve relevant raw event IDs and determine available telemetry coverage. If unauthorised activity is confirmed, follow the organisation's incident response and credential-containment procedures.

No containment, AWS IAM changes, real access-key operations, notifications or incident tickets were executed by this project.

## Comparison and disposition limits

Pat-admin's similar sequence remains High but has exact matching fictional approval records. Jordan's key-only sequence is Review. The difference demonstrates why a candidate queue needs evidence and business context before disposition. This report records no measured detection accuracy, production performance, or analyst-time improvement.
