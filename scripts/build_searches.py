#!/usr/bin/env python3
"""Build readable SPL1 files from a shared JSON-field normalization prefix."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PREFIX = '''index=aws_security_demo sourcetype=aws:cloudtrail:demo
| dedup eventID
| eval account_id=recipientAccountId, principal_arn='userIdentity.arn', identity_type='userIdentity.type', actor=coalesce('userIdentity.userName', 'userIdentity.arn', "unknown"), src=sourceIPAddress, login_result='responseElements.ConsoleLogin', mfa_used='additionalEventData.MFAUsed', target_user='requestParameters.userName', policy_arn='requestParameters.policyArn'
| eval actor=if(actor="HIDDEN_DUE_TO_SECURITY_REASONS", "unknown", actor)
| eval outcome=case(eventName="ConsoleLogin", login_result, isnotnull(errorCode) AND errorCode!="success", "Denied", true(), "Success")'''

BODIES = {
'01_failed_login_by_user.spl': '''| where eventName="ConsoleLogin" AND login_result="Failure"
| bin _time span=15m
| stats count as failed_logins values(actor) as observed_actors by _time account_id src
| where failed_logins>=5
| sort 0 -failed_logins''',
'02_success_without_mfa.spl': '''| where eventName="ConsoleLogin" AND login_result="Success" AND mfa_used="No"
| table _time actor principal_arn account_id src mfa_used eventID
| sort 0 -_time''',
'03_iam_policy_change.spl': '''| where eventName IN ("AttachUserPolicy", "PutUserPolicy", "CreateAccessKey")
| table _time actor target_user eventName outcome policy_arn src account_id eventID
| sort 0 -_time''',
'04_investigation_timeline.spl': '''| eval finding=case(eventName="ConsoleLogin" AND login_result="Failure", "Failed sign-in", eventName="ConsoleLogin" AND login_result="Success" AND mfa_used="No", "Successful sign-in without MFA", eventName="AttachUserPolicy", "Policy attachment to ".target_user, eventName="CreateAccessKey", "Access key creation for ".target_user, true(), eventName)
| sort 0 _time eventID
| table _time actor principal_arn finding outcome target_user policy_arn src account_id eventName eventID''',
'05_login_trend.spl': '''| where eventName="ConsoleLogin"
| timechart span=15m fixedrange=false count by login_result''',
'06_suspicious_sequence.spl': '''| where identity_type="IAMUser" AND isnotnull(principal_arn) AND actor!="unknown"
| eval event_order=if(eventName="ConsoleLogin" AND login_result="Success", 0, 1), is_failure=if(eventName="ConsoleLogin" AND login_result="Failure", 1, 0)
| sort 0 _time event_order eventID
| streamstats time_window=15m sum(is_failure) as preceding_failures by account_id principal_arn src
| eval candidate_login=if(eventName="ConsoleLogin" AND login_result="Success" AND mfa_used="No" AND preceding_failures>=5, _time, null())
| streamstats current=f last(candidate_login) as suspicious_login_time by account_id principal_arn src
| where eventName IN ("AttachUserPolicy", "PutUserPolicy", "CreateAccessKey") AND outcome="Success" AND _time>suspicious_login_time AND _time-suspicious_login_time<=900
| eval seconds_after_login=_time-suspicious_login_time
| table _time account_id actor principal_arn src eventName target_user policy_arn outcome seconds_after_login eventID''',
'07_identity_context.spl': '''| stats count as events values(src) as source_ips by account_id actor
| lookup demo_identity_context.csv account_id actor OUTPUT environment owner expected_activity context_source
| eval owner=coalesce(owner, "No context in demo lookup")
| table account_id actor environment owner expected_activity context_source events source_ips''',
'08_raw_evidence.spl': '''| sort 0 _time eventID
| table _time account_id actor eventID _raw''',
    '09_investigation_queue.spl': '| where identity_type="IAMUser" AND isnotnull(principal_arn) AND actor!="unknown"\n| eval event_order=if(eventName="ConsoleLogin" AND login_result="Success",0,1), is_failure=if(eventName="ConsoleLogin" AND login_result="Failure",1,0)\n| sort 0 _time event_order eventID\n| streamstats time_window=15m sum(is_failure) as preceding_failures by account_id principal_arn src\n| eval candidate_login=if(eventName="ConsoleLogin" AND login_result="Success" AND mfa_used="No" AND preceding_failures>=5,_time,null())\n| streamstats current=f last(candidate_login) as suspicious_login_time by account_id principal_arn src\n| where eventName IN ("AttachUserPolicy","PutUserPolicy","CreateAccessKey") AND outcome="Success" AND _time>suspicious_login_time AND _time-suspicious_login_time<=900\n| eval admin_grant=if(eventName="AttachUserPolicy" AND policy_arn="arn:aws:iam::aws:policy/AdministratorAccess",1,0), cross_user_key=if(eventName="CreateAccessKey" AND actor!=target_user,1,0)\n| stats min(_time) as first_change max(_time) as last_change count as matching_actions values(eventName) as actions max(admin_grant) as admin_grant max(cross_user_key) as cross_user_key by account_id principal_arn actor src suspicious_login_time target_user\n| eval priority=if(admin_grant=1 AND cross_user_key=1,"High — demo rule","Review"), priority_order=if(priority="High — demo rule",1,2), evidence="5+ failures → successful sign-in without MFA → IAM changes", sign_in_time=strftime(suspicious_login_time,"%d %b %Y %H:%M %Z"), last_activity=strftime(last_change,"%d %b %Y %H:%M %Z")\n| sort 0 priority_order -last_change\n| table priority actor account_id target_user src sign_in_time last_activity matching_actions actions evidence\n| rename priority as "Priority" actor as "Caller" account_id as "AWS account" target_user as "Affected identity" src as "Source IP" sign_in_time as "Qualifying sign-in" last_activity as "Latest activity" matching_actions as "Matching actions" actions as "Observed actions" evidence as "Sequence evidence"',
}


def main():
    for filename, body in BODIES.items():
        (ROOT / 'spl' / filename).write_text(PREFIX + '\n' + body + '\n')
    print(f'Built {len(BODIES)} searches.')


if __name__ == '__main__':
    main()
