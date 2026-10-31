#!/usr/bin/env python3
"""Build the portable enterprise Dashboard Studio definition and readable searches.

No Splunk connections or local installation writes. Generated CSV context is copied
from the fixture; rerun after regenerating the fixture with a different anchor.
"""
import json
import shutil
from datetime import datetime
from pathlib import Path

from build_searches import PREFIX, BODIES

ROOT = Path(__file__).resolve().parents[1]
BASE = PREFIX.replace('index=aws_security_demo', 'index=aws_security_enterprise_demo')
SEQUENCE = BASE + '\n' + BODIES['06_suspicious_sequence.spl'].split('| eval seconds_after_login=')[0].rstrip()

# Exact action keys, followed by a UTC interval check. Multiple approvals for the
# same action must all be considered; an out-of-window record is not approval.
KEY = 'md5(account_id."|".principal_arn."|".target_user."|".eventName."|".coalesce(policy_arn,"-"))'
ENRICH = '''| eval approval_key=KEY
| join type=left max=0 approval_key [
    | inputlookup enterprise_approved_changes.csv
    | rename caller_arn as principal_arn affected_user as target_user event_name as eventName
    | eval approval_key=KEY, approval_start=strptime(replace(valid_from,"Z$","+0000"),"%Y-%m-%dT%H:%M:%S%z"), approval_end=strptime(replace(valid_to,"Z$","+0000"),"%Y-%m-%dT%H:%M:%S%z")
    | fields approval_key change_id approval_start approval_end approval_context
]
| eval valid_approval=if(_time>=approval_start AND _time<=approval_end,change_id,null())
| stats values(valid_approval) as matching_changes values(eval(if(isnotnull(valid_approval),approval_context,null()))) as approval_notes by eventID _time account_id principal_arn actor src suspicious_login_time target_user eventName
| eval approved_action=if(mvcount(matching_changes)>0,1,0)
| lookup enterprise_accounts.csv account_id OUTPUT account_name environment owner as account_owner
| lookup enterprise_identities.csv account_id principal_arn OUTPUT owner as identity_owner identity_purpose
'''.replace('KEY', KEY)

# Retain policy_arn through the per-event reduction without dropping key events
# with a null policy. The admin flag is taken from the original raw action.
ENRICH = ENRICH.replace('| eval approval_key=', '| eval admin_grant=if(eventName="AttachUserPolicy" AND policy_arn="arn:aws:iam::aws:policy/AdministratorAccess",1,0), cross_user_key=if(eventName="CreateAccessKey" AND actor!=target_user,1,0), approval_key=', 1)
ENRICH = ENRICH.replace('| stats values(valid_approval)', '| stats max(admin_grant) as admin_grant max(cross_user_key) as cross_user_key values(policy_arn) as policy_arn values(valid_approval)')

QUEUE = SEQUENCE + '\n' + ENRICH + '''| stats min(_time) as first_change max(_time) as last_change count as matching_actions values(eventName) as actions max(admin_grant) as admin_grant max(cross_user_key) as cross_user_key sum(approved_action) as approved_actions values(matching_changes) as matching_changes values(account_name) as account_name values(environment) as environment values(identity_owner) as identity_owner by account_id principal_arn actor src suspicious_login_time target_user
| eval priority=if(admin_grant=1 AND cross_user_key=1,"High - demo rule","Review"), priority_order=if(admin_grant=1 AND cross_user_key=1,1,2), approval_status=case(approved_actions=matching_actions,"Matching approval - verify",approved_actions>0,"Partial approval - review",true(),"No matching approval"), sign_in_time=strftime(suspicious_login_time,"%d %b %Y %H:%M %Z"), _account=account_id, _principal=principal_arn, _src=src, _start=suspicious_login_time-900, _end=suspicious_login_time+901
| sort 0 priority_order -last_change
'''
QUEUE_TABLE = QUEUE + '''| table priority actor account_id environment target_user sign_in_time matching_actions approval_status _account _principal _src _start _end
| rename priority as "Priority" actor as "Caller" account_id as "AWS account" environment as "Environment" target_user as "Affected identity" sign_in_time as "Sign-in time" matching_actions as "Actions" approval_status as "Change context"
'''
DETAIL_BASE = BASE + '''
| where account_id=$selected_account|s$ AND principal_arn=$selected_principal|s$ AND src=$selected_src|s$ AND _time>=tonumber($selected_start|s$) AND _time<tonumber($selected_end|s$)
'''
TIMELINE = DETAIL_BASE + '''| eval Time=strftime(_time,"%d %b %H:%M:%S %Z"), Evidence=case(eventName="ConsoleLogin" AND login_result="Failure","Failed sign-in",eventName="ConsoleLogin" AND login_result="Success" AND mfa_used="No","Successful sign-in without MFA",eventName="ConsoleLogin","Successful sign-in with MFA",eventName="AttachUserPolicy","Policy attachment",eventName="CreateAccessKey","Access key creation",true(),eventName), MFA=coalesce(mfa_used,"N/A"), Target=coalesce(target_user,"N/A"), Policy=coalesce(policy_arn,"N/A")
| sort 0 _time eventID
| table Time actor Evidence outcome MFA Target Policy
| rename actor as "Caller" outcome as "Outcome"
'''
CONTEXT = DETAIL_BASE + '''| where eventName IN ("AttachUserPolicy","PutUserPolicy","CreateAccessKey") AND outcome="Success"
| eval suspicious_login_time=tonumber($selected_start|s$)+900
''' + ENRICH + '''| eval Time=strftime(_time,"%d %b %H:%M:%S %Z"), change_context=if(approved_action=1,mvjoin(matching_changes,", "),"No matching approval"), Notes=if(approved_action=1,mvjoin(approval_notes,"; "),"No exact action-and-time match in the fictional change register; investigate with the owner.")
| sort 0 _time
| table Time eventName target_user change_context Notes
| rename eventName as "Action" target_user as "Affected identity" change_context as "Change record"
'''
OWNER = DETAIL_BASE + '''| stats count as Events by account_id principal_arn actor
| lookup enterprise_accounts.csv account_id OUTPUT account_name environment owner as account_owner criticality
| lookup enterprise_identities.csv account_id principal_arn OUTPUT owner as identity_owner identity_purpose expected_activity
| table actor account_id account_name environment criticality identity_owner identity_purpose expected_activity
| rename actor as "Caller" account_id as "AWS account" account_name as "Account name" environment as "Environment" criticality as "Business criticality" identity_owner as "Owner" identity_purpose as "Identity purpose" expected_activity as "Expected activity"
'''
RAW = DETAIL_BASE + '''| sort 0 _time eventID
| table eventTime eventID _raw
| rename eventTime as "UTC event time" eventID as "Event ID" _raw as "CloudTrail JSON"
'''
TREND = '''index=aws_security_enterprise_demo sourcetype=aws:cloudtrail:demo eventName=ConsoleLogin
| dedup eventID
| eval login_result='responseElements.ConsoleLogin'
| timechart span=1h fixedrange=false count by login_result
'''
OVERVIEW = BASE + '''
| stats count as Events dc(account_id) as Accounts dc(principal_arn) as Principals count(eval(eventName="ConsoleLogin" AND login_result="Failure")) as Failed_sign_ins count(eval(outcome="Denied")) as Denied_APIs
'''


def make_dashboard(earliest, latest):
    sources, visualizations, structure = {}, {}, []

    def ds(name, query, params=None):
        key = 'ds_' + name
        sources[key] = {'type': 'ds.search', 'name': name.replace('_', ' ').title(), 'options': {'query': query}}
        if params:
            sources[key]['options']['queryParameters'] = params
        return key

    def viz(name, kind, title, source, x, y, w, h, options=None, **extra):
        key = 'viz_' + name
        visualizations[key] = {'type': kind, 'title': title, 'options': options or {}, **extra}
        if source:
            visualizations[key]['dataSources'] = {'primary': source}
        structure.append({'item': key, 'type': 'block', 'position': {'x': x, 'y': y, 'w': w, 'h': h}})
        return key

    def markdown(name, text, y, h):
        viz(name, 'splunk.markdown', '', None, 0, y, 1440, h, {'markdown': text})

    overview = ds('overview', OVERVIEW)
    # Reuse the transforming overview instead of scanning the index four times.
    for i, (field, title) in enumerate([('Events', 'CloudTrail events'), ('Accounts', 'AWS accounts'), ('Principals', 'IAM principals'), ('Failed_sign_ins', 'Failed sign-ins')]):
        metric = 'ds_metric_' + field.lower()
        sources[metric] = {'type':'ds.chain','name':title,'options':{'extend':overview,'query':'| table ' + field}}
        viz(field.lower(), 'splunk.singlevalue', title, metric, i*288, 100, 288, 120)
    markdown('intro', '### From activity to investigation\nSynthetic CloudTrail · 20 accounts · IAM-user scope. Start with the queue, select a row, then inspect its evidence and change context. Priority is an educational rule, not a calibrated risk score.', 0, 100)
    viz('trend', 'splunk.column', 'Console sign-ins — hourly success and failure', ds('login_trend', TREND), 0, 220, 1440, 260, {'stackMode': 'stacked', 'legendDisplay': 'right', 'xAxisTitleText': 'Event time (profile timezone)', 'yAxisTitleText': 'Sign-ins', 'seriesColors': ['#D94E17', '#007ABD']})
    queue = ds('investigation_queue', QUEUE_TABLE)
    sources['ds_candidate_count'] = {'type':'ds.chain','name':'Candidate count','options':{'extend':queue,'query':'| stats count as Candidates'}}
    viz('candidates','splunk.singlevalue','Investigation candidates','ds_candidate_count',1152,100,288,120)
    tokens = [{'token': 'selected_' + key, 'key': 'row._' + field + '.value'} for key, field in [('account','account'),('principal','principal'),('src','src'),('start','start'),('end','end')]]
    tokens.append({'token':'selected_caller','key':'row.Caller.value'})
    viz('queue', 'splunk.table', 'Investigation queue — select a row to inspect evidence', queue, 0, 480, 1440, 260, {'showInternalFields':False,'count':10}, eventHandlers=[{'type':'drilldown.setToken','options':{'tokens':tokens}}], description='5+ failures in 15 minutes → success without MFA → successful IAM change within 15 minutes. High requires AdministratorAccess and a cross-user access key for the same affected identity. Approval context does not suppress candidates.')
    markdown('selection', '### Selected investigation: $selected_caller$\nScope: account + principal ARN + source IP, within 15 minutes of the qualifying sign-in and the global time filter. Select a queue row to show evidence. If a time change hides the selected evidence, select another candidate.', 740, 110)
    # Inherit global bounds; explicit eval filters intersect them with the
    # selected candidate window, preventing stale out-of-range evidence.
    detail_params = None
    viz('owner', 'splunk.table', 'Ownership and account context', ds('selected_owner',OWNER,detail_params), 0, 850, 1440, 170, {'showInternalFields':False})
    viz('timeline', 'splunk.table', 'Evidence timeline — caller, affected identity and outcome', ds('selected_timeline',TIMELINE,detail_params), 0, 1020, 1440, 520, {'showInternalFields':False,'count':15})
    viz('approvals', 'splunk.table', 'Action-specific change context — verify before disposition', ds('selected_changes',CONTEXT,detail_params), 0, 1540, 1440, 260, {'showInternalFields':False,'count':10})
    viz('raw', 'splunk.table', 'Raw evidence — UTC timestamp and event ID', ds('selected_raw',RAW,detail_params), 0, 1800, 1440, 280, {'showInternalFields':False,'count':5})
    markdown('limits', '**Investigation limits:** a sequence is not proof of compromise. MFAUsed=No does not mean MFA was disabled. Missing change records mean unknown authorisation. Documentation IPs cannot support geolocation. Synthetic IAM users only; roles, Identity Center, ES risk and production scale remain future work.', 2080, 100)
    dashboard = {'title':'AWS Enterprise Identity Investigation','description':'Synthetic enterprise CloudTrail: prioritize suspicious identity sequences, inspect evidence and validate change context.', 'inputs':{'input_global_trp':{'type':'input.timerange','title':'Investigation time range','options':{'token':'global_time','defaultValue':f'{earliest},{latest}'}}}, 'defaults':{'dataSources':{'ds.search':{'options':{'queryParameters':{'earliest':'$global_time.earliest$','latest':'$global_time.latest$'}}}},'visualizations':{'global':{'showProgressBar':True}}}, 'visualizations':visualizations,'dataSources':sources,'layout':{'globalInputs':['input_global_trp'],'layoutDefinitions':{'layout_1':{'type':'grid','options':{'width':1440,'height':2060},'structure':structure}},'tabs':{'items':[{'label':'Triage and investigation','layoutId':'layout_1'}]}},'applicationProperties':{'hideEdit':False,'hideExport':False}}
    sentinel = {'selected_account':'__unselected__','selected_principal':'__unselected__','selected_src':'__unselected__','selected_start':'0','selected_end':'1','selected_caller':'Choose a queue row'}
    dashboard['defaults']['tokens'] = {'default':{key:{'value':value} for key,value in sentinel.items()}}
    dashboard['layout']['layoutDefinitions']['layout_1']['options']['height'] = 2180
    for key in ('viz_owner','viz_timeline','viz_approvals','viz_raw'):
        visualizations[key]['hideWhenNoData'] = True
    # Stable visual order also helps review/import tools.
    structure.sort(key=lambda block:(block['position']['y'],block['position']['x']))
    return dashboard


def main():
    events_path = ROOT/'data/enterprise_cloudtrail.jsonl'
    # Streaming read, bounded memory; do not infer date fields from fragile
    # manifest key names. The fixture checker validates sorting separately.
    first = last = None
    with events_path.open() as f:
        for line in f:
            event = json.loads(line)
            epoch = int(datetime.fromisoformat(event['eventTime'].replace('Z','+00:00')).timestamp())
            first = epoch if first is None else min(first, epoch)
            last = epoch if last is None else max(last, epoch)
    earliest, latest = first//86400*86400, (last//86400+1)*86400
    out = ROOT/'dashboards'
    out.mkdir(exist_ok=True)
    (out/'aws_enterprise_identity_investigation.json').write_text(json.dumps(make_dashboard(earliest,latest),indent=2,ensure_ascii=False)+'\n')
    searches = ROOT/'spl/enterprise'
    searches.mkdir(exist_ok=True)
    for name, query in {'01_overview':OVERVIEW,'02_login_trend':TREND,'03_investigation_queue':QUEUE_TABLE,'04_selected_timeline':TIMELINE,'05_selected_changes':CONTEXT,'06_selected_owner':OWNER,'07_selected_raw':RAW}.items():
        (searches/(name+'.spl')).write_text(query.rstrip()+'\n')
    for name in ('accounts','identities','approved_changes'):
        shutil.copyfile(ROOT/f'data/enterprise_cloudtrail.{name}.csv', ROOT/f'lookups/enterprise_{name}.csv')
    print(f'Built enterprise dashboard, seven searches and three fictional lookups; UTC bounds {earliest}–{latest}.')


if __name__=='__main__':
    main()
