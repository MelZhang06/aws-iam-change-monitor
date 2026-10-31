#!/usr/bin/env python3
"""Build an isolated Splunk app. No installation or network operations."""
import json
import shutil
from pathlib import Path
from xml.sax.saxutils import escape

from change_scenario import ADMIN, DATA, ROOT

APP_ID='aws_iam_change_demo'
APP=ROOT/'splunk_app'/APP_ID
RULE_NAME='GSS - Production service identity administrator policy attached'
BASE='''index=aws_iam_change_demo sourcetype=aws:cloudtrail:gss
| dedup recipientAccountId eventID
| eval account_id=recipientAccountId, target_user='requestParameters.userName', actor_arn='userIdentity.arn', role_arn=coalesce('userIdentity.sessionContext.sessionIssuer.arn','userIdentity.arn'), actor_key='userIdentity.accessKeyId', policy_arn=coalesce('requestParameters.policyArn',"-"), outcome=if(isnotnull(errorCode) OR isnotnull(errorMessage),"Rejected","API completed without reported error")
'''
ASSET='''| lookup gss_assets.csv account_id target_user OUTPUT target_arn environment owner expected_policy boundary console_access snapshot_from snapshot_to
| eval snapshot_valid=if(_time>=strptime(replace(snapshot_from,"Z$","+0000"),"%Y-%m-%dT%H:%M:%S%z") AND _time<=strptime(replace(snapshot_to,"Z$","+0000"),"%Y-%m-%dT%H:%M:%S%z"),1,0)
| eval environment=if(snapshot_valid=1,environment,"Unknown"), context_status=if(snapshot_valid=1,"Snapshot available - verify","Missing or out-of-period snapshot"), target_arn=if(snapshot_valid=1,target_arn,"Unresolved target ARN")
'''
DETECT=BASE+'''| where eventSource="iam.amazonaws.com" AND eventName="AttachUserPolicy" AND policy_arn="ADMIN" AND isnull(errorCode) AND isnull(errorMessage)
'''.replace('ADMIN',ADMIN)+ASSET+'''| where environment="production" OR environment="Unknown"
| eval rule_id="gss-admin-attach-v2", finding_id=sha256(account_id."|".eventID."|gss-admin-attach-v2"), detected_at=now(), event_epoch=_time
| eval alert_payload=json_object("rule_id",rule_id,"finding_id",finding_id,"event_id",eventID,"account_id",account_id,"target_user",target_user,"target_arn",target_arn,"environment",environment,"actor_arn",actor_arn,"role_arn",role_arn,"actor_key",coalesce(actor_key,"Unknown"),"policy_arn",policy_arn,"event_time",eventTime,"event_epoch",event_epoch,"detected_at",detected_at,"context_status",context_status)
| table finding_id rule_id eventID account_id target_user target_arn environment actor_arn role_arn actor_key policy_arn eventTime event_epoch detected_at context_status alert_payload
'''
LIVE_DETECT=DETECT.replace('sourcetype=aws:cloudtrail:gss','sourcetype=aws:cloudtrail:gss _index_earliest=-15m')
ALERTS='''index=aws_iam_change_alerts sourcetype=aws:iam:change:alert earliest=-24h latest=now
| dedup finding_id
| eval Detected=strftime(detected_at,"%d %b %H:%M:%S %Z"), Concern=if(environment="Unknown","High-risk policy; context missing","Production high-risk policy attachment"), _account=account_id, _target=target_user, _event=event_id, _finding=finding_id, _from=event_epoch-900, _to=event_epoch+901
| sort 0 -detected_at
'''
ALERT_TABLE=ALERTS+'''| table Detected event_time account_id target_user Concern context_status _account _target _event _finding _from _to
| rename event_time as "Event time (UTC)" account_id as "AWS account" target_user as "Affected identity" context_status as "Asset context"
'''
SELECT=BASE+'''| where account_id=$case_account|s$ AND target_user=$case_target|s$ AND _time>=tonumber($case_from|s$) AND _time<tonumber($case_to|s$)
'''
# Target-wide context intentionally retains other callers; callers are displayed,
# never falsely merged. Same credential is a pivot, not proof of a human's identity.
TIMELINE=SELECT+'''| eval Time=strftime(_time,"%d %b %H:%M:%S %Z"), Policy=if(policy_arn="-","N/A",policy_arn), Session=actor_arn, Credential=coalesce(actor_key,"Unavailable")
| sort 0 _time eventID
| table Time eventName outcome Session Credential Policy eventID
| rename eventName as "Action" outcome as "API outcome" eventID as "Event ID"
'''
APPROVAL=SELECT+'''| where eventName IN ("AttachUserPolicy","CreateAccessKey","UpdateAccessKey","DeleteAccessKey")
'''+ASSET+'''| eval scope_key=md5(account_id."|".target_arn."|".role_arn."|".eventName."|".policy_arn)
| join type=left max=0 scope_key [
    | inputlookup gss_changes.csv
    | where status="Approved"
    | eval scope_key=md5(account_id."|".target_arn."|".role_arn."|".event_name."|".policy_arn), start_epoch=strptime(replace(valid_from,"Z$","+0000"),"%Y-%m-%dT%H:%M:%S%z"), end_epoch=strptime(replace(valid_to,"Z$","+0000"),"%Y-%m-%dT%H:%M:%S%z")
    | fields scope_key change_id start_epoch end_epoch scope
]
| eval match_id=if(_time>=start_epoch AND _time<=end_epoch,change_id,null())
| stats values(match_id) as matching_changes values(scope) as scope by eventID _time eventName target_user outcome
| eval Time=strftime(_time,"%d %b %H:%M:%S %Z"), Scope_match=if(mvcount(matching_changes)>0,mvjoin(matching_changes,", ")." - this action only; verify overall change","No exact approved scope match - verify"), Interpretation=if(mvcount(matching_changes)>0,"Matching key action does not approve a policy attachment","Missing scope match is not proof of compromise")
| sort 0 _time
| table Time eventName outcome Scope_match Interpretation
| rename eventName as "Action" outcome as "API outcome" Scope_match as "Change-scope evidence"
'''
CONTEXT=SELECT+ASSET+'''| lookup gss_roles.csv account_id role_arn OUTPUT owner as role_owner attachment_scope
| stats values(environment) as Environment values(owner) as Service_owner values(expected_policy) as Expected_baseline values(boundary) as Boundary values(console_access) as Console_access values(role_arn) as Caller_roles values(role_owner) as Role_owner values(attachment_scope) as Delegation_scope values(context_status) as Snapshot_status by account_id target_user
| rename account_id as "AWS account" target_user as "Affected identity"
| eval Owners=Service_owner." / ".Role_owner
| rename Expected_baseline as "Expected baseline" Console_access as "Console access" Snapshot_status as "Asset context"
| table Environment Owners "Expected baseline" Boundary "Console access" "Asset context"
'''
RAW=SELECT+'''| sort 0 _time eventID
| table eventTime eventID _raw
| rename eventTime as "UTC event time" eventID as "Event ID" _raw as "Original synthetic event"
'''
METRICS='''index=aws_iam_change_demo sourcetype=aws:cloudtrail:gss earliest=-8d latest=now
| stats count as Indexed_events dc(eventID) as Unique_events dc(recipientAccountId) as Accounts count(eval(isnotnull(errorCode))) as Rejected_requests
'''
TREND='''index=aws_iam_change_demo sourcetype=aws:cloudtrail:gss earliest=-8d latest=now
| dedup recipientAccountId eventID
| timechart span=1h fixedrange=false count as "IAM management events"
'''


def make_dashboard():
    sources={};visuals={};blocks=[]
    def source(name,query,extend=None,params=None):
        key='ds_'+name
        sources[key]={'type':'ds.chain' if extend else 'ds.search','name':name.replace('_',' ').title(),'options':{'query':query}}
        if extend:sources[key]['options']['extend']=extend
        if params:sources[key]['options']['queryParameters']=params
        return key
    def visual(name,kind,title,ds,x,y,w,h,options=None,**extra):
        key='viz_'+name
        visuals[key]={'type':kind,'title':title,'options':options or {},**extra}
        if ds:visuals[key]['dataSources']={'primary':ds}
        blocks.append({'item':key,'type':'block','position':{'x':x,'y':y,'w':w,'h':h}})
    def md(name,text,y,h):
        visual(name,'splunk.markdown','',None,0,y,1440,h,{'markdown':text})
    md('intro','### Detect → alert → investigate\nSynthetic AWS management events. An enabled scheduled rule records high-risk policy attachments; the table below reads delivered alert records, not recomputed detection results. No email, ITSM or containment integration.',0,100)
    metrics=source('metrics',METRICS)
    for i,(field,title) in enumerate([('Indexed_events','Indexed IAM events · 8d'),('Unique_events','Unique events · 8d'),('Accounts','AWS accounts · 8d'),('Rejected_requests','Rejected requests · 8d')]):
        visual(field,'splunk.singlevalue',title,source('metric_'+field,'| table '+field,metrics),i*288,100,288,110)
    alerts=source('delivered_alerts',ALERT_TABLE)
    visual('count','splunk.singlevalue','Recorded alerts · received 24h',source('alert_count','| stats count as Alerts',alerts),1152,100,288,110)
    visual('trend','splunk.column','IAM activity background — hourly, last eight days',source('trend',TREND),0,210,1440,210,{'legendDisplay':'off','seriesColors':['#007ABD']})
    visual('alerts','splunk.table','1. Recorded alerts — select a row to investigate',alerts,0,420,1440,260,{'showInternalFields':False,'count':10},eventHandlers=[{'type':'drilldown.setToken','options':{'tokens':[{'token':'case_'+name,'key':'row._'+name+'.value'} for name in ('account','target','event','finding','from','to')]}}],description='Trigger: successful AdministratorAccess attachment to a production service identity, or an identity with missing context. No login-failure or new-key prerequisite. Rule version: gss-admin-attach-v2. Select a row for event-time evidence.')
    md('selected','### 2. Selected identity: $case_target$ · account $case_account$\nEvidence window: 15 minutes before/after the original policy event, including late-arriving events. Target-wide context retains each caller separately. The alert list uses detection time; evidence uses the selected event time. Changing either query is available through Open in Search.',680,100)
    params={'earliest':'$case_from$','latest':'$case_to$'}
    visual('context','splunk.table','Configuration and ownership snapshots — fictional, time checked',source('context',CONTEXT,params=params),0,780,1440,190,{'showInternalFields':False},hideWhenNoData=True)
    visual('timeline','splunk.table','3. What happened? Caller role sessions remain visible',source('timeline',TIMELINE,params=params),0,970,1440,340,{'showInternalFields':False,'count':10},hideWhenNoData=True)
    visual('scope','splunk.table','4. Was this action within the recorded change scope?',source('scope',APPROVAL,params=params),0,1310,1440,260,{'showInternalFields':False,'count':10},hideWhenNoData=True)
    md('decision','### 5. Human verification and next action\nConfirm change scope and ownership; distinguish authorised maintenance, out-of-scope change and insufficient evidence. Key creation alone does not prove use or leakage. Matching approval does not clear the overall workflow. This demo does not persist analyst disposition or automatically remediate.',1570,110)
    visual('raw','splunk.table','Original event evidence and IDs',source('raw',RAW,params=params),0,1680,1440,270,{'showInternalFields':False,'count':3},hideWhenNoData=True)
    md('limits','**Boundaries:** no real AWS ingestion or policy execution; sourceIdentity/employee attribution is not asserted; a role session is not a verified person. AdministratorAccess attachment does not override SCPs/boundaries. Triggered Alerts and the recorded-alert index are demonstrated locally; external notification is not configured.',1950,100)
    defaults={'case_account':'Choose an alert','case_target':'Choose an alert','case_event':'__unselected__','case_finding':'__unselected__','case_from':'0','case_to':'1'}
    return {'title':'AWS IAM Change Monitor','description':'Proactive detection and human verification of production service-identity changes. Original synthetic scenario.',
            'inputs':{},'defaults':{'tokens':{'default':{k:{'value':v} for k,v in defaults.items()}},'visualizations':{'global':{'showProgressBar':True}}},
            'visualizations':visuals,'dataSources':sources,'layout':{'globalInputs':[],'layoutDefinitions':{'layout_1':{'type':'grid','options':{'width':1440,'height':2050},'structure':blocks}},'tabs':{'items':[{'label':'Alert to investigation','layoutId':'layout_1'}]}}}


def main():
    if not (DATA/'manifest.json').exists():raise SystemExit('Prepare the new fixture first: change_scenario.py prepare')
    default=APP/'default';views=default/'data/ui/views';nav=default/'data/ui/nav'
    for path in (views,nav,APP/'metadata',APP/'lookups',ROOT/'spl/change_monitor'):
        path.mkdir(parents=True,exist_ok=True)
    (default/'app.conf').write_text('''[install]
state = enabled
is_configured = 1
[ui]
is_visible = 1
label = AWS IAM Change Monitor
[launcher]
author = Demo project owner
description = Synthetic proactive IAM-change detection and investigation. No AWS operations.
version = 2.0.0
''')
    (default/'indexes.conf').write_text(''.join(f'''[{name}]
homePath = $SPLUNK_DB/{name}/db
coldPath = $SPLUNK_DB/{name}/colddb
thawedPath = $SPLUNK_DB/{name}/thaweddb
maxTotalDataSizeMB = 1000
\n''' for name in ('aws_iam_change_demo','aws_iam_change_alerts')))
    (default/'props.conf').write_text(r'''[aws:cloudtrail:gss]
INDEXED_EXTRACTIONS = json
KV_MODE = none
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TIMESTAMP_FIELDS = eventTime
TIME_FORMAT = %Y-%m-%dT%H:%M:%SZ
TZ = UTC
[aws:iam:change:alert]
KV_MODE = json
SHOULD_LINEMERGE = false
DATETIME_CONFIG = CURRENT
''')
    search=' '.join(LIVE_DETECT.strip().splitlines())
    (default/'savedsearches.conf').write_text(f'''[{RULE_NAME}]
description = Synthetic detection: successful high-risk policy attachment. Generated alert records are evidence of alert action delivery, not confirmed incidents.
search = {search}
disabled = 0
enableSched = 1
cron_schedule = */1 * * * *
dispatch.earliest_time = 0
dispatch.latest_time = now
dispatch.ttl = 86400
counttype = number of events
relation = greater than
quantity = 0
alert.digest_mode = 0
alert.track = 1
alert.expires = 24h
alert.severity = 4
alert.suppress = 1
alert.suppress.fields = finding_id
alert.suppress.period = 24h
action.logevent = 1
action.logevent.param.event = $result.alert_payload$
action.logevent.param.index = aws_iam_change_alerts
action.logevent.param.sourcetype = aws:iam:change:alert
action.logevent.param.source = rule:gss-admin-attach-v2
request.ui_dispatch_app = {APP_ID}
request.ui_dispatch_view = change_investigation
''')
    (APP/'metadata/default.meta').write_text('''[]
access = read : [ admin ], write : [ admin ]
export = none
''')
    dashboard=make_dashboard()
    (ROOT/'dashboards/aws_iam_change_monitor.json').write_text(json.dumps(dashboard,indent=2,ensure_ascii=False)+'\n')
    (views/'change_investigation.xml').write_text('<dashboard version="2" theme="dark">\n<label>'+escape(dashboard['title'])+'</label>\n<description>'+escape(dashboard['description'])+'</description>\n<definition><![CDATA[\n'+json.dumps(dashboard,indent=2,ensure_ascii=False)+'\n]]></definition>\n</dashboard>\n')
    (nav/'default.xml').write_text('<nav search_view="search"><view name="change_investigation" default="true"/><view name="search"/><view name="alerts"/><view name="alert_fired"/></nav>\n')
    for name in ('gss_assets','gss_roles','gss_changes'):
        shutil.copyfile(DATA/(name+'.csv'),APP/'lookups'/(name+'.csv'))
    for name,query in {'01_detection':DETECT,'02_scheduled_detection':LIVE_DETECT,'03_recorded_alerts':ALERT_TABLE,'04_timeline':TIMELINE,'05_approval_scope':APPROVAL,'06_configuration':CONTEXT,'07_raw':RAW}.items():
        (ROOT/'spl/change_monitor'/(name+'.spl')).write_text(query)
    overlay=DATA/'install_overlay';overlay.mkdir(exist_ok=True)
    (overlay/'inputs.conf').write_text(''.join(f'''[monitor://{DATA/name}]
disabled = 0
index = aws_iam_change_demo
sourcetype = aws:cloudtrail:gss
host = synthetic-change-replay
crcSalt = <SOURCE>
\n''' for name in ('history.jsonl','stream.jsonl')))
    print(f'Built {APP}; source monitoring overlay is local and remains gitignored.')


if __name__=='__main__':main()
