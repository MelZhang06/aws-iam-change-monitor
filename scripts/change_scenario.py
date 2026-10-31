#!/usr/bin/env python3
"""Original synthetic IAM-change fixture and append-only replay; never calls AWS.

Key IDs are fabricated identifiers, without secret keys or session tokens.
The reference model checks an explicitly bounded policy/key-state contract; it
is not an AWS policy simulator or a general CloudTrail validator.
"""
import argparse
import base64
import csv
import hashlib
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / 'data/iam_change'
ADMIN = 'arn:aws:iam::aws:policy/AdministratorAccess'
ACCOUNT = '111122223333'
ROLE = 'LegacyIdentityMaintainer'
READ_ACTIONS = ('ListAccessKeys', 'GetUser', 'ListAttachedUserPolicies')
WRITE_ACTIONS = ('AttachUserPolicy', 'DetachUserPolicy', 'CreateAccessKey', 'UpdateAccessKey', 'DeleteAccessKey')
PHASES = ('normal', 'policy', 'followup', 'duplicate', 'denied', 'late', 'unknown', 'bounded', 'cleanup')


def utc(value):
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError('UTC/timezone-aware timestamp required')
    return value.astimezone(timezone.utc).replace(microsecond=0)


def stamp(value):
    return utc(value).strftime('%Y-%m-%dT%H:%M:%SZ')


def identifier(prefix, value):
    return prefix + base64.b32encode(hashlib.sha256(value.encode()).digest()).decode()[:16]


def role_arn(account=ACCOUNT):
    return f'arn:aws:iam::{account}:role/{ROLE}'


def target_arn(target, account=ACCOUNT):
    return f'arn:aws:iam::{account}:user/legacy-reporting/{target}'


def event(at, session, action, target='svc-report-export', account=ACCOUNT,
          policy=None, error=None, key=None, call_id=''):
    at = utc(at)
    name = session[:64]
    identity = {
        'type': 'AssumedRole',
        'principalId': identifier('AROA', account+ROLE) + ':' + name,
        'arn': f'arn:aws:sts::{account}:assumed-role/{ROLE}/{name}',
        'accountId': account,
        'accessKeyId': identifier('ASIA', account+session),
        'sessionContext': {
            'sessionIssuer': {'type': 'Role', 'principalId': identifier('AROA', account+ROLE),
                              'arn': role_arn(account), 'accountId': account, 'userName': ROLE},
            'attributes': {'creationDate': stamp(at-timedelta(hours=1)), 'mfaAuthenticated': 'false'},
        },
    }
    # Fixed session creation time is assigned by callers for multi-event sessions.
    params = {'userName': target}
    if action in ('AttachUserPolicy','DetachUserPolicy'):
        params['policyArn'] = policy or ADMIN
    if action in ('UpdateAccessKey', 'DeleteAccessKey'):
        params['accessKeyId'] = key or identifier('AKIA', account+target+'old')
    if action == 'UpdateAccessKey':
        params['status'] = 'Inactive'
    response = None
    if action == 'CreateAccessKey' and not error:
        response = {'accessKey': {'userName': target, 'accessKeyId': key or identifier('AKIA', account+session+target),
                                  'status': 'Active', 'createDate': stamp(at)}}
    payload = {'eventVersion':'1.08', 'userIdentity':identity, 'eventTime':stamp(at),
               'eventSource':'iam.amazonaws.com', 'eventName':action, 'awsRegion':'us-east-1',
               'sourceIPAddress':'203.0.113.40', 'userAgent':'aws-cli/2.0 (Synthetic IAM change demo)',
               'requestParameters':params, 'responseElements':response,
               'readOnly':action in READ_ACTIONS, 'eventType':'AwsApiCall',
               'managementEvent':True, 'eventCategory':'Management', 'recipientAccountId':account}
    if error:
        payload.update(errorCode=error, errorMessage='Synthetic rejected request')
    key_text = json.dumps(payload,sort_keys=True)+call_id
    payload['eventID'] = str(uuid.uuid5(uuid.NAMESPACE_URL,'iam-change-v2:'+key_text))
    payload['requestID'] = str(uuid.uuid5(uuid.NAMESPACE_DNS,'request:'+key_text))
    return payload


def same_session(events, created):
    """Creation time is a property of a session, not of each individual call."""
    for item in events:
        item['userIdentity']['sessionContext']['attributes']['creationDate'] = stamp(created)
    return events


def scenario(phase, at, run_id):
    """No scenario labels are inserted into the CloudTrail-shaped events."""
    at = utc(at)
    session = 'demo-'+run_id
    if len(session)>55:
        raise ValueError('run ID too long')
    if phase == 'normal':
        session += '-normal'
        new_key = identifier('AKIA',ACCOUNT+session+'new')
        old_key = identifier('AKIA',ACCOUNT+'svc-report-archive'+'old')
        result = [event(at,session,'CreateAccessKey','svc-report-archive',key=new_key),
                  event(at+timedelta(seconds=1),session,'UpdateAccessKey','svc-report-archive',key=old_key),
                  event(at+timedelta(seconds=2),session,'DeleteAccessKey','svc-report-archive',key=old_key)]
    elif phase == 'policy':
        result = [event(at-timedelta(seconds=1),session,'ListAccessKeys'),
                  event(at,session,'AttachUserPolicy')]
    elif phase == 'followup':
        result = [event(at,session,'CreateAccessKey')]
    elif phase == 'denied':
        result = [event(at,session+'-denied','AttachUserPolicy',error='AccessDenied')]
    elif phase == 'late':
        # Indexed later, but event time is deliberately two hours old.
        result = [event(at-timedelta(hours=2),session+'-late','AttachUserPolicy')]
    elif phase == 'unknown':
        result = [event(at,session+'-unknown','AttachUserPolicy','svc-unregistered')]
    elif phase == 'bounded':
        result = [event(at,session+'-bounded','AttachUserPolicy','svc-bounded')]
    elif phase == 'cleanup':
        key=identifier('AKIA',ACCOUNT+session+'svc-report-export')
        result=[event(at,session+'-cleanup','UpdateAccessKey',key=key),
                event(at+timedelta(seconds=1),session+'-cleanup','DeleteAccessKey',key=key),
                event(at+timedelta(seconds=2),session+'-cleanup','DetachUserPolicy')]
    else:
        raise ValueError('duplicate uses saved original bytes; unsupported phase '+phase)
    return same_session(result,min(utc(item['eventTime']) for item in result)-timedelta(minutes=5))


def contexts(anchor):
    anchor=utc(anchor)
    start,end=stamp(anchor-timedelta(days=8)),stamp(anchor+timedelta(days=2))
    assets=[]
    roles=[]
    for i in range(20):
        account=ACCOUNT if i==0 else f'90000000{i:04d}'
        environment='production' if i%2==0 else 'development'
        roles.append({'account_id':account,'role_arn':role_arn(account),'owner':f'Cloud platform team {i%4+1}',
                      'allowed_target_prefix':f'arn:aws:iam::{account}:user/legacy-reporting/',
                      'attachment_scope':'Legacy delegation does not restrict managed-policy ARN',
                      'snapshot_from':start,'snapshot_to':end,'source':'Fictional configuration snapshot; not live IAM evaluation'})
        for target in ('svc-report-export','svc-report-archive','svc-bounded'):
            assets.append({'account_id':account,'target_user':target,'target_arn':target_arn(target,account),
                           'environment':environment,'owner':f'Reporting team {i%4+1}',
                           'expected_policy':'ReportDataReadOnly','baseline_key_count':1,
                           'console_access':'Not configured',
                           'boundary':'ReportReadBoundary' if target=='svc-bounded' else 'None in simulated baseline',
                           'snapshot_from':start,'snapshot_to':end,'source':'Fictional asset and configuration register'})
    changes=[]
    for target,number in [('svc-report-export','001'),('svc-report-archive','002')]:
        for action in ('CreateAccessKey','UpdateAccessKey','DeleteAccessKey'):
            changes.append({'change_id':'DEMO-ROTATE-'+number,'account_id':ACCOUNT,'target_arn':target_arn(target),
                            'role_arn':role_arn(),'event_name':action,'policy_arn':'-',
                            'valid_from':stamp(anchor-timedelta(hours=1)),'valid_to':stamp(anchor+timedelta(days=1)),
                            'status':'Approved','scope':'Key lifecycle only; no permission or policy changes',
                            'source':'Fictional change register; not a real ITSM integration'})
    return assets,roles,changes


def successful(item):
    return item['eventSource']=='iam.amazonaws.com' and not item.get('errorCode') and not item.get('errorMessage')


def detects(item, assets):
    if not (successful(item) and item['eventName']=='AttachUserPolicy'
            and item['requestParameters'].get('policyArn')==ADMIN):
        return False
    found=[row for row in assets if row['account_id']==item['recipientAccountId']
           and row['target_user']==item['requestParameters']['userName']
           and utc(row['snapshot_from'])<=utc(item['eventTime'])<=utc(row['snapshot_to'])]
    return not found or found[0]['environment']=='production'


def approvals(item,changes):
    role=item['userIdentity']['sessionContext']['sessionIssuer']['arn']
    return [row['change_id'] for row in changes if row['status']=='Approved'
            and row['account_id']==item['recipientAccountId']
            and row['target_arn']==target_arn(item['requestParameters']['userName'],item['recipientAccountId'])
            and row['role_arn']==role and row['event_name']==item['eventName']
            and row['policy_arn']==item['requestParameters'].get('policyArn','-')
            and utc(row['valid_from'])<=utc(item['eventTime'])<=utc(row['valid_to'])]


def validate(events):
    problems=[]
    sessions={}
    for item in events:
        try:
            at=utc(item['eventTime'])
            identity=item['userIdentity']
            assert identity['type']=='AssumedRole'
            assert identity['arn'].startswith('arn:aws:sts::'+item['recipientAccountId']+':assumed-role/')
            assert identity['sessionContext']['sessionIssuer']['arn']==role_arn(item['recipientAccountId'])
            assert utc(identity['sessionContext']['attributes']['creationDate'])<=at
            assert identity['accessKeyId'].startswith('ASIA') and len(identity['accessKeyId'])==20
            assert item['readOnly']==(item['eventName'] in READ_ACTIONS)
            assert item['eventName'] in READ_ACTIONS+WRITE_ACTIONS
            assert item['requestParameters']['userName'].startswith('svc-')
            assert item['sourceIPAddress'].startswith(('192.0.2.','198.51.100.','203.0.113.'))
            created=identity['sessionContext']['attributes']['creationDate']
            session_key=identity['accessKeyId']
            assert sessions.setdefault(session_key,created)==created,'session creation time changed'
            raw=json.dumps(item).lower()
            assert 'secretaccesskey' not in raw and 'sessiontoken' not in raw
        except (AssertionError,KeyError,TypeError,ValueError) as exc:
            problems.append(str(item.get('eventID','missing'))+': '+str(exc))
    return problems


def write_csv(path,rows):
    with path.open('w',newline='',encoding='utf-8') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0]))
        writer.writeheader();writer.writerows(rows)


def apply_state(events,previous=None):
    """Check key quota/lifecycle across replay runs; duplicate event IDs do not
    execute twice. This is a fixture state model, not AWS authorisation logic.
    """
    state=json.loads(json.dumps(previous or {'targets':{},'seen':[]}))
    for item in events:
        event_id=item['eventID']
        if event_id in state['seen'] or not successful(item) or item['eventName'] not in WRITE_ACTIONS:continue
        account=item['recipientAccountId'];target=item['requestParameters']['userName']
        entry=state['targets'].setdefault(account+':'+target,{
            'keys':{identifier('AKIA',account+target+'old'):'Active'},'policies':['ReportDataReadOnly']})
        action=item['eventName'];params=item['requestParameters']
        if action=='CreateAccessKey':
            if len(entry['keys'])>=2:raise ValueError('simulated key quota reached; cleanup the earlier run before creating another key')
            entry['keys'][item['responseElements']['accessKey']['accessKeyId']]='Active'
        elif action=='UpdateAccessKey':
            if params['accessKeyId'] not in entry['keys']:raise ValueError('cannot deactivate an absent simulated key')
            entry['keys'][params['accessKeyId']]=params['status']
        elif action=='DeleteAccessKey':
            if entry['keys'].get(params['accessKeyId'])!='Inactive':raise ValueError('demo cleanup requires an existing inactive key')
            del entry['keys'][params['accessKeyId']]
        elif action=='AttachUserPolicy':
            if params['policyArn'] not in entry['policies']:entry['policies'].append(params['policyArn'])
        elif action=='DetachUserPolicy':
            if params['policyArn'] not in entry['policies']:raise ValueError('simulated policy is not attached')
            entry['policies'].remove(params['policyArn'])
        state['seen'].append(event_id)
    return state


def generate(anchor,count=50000):
    anchor=utc(anchor)
    if count<20:
        raise ValueError('at least 20 background events required')
    rng=random.Random(53)
    events=[]
    # Read-only history gives chart context but cannot trigger the write rule.
    for i in range(count):
        account=ACCOUNT if i%20==0 else f'90000000{i%20:04d}'
        offset=rng.randrange(7*86400)
        at=anchor-timedelta(seconds=offset+1)
        # A one-hour session has one stable creation time across its events.
        hour=int(at.timestamp())//3600
        session=f'history-{i%20}-{hour}'
        item=event(at,session,READ_ACTIONS[i%3],account=account,call_id=str(i))
        item['userIdentity']['sessionContext']['attributes']['creationDate']=stamp(datetime.fromtimestamp(hour*3600,tz=timezone.utc))
        events.append(item)
    events.sort(key=lambda item:(item['eventTime'],item['eventID']))
    return events


def setup(anchor,count):
    DATA.mkdir(parents=True,exist_ok=True)
    if (DATA/'history.jsonl').exists():
        raise ValueError('output exists; use a new workspace or explicitly archive the previous generated history')
    history=generate(anchor,count)
    errors=validate(history)
    if errors:
        raise ValueError(errors[:3])
    with (DATA/'history.jsonl').open('w') as f:
        for item in history:f.write(json.dumps(item,separators=(',',':'))+'\n')
    (DATA/'stream.jsonl').touch(exist_ok=True)
    for name,rows in zip(('gss_assets','gss_roles','gss_changes'),contexts(anchor)):
        write_csv(DATA/(name+'.csv'),rows)
    (DATA/'manifest.json').write_text(json.dumps({'anchor':stamp(anchor),'background_events':count,
        'scope':'AssumedRole management-event simulation; no real AWS calls',
        'history_sha256':hashlib.sha256((DATA/'history.jsonl').read_bytes()).hexdigest()},indent=2)+'\n')
    print(f'Prepared {count} read-only history events and empty append-only stream in {DATA}')


def replay(phase,run_id,at):
    DATA.mkdir(parents=True,exist_ok=True)
    state_path=DATA/('run-'+run_id+'.json')
    state=json.loads(state_path.read_text()) if state_path.exists() else {'run_id':run_id,'phases':{},'session_created':stamp(utc(at)-timedelta(minutes=5))}
    ledger_path=DATA/'replay_state.json'
    ledger=json.loads(ledger_path.read_text()) if ledger_path.exists() else None
    if phase=='duplicate':
        if 'policy' not in state['phases']:raise ValueError('replay policy before duplicate')
        events=state['phases']['policy']
    else:
        if phase in state['phases']:raise ValueError('phase already emitted; choose a new run ID')
        if phase=='followup' and 'policy' not in state['phases']:raise ValueError('emit policy and verify alert before followup')
        if phase=='cleanup' and 'policy' not in state['phases']:raise ValueError('emit policy before cleanup')
        events=scenario(phase,at,run_id)
        if phase=='cleanup' and 'followup' not in state['phases']:
            events=[e for e in events if e['eventName']=='DetachUserPolicy']
        if phase=='normal' and ledger:
            keys=ledger['targets'].get(ACCOUNT+':svc-report-archive',{}).get('keys',{})
            active=[key for key,status in keys.items() if status=='Active']
            if active:
                for item in events:
                    if item['eventName'] in ('UpdateAccessKey','DeleteAccessKey'):
                        item['requestParameters']['accessKeyId']=active[0]
        if phase in ('policy','followup'):
            if utc(at)-utc(state['session_created'])>timedelta(hours=1):
                raise ValueError('simulated one-hour role session expired; use a new run ID')
            same_session(events,utc(state['session_created']))
        errors=validate(events)
        if errors:raise ValueError(errors)
        state['phases'][phase]=events
    next_ledger=apply_state(events,ledger)
    with (DATA/'stream.jsonl').open('a',encoding='utf-8') as f:
        for item in events:f.write(json.dumps(item,separators=(',',':'))+'\n')
    state_path.write_text(json.dumps(state,indent=2)+'\n')
    ledger_path.write_text(json.dumps(next_ledger,indent=2)+'\n')
    print(json.dumps({'phase':phase,'run_id':run_id,'events_appended':len(events),
                      'event_ids':[item['eventID'] for item in events]},indent=2))


def refresh_context(anchor):
    """Archive and renew fictional context only; preserve indexed event history."""
    if not (DATA/'manifest.json').exists():
        raise ValueError('prepare the fixture before refreshing context')
    archive=DATA/'context_archive'/utc(anchor).strftime('%Y%m%dT%H%M%SZ')
    archive.mkdir(parents=True,exist_ok=False)
    for name,rows in zip(('gss_assets','gss_roles','gss_changes'),contexts(anchor)):
        path=DATA/(name+'.csv')
        if path.exists():(archive/path.name).write_bytes(path.read_bytes())
        write_csv(path,rows)
    (DATA/'context_refresh.json').write_text(json.dumps({'anchor':stamp(anchor),
        'previous_context':str(archive),'scope':'Fictional context only; event history unchanged'},indent=2)+'\n')
    print('Renewed fictional context; rebuild and update the demo app to deploy these lookups.')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    subs=parser.add_subparsers(dest='command',required=True)
    prepare=subs.add_parser('prepare');prepare.add_argument('--anchor');prepare.add_argument('--count',type=int,default=50000)
    refresh=subs.add_parser('refresh-context');refresh.add_argument('--anchor')
    emit=subs.add_parser('replay');emit.add_argument('--phase',choices=PHASES,required=True);emit.add_argument('--run-id',required=True)
    args=parser.parse_args()
    now=datetime.now(timezone.utc).replace(microsecond=0)
    try:
        if args.command=='prepare':setup(utc(args.anchor) if args.anchor else now,args.count)
        elif args.command=='refresh-context':refresh_context(utc(args.anchor) if args.anchor else now)
        else:
            if not args.run_id.replace('-','').isalnum():raise ValueError('run ID must contain only letters, digits and hyphens')
            replay(args.phase,args.run_id,now)
    except ValueError as exc:
        parser.error(str(exc))


if __name__=='__main__':main()
