#!/usr/bin/env python3
"""Generate a bounded, fictional IAM-user enterprise simulation; no AWS calls."""
import argparse
import csv
import hashlib
import io
import json
import random
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from generate_events import ENTERPRISE_ACCOUNTS, READ_ONLY_EVENTS, event, parse_anchor

LOCAL_TZ = ZoneInfo('Australia/Melbourne')
PEOPLE = ['alex', 'sam', 'jordan', 'riley', 'morgan', 'casey', 'taylor', 'jamie',
          'avery', 'robin', 'drew', 'pat-admin']
SERVICES = ['svc-analytics', 'svc-reporting', 'svc-build']
READ_APIS = ['DescribeInstances', 'DescribeSecurityGroups', 'ListBuckets',
             'GetCallerIdentity', 'GetUser', 'ListAccessKeys', 'ListAttachedUserPolicies', 'ListUsers']


def roster():
    accounts=[]
    identities=[]
    for i,account in enumerate(ENTERPRISE_ACCOUNTS):
        environment=['production','development','shared-services','staging'][i%4]
        accounts.append({'account_id':account,'account_name':f'demo-{environment}-{i+1:02d}',
                         'environment':environment,'owner':f'Cloud team {i%5+1}',
                         'criticality':'High' if environment=='production' else 'Standard',
                         'context_source':'Fictional enterprise simulation'})
        for user in PEOPLE+SERVICES:
            identities.append({'account_id':account,'principal_arn':f'arn:aws:iam::{account}:user/{user}',
                               'actor':user,'identity_type':'IAMUser',
                               'identity_purpose':'Legacy automation simulation' if user in SERVICES else 'Human IAM-user simulation',
                               'owner':f'Cloud team {i%5+1}',
                               'expected_activity':'Change-controlled administration' if user=='pat-admin' else
                                                   'Read operations and console access' if user in PEOPLE else 'Read-only inventory workload',
                               'context_source':'Fictional enterprise simulation'})
    return accounts,identities


def generate_enterprise(anchor, seed=41, count=50000):
    if anchor.tzinfo is None or anchor.utcoffset() is None:
        raise ValueError('anchor must be timezone-aware')
    if not 1000 <= count <= 1000000:
        raise ValueError('event count must be between 1,000 and 1,000,000')
    anchor=anchor.astimezone(timezone.utc).replace(microsecond=0)
    start=anchor-timedelta(days=7)
    rng=random.Random(seed)
    accounts,identities=roster()
    events=[]
    cases=[]
    changes=[]

    def add_case(case_id, day, account_index, caller, target, ip, *, burst=5, mfa='No',
                 policy=True, key=True, denied=False, isolated=False, approved=False):
        # Keep all cases within the data window even for anchors not on an hour.
        begins=start+timedelta(days=day,hours=2)
        case_events=[]
        def add(offset,name,**kwargs):
            e=event(begins+timedelta(minutes=offset),ENTERPRISE_ACCOUNTS[account_index],caller,name,ip,**kwargs)
            events.append(e);case_events.append(e)
        for i in range(burst):
            add(i,'ConsoleLogin',result='Failure',mfa='No' if mfa=='No' else 'Yes')
        if not isolated:
            add(7,'ConsoleLogin',result='Success',mfa=mfa)
            if policy:
                add(13,'AttachUserPolicy',target=target,policy='AdministratorAccess',error='AccessDenied' if denied else None)
            if key:
                add(14,'CreateAccessKey',target=target,error='AccessDenied' if denied else None)
        matches=0 if isolated or denied or mfa!='No' else int(policy)+int(key)
        cases.append({'case_id':case_id,'account_id':ENTERPRISE_ACCOUNTS[account_index],
                      'caller':caller,'target':target,'source_ip':ip,
                      'first_event':case_events[0]['eventTime'],'last_event':case_events[-1]['eventTime'],
                      'expected_sequence_actions':matches,'expected_queue_candidates':int(matches>0),
                      'expected_priority':('High — demo rule' if policy and key else 'Review') if matches else None,
                      'approved_change':approved,'events':case_events})
        if approved:
            for name in ('AttachUserPolicy','CreateAccessKey'):
                changes.append({'change_id':f'DEMO-CHG-{case_id}',
                                'account_id':ENTERPRISE_ACCOUNTS[account_index],
                                'caller_arn':f'arn:aws:iam::{ENTERPRISE_ACCOUNTS[account_index]}:user/{caller}',
                                'affected_user':target,'event_name':name,
                                'policy_arn':'arn:aws:iam::aws:policy/AdministratorAccess' if name=='AttachUserPolicy' else '',
                                'valid_from':begins.strftime('%Y-%m-%dT%H:%M:%SZ'),
                                'valid_to':(begins+timedelta(minutes=30)).strftime('%Y-%m-%dT%H:%M:%SZ'),
                                'approval_context':'Fictional authorised exercise, including an MFA exception; investigate before disposition'})

    add_case('suspicious-admin-and-key',5,0,'alex','svc-analytics','203.0.113.77',burst=6)
    add_case('suspicious-key-only',3,4,'jordan','svc-reporting','203.0.113.78',policy=False)
    add_case('approved-lookalike',2,2,'pat-admin','svc-reporting','203.0.113.79',burst=6,approved=True)
    add_case('isolated-failures',4,1,'casey',None,'203.0.113.80',isolated=True)
    add_case('denied-access-changes',1,5,'taylor','svc-build','203.0.113.81',denied=True)
    add_case('mfa-protected-control',0,6,'morgan','svc-analytics','203.0.113.82',mfa='Yes')

    # Ordinary legitimate administration is visible even without the full sequence.
    for i,account in enumerate(ENTERPRISE_ACCOUNTS):
        begins=start+timedelta(days=1+i%5,hours=5,minutes=i)
        for offset,name in ((0,'AttachUserPolicy'),(1,'CreateAccessKey')):
            events.append(event(begins+timedelta(minutes=offset),account,'pat-admin',name,
                                f'192.0.2.{10+i}',target='svc-reporting',policy='ReadOnlyAccess'))
            changes.append({'change_id':f'DEMO-CHG-{i+1:03d}','account_id':account,
                            'caller_arn':f'arn:aws:iam::{account}:user/pat-admin',
                            'affected_user':'svc-reporting','event_name':name,
                            'policy_arn':'arn:aws:iam::aws:policy/ReadOnlyAccess' if name=='AttachUserPolicy' else '',
                            'valid_from':begins.strftime('%Y-%m-%dT%H:%M:%SZ'),
                            'valid_to':(begins+timedelta(minutes=30)).strftime('%Y-%m-%dT%H:%M:%SZ'),
                            'approval_context':'Fictional approved reporting maintenance'})

    human_hours=[]
    hour_weights=[]
    for h in range(7*24):
        local=(start+timedelta(hours=h,minutes=30)).astimezone(LOCAL_TZ)
        human_hours.append(h)
        hour_weights.append((1.0 if 8<=local.hour<18 else 0.035)*(0.25 if local.weekday()>=5 else 1.0))

    # Account load is deliberately uneven. Automation is active around the clock;
    # human activity follows Melbourne office hours with occasional after-hours work.
    for i in range(count-len(events)):
        person=identities[i] if i<len(identities) else None
        if person is None:
            account_index=rng.choices(range(20),weights=[8 if j<4 else 1+(j%3) for j in range(20)])[0]
            user=rng.choice(SERVICES) if rng.random()<0.35 else rng.choice(PEOPLE)
        else:
            account_index=ENTERPRISE_ACCOUNTS.index(person['account_id'])
            user=person['actor']
        automation=user in SERVICES
        if automation:
            dt=start+timedelta(seconds=rng.randrange(7*24*3600))
        else:
            dt=start+timedelta(hours=rng.choices(human_hours,weights=hour_weights)[0],seconds=rng.randrange(3600))
        name='ConsoleLogin' if not automation and rng.random()<0.14 else rng.choice(READ_APIS)
        account=ENTERPRISE_ACCOUNTS[account_index]
        ip=f'198.51.100.{20+account_index}' if automation else f'192.0.2.{10+account_index}'
        if name=='ConsoleLogin':
            e=event(dt,account,user,name,ip,result='Failure' if rng.random()<0.035 else 'Success',mfa='Yes')
        else:
            e=event(dt,account,user,name,ip,error='AccessDenied' if rng.random()<0.012 else None)
            if name.startswith('Describe'):
                e['awsRegion']=rng.choice(['ap-southeast-2','us-east-1','eu-west-1'])
            if automation:
                e['userAgent']='aws-sdk-python/1.0 (Synthetic demo inventory job)'
        events.append(e)

    # Independent ID namespace prevents identical teaching and enterprise events
    # from silently deduplicating if an operator combines the files by mistake.
    for i,e in enumerate(events):
        payload=json.dumps(e,sort_keys=True,separators=(',',':'))
        e['eventID']=str(uuid.uuid5(uuid.NAMESPACE_URL,f'enterprise-iam-demo:{seed}:{i}:{payload}'))
    events.sort(key=lambda e:(e['eventTime'],e['eventID']))
    for case in cases:
        case['event_ids']=[e['eventID'] for e in case.pop('events')]
    core=next(c for c in cases if c['case_id']=='suspicious-admin-and-key')
    meta={'synthetic':True,'schema_version':2,'profile':'enterprise','seed':seed,'anchor':anchor.isoformat(),
          'window_start':start.isoformat(),'window_end_exclusive':anchor.isoformat(),
          'event_count':len(events),'earliest':events[0]['eventTime'],'latest':events[-1]['eventTime'],
          'event_counts':dict(sorted(Counter(e['eventName'] for e in events).items())),
          'accounts':20,'caller_principals':len({e['userIdentity']['arn'] for e in events}),
          'identity_scope':'IAMUser only; includes deliberately simulated legacy automation users; no assumed-role coverage',
          'expected_sequence_actions':sum(c['expected_sequence_actions'] for c in cases),
          'expected_queue_candidates':sum(c['expected_queue_candidates'] for c in cases),
          'core':{'account':core['account_id'],'caller':core['caller'],'target':core['target'],
                  'source_ip':core['source_ip'],'event_count':len(core['event_ids'])},
          'cases':cases}
    return events,meta,accounts,identities,changes


def csv_text(rows):
    output=io.StringIO(newline='')
    writer=csv.DictWriter(output,fieldnames=list(rows[0]),lineterminator='\n')
    writer.writeheader();writer.writerows(rows)
    return output.getvalue()


def output_paths(path):
    stem=path.with_suffix('')
    return {'events':path,'manifest':path.with_suffix('.manifest.json'),
            'accounts':Path(str(stem)+'.accounts.csv'),
            'identities':Path(str(stem)+'.identities.csv'),
            'changes':Path(str(stem)+'.approved_changes.csv')}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--anchor',type=parse_anchor,help='Timezone-aware fixed anchor; default current UTC minute')
    p.add_argument('--seed',type=int,default=41)
    p.add_argument('--count',type=int,default=50000)
    p.add_argument('--output',type=Path,default=Path('data/enterprise_cloudtrail.jsonl'))
    p.add_argument('--force',action='store_true',help='Replace this enterprise output set')
    args=p.parse_args()
    paths=output_paths(args.output)
    if len(set(paths.values()))!=len(paths):
        p.error('Output paths must be distinct')
    if not args.force and any(path.exists() for path in paths.values()):
        p.error('Output exists; use --force to replace enterprise simulation files')
    anchor=args.anchor or datetime.now(timezone.utc).replace(second=0,microsecond=0)
    try:
        events,meta,accounts,identities,changes=generate_enterprise(anchor,args.seed,args.count)
    except ValueError as exc:
        p.error(str(exc))
    raw=''.join(json.dumps(e,separators=(',',':'))+'\n' for e in events)
    meta['jsonl_sha256']=hashlib.sha256(raw.encode()).hexdigest()
    meta['jsonl_bytes']=len(raw.encode())
    payloads={'events':raw,'manifest':json.dumps(meta,indent=2)+'\n',
              'accounts':csv_text(accounts),'identities':csv_text(identities),'changes':csv_text(changes)}
    for key,path in paths.items():
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(payloads[key],encoding='utf-8')
    print(f'Wrote {len(events):,} synthetic events ({meta["jsonl_bytes"]/1000000:.2f} MB) across 20 accounts / {meta["caller_principals"]} caller principals.')
    print(f'UTC range: {meta["earliest"]} to {meta["latest"]}')
    print('Expected: 5 matching API actions, grouped into 3 candidates; one candidate is a fictional approved lookalike.')
    print(f'Manifest and context CSVs are next to {args.output}. No Splunk or AWS operations performed.')


if __name__=='__main__':
    main()
