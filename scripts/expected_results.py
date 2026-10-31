#!/usr/bin/env python3
"""Independent reference evaluation of demo findings, not an SPL execution engine."""
import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from check_data import read_jsonl, validate
from generate_events import ACCOUNTS, ENTERPRISE_ACCOUNTS


def seconds(e):
    return datetime.fromisoformat(e['eventTime'].replace('Z', '+00:00')).timestamp()


def login(e, result):
    return e['eventName'] == 'ConsoleLogin' and (e.get('responseElements') or {}).get('ConsoleLogin') == result


def successful_api(e):
    return e['eventName'] in ('AttachUserPolicy', 'PutUserPolicy', 'CreateAccessKey') and e.get('errorCode') in (None, 'success')


def identity(e):
    u=e.get('userIdentity', {})
    return e.get('recipientAccountId'), u.get('arn'), e.get('sourceIPAddress')


def sequence_matches(events):
    # Independently inspect each sensitive event, candidate login, and prior failures.
    # No demo usernames, targets, IPs, or labels participate in the decision.
    unique={e['eventID']: e for e in events}
    events=list(unique.values())
    grouped=defaultdict(list)
    for e in events:
        grouped[identity(e)].append(e)
    matches=[]
    for change in events:
        if not successful_api(change):
            continue
        key=identity(change)
        if not all(key):
            continue
        related=[e for e in grouped[key] if e['userIdentity'].get('type')=='IAMUser'
                 and e['userIdentity'].get('userName') not in ('HIDDEN_DUE_TO_SECURITY_REASONS', None)]
        candidates=[]
        for signin in related:
            if not login(signin,'Success') or signin.get('additionalEventData',{}).get('MFAUsed')!='No':
                continue
            if not 0 < seconds(change)-seconds(signin) <= 900:
                continue
            failures=[e for e in related if login(e,'Failure') and 0 < seconds(signin)-seconds(e) <= 900]
            if len(failures)>=5:
                candidates.append(signin)
        if candidates:
            latest=max(candidates,key=seconds)
            matches.append({'event_id':change['eventID'],'account_id':key[0],
                            'actor':change['userIdentity']['userName'],'event_name':change['eventName'],
                            'target':change['requestParameters']['userName'],
                            'seconds_after_login':int(seconds(change)-seconds(latest)),
                            'principal_arn':key[1],'src':key[2],
                            'qualifying_login':latest['eventTime'],'change_time':change['eventTime']})
    return sorted(matches,key=lambda r:(r['seconds_after_login'],r['event_id']))



def queue_candidates(events, matches=None):
    """Reference grouping matches the dashboard's documented candidate definition."""
    by_id={e['eventID']:e for e in events}
    groups=defaultdict(list)
    for match in sequence_matches(events) if matches is None else matches:
        key=(match['account_id'],match['principal_arn'],match['actor'],match['src'],
             match['qualifying_login'],match['target'])
        groups[key].append(match)
    result=[]
    for key,rows in groups.items():
        admin=any(by_id[r['event_id']]['eventName']=='AttachUserPolicy'
                  and by_id[r['event_id']]['requestParameters'].get('policyArn')=='arn:aws:iam::aws:policy/AdministratorAccess'
                  for r in rows)
        cross_key=any(r['event_name']=='CreateAccessKey' and r['actor']!=r['target'] for r in rows)
        result.append({'account_id':key[0],'principal_arn':key[1],'actor':key[2],'src':key[3],
                       'qualifying_login':key[4],'target':key[5],
                       'priority':'High — demo rule' if admin and cross_key else 'Review',
                       'matching_actions':len(rows),'actions':sorted({r['event_name'] for r in rows}),
                       'first_change':min(r['change_time'] for r in rows),
                       'last_change':max(r['change_time'] for r in rows),
                       'event_ids':sorted(r['event_id'] for r in rows)})
    return sorted(result,key=lambda r:(r['qualifying_login'],r['account_id'],r['target']))


def summarize(events):
    events=list({e['eventID']:e for e in events}.values())
    buckets=defaultdict(list)
    for e in events:
        if login(e,'Failure'):
            buckets[(int(seconds(e))//900*900,e['recipientAccountId'],e['sourceIPAddress'])].append(e)
    bursts=[{'bucket_utc':datetime.fromtimestamp(k[0],tz=timezone.utc).isoformat(),
             'account_id':k[1],'src':k[2],'failed_logins':len(v)} for k,v in buckets.items() if len(v)>=5]
    matches=sequence_matches(events)
    return {'unique_events':len(events),'event_counts':dict(sorted(Counter(e['eventName'] for e in events).items())),
            'failure_bursts':sorted(bursts,key=lambda r:r['bucket_utc']),
            'successful_no_mfa':sum(login(e,'Success') and e.get('additionalEventData',{}).get('MFAUsed')=='No' for e in events),
            'sensitive_iam_rows':sum(e['eventName'] in ('AttachUserPolicy','PutUserPolicy','CreateAccessKey') for e in events),
            'sequence_matches':matches, 'queue_candidates':queue_candidates(events,matches)}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('path',type=Path)
    p.add_argument('--profile', choices=['teaching','enterprise'], default='teaching')
    args=p.parse_args()
    try:
        events=read_jsonl(args.path)
        errors=validate(events,ENTERPRISE_ACCOUNTS if args.profile=="enterprise" else ACCOUNTS)
        if errors:
            p.exit(1,'\n'.join(errors)+'\n')
        print(json.dumps(summarize(events),indent=2))
    except (OSError,ValueError) as exc:
        p.exit(1,str(exc)+'\n')


if __name__=='__main__':
    main()
