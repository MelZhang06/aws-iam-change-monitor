#!/usr/bin/env python3
"""Generate deterministic, synthetic CloudTrail-like investigation fixtures."""
import argparse
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ACCOUNTS = ['111122223333', '444455556666', '777788889999']
SAFE_IPS = ['192.0.2.11', '198.51.100.23', '203.0.113.17']
ENTERPRISE_ACCOUNTS = ACCOUNTS + [f'90000000{i:04d}' for i in range(17)]
SOURCES = {'ConsoleLogin': 'signin.amazonaws.com', 'ListUsers': 'iam.amazonaws.com',
           'AttachUserPolicy': 'iam.amazonaws.com', 'CreateAccessKey': 'iam.amazonaws.com',
           'GetUser': 'iam.amazonaws.com', 'ListAccessKeys': 'iam.amazonaws.com',
           'ListAttachedUserPolicies': 'iam.amazonaws.com',
           'DescribeInstances': 'ec2.amazonaws.com', 'DescribeSecurityGroups': 'ec2.amazonaws.com',
           'ListBuckets': 's3.amazonaws.com', 'GetCallerIdentity': 'sts.amazonaws.com'}
READ_ONLY_EVENTS = frozenset(SOURCES) - {'ConsoleLogin', 'AttachUserPolicy', 'CreateAccessKey'}


def parse_anchor(value):
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if dt.tzinfo is None or dt.utcoffset() is None:
            raise ValueError('timezone required')
        return dt.astimezone(timezone.utc).replace(microsecond=0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError('Use an ISO timestamp with timezone, e.g. 2026-10-25T12:00:00Z') from exc


def event(dt, account, user, name, ip, *, result=None, mfa=None, target=None,
          policy='ReadOnlyAccess', error=None):
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError('event time must be timezone-aware')
    e = {
        'eventVersion': '1.08',
        'eventTime': dt.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'eventSource': SOURCES[name], 'eventName': name, 'awsRegion': 'us-east-1',
        'sourceIPAddress': ip,
        'userIdentity': {'type': 'IAMUser', 'accountId': account, 'userName': user,
                         'principalId': 'DEMO' + uuid.uuid5(uuid.NAMESPACE_URL, account + '/' + user).hex[:16].upper(),
                         'arn': f'arn:aws:iam::{account}:user/{user}'},
        'recipientAccountId': account,
        'eventType': 'AwsConsoleSignIn' if name == 'ConsoleLogin' else 'AwsApiCall',
        'eventCategory': 'Management', 'managementEvent': True,
        'readOnly': name in READ_ONLY_EVENTS,
        'userAgent': 'Mozilla/5.0 (Synthetic demo)' if name == 'ConsoleLogin' else 'aws-cli/2.0 (Synthetic demo)',
        'requestParameters': None, 'responseElements': None,
    }
    if name == 'ConsoleLogin':
        e['responseElements'] = {'ConsoleLogin': result or 'Success'}
        e['additionalEventData'] = {'MFAUsed': mfa or 'Yes'}
        if result == 'Failure':
            e['errorMessage'] = 'Failed authentication'
    elif name in ('AttachUserPolicy', 'CreateAccessKey'):
        e['requestParameters'] = {'userName': target or user}
        if name == 'AttachUserPolicy':
            e['requestParameters']['policyArn'] = f'arn:aws:iam::aws:policy/{policy}'
        elif not error:
            # Deliberately omit credential material, including access key identifiers.
            e['responseElements'] = {'accessKey': {'userName': target or user, 'status': 'Active'}}
    if name in ('GetUser', 'ListAccessKeys', 'ListAttachedUserPolicies'):
        e['requestParameters'] = {'userName': target or user}
    if name in ('DescribeInstances', 'DescribeSecurityGroups'):
        e['requestParameters'] = {}
    if error:
        e['errorCode'] = error
        e['errorMessage'] = 'Synthetic denied operation'
        e['responseElements'] = None
    return e


def generate(anchor, seed=41):
    if anchor.tzinfo is None or anchor.utcoffset() is None:
        raise ValueError('anchor must be timezone-aware')
    anchor = anchor.astimezone(timezone.utc).replace(microsecond=0)
    rng = random.Random(seed)
    events = []
    for i in range(54):
        account = ACCOUNTS[i % 3]
        user = ['sam', 'jordan', 'riley', 'morgan'][i % 4]
        dt = anchor - timedelta(hours=10) + timedelta(minutes=10*i)
        events.append(event(dt, account, user, 'ConsoleLogin', SAFE_IPS[i % 3],
                            result='Failure' if rng.random() < 0.12 else 'Success', mfa='Yes'))
        if i % 3 == 0:
            api_account = ACCOUNTS[(i // 3) % 3]
            events.append(event(dt + timedelta(seconds=30), api_account, user, 'ListUsers',
                                SAFE_IPS[(i // 3) % 3]))
    start = anchor.replace(minute=0, second=0) - timedelta(minutes=90)
    for i in range(6):
        events.append(event(start + timedelta(minutes=i), ACCOUNTS[0], 'alex', 'ConsoleLogin',
                            '203.0.113.77', result='Failure', mfa='No'))
    events.append(event(start + timedelta(minutes=7), ACCOUNTS[0], 'alex', 'ConsoleLogin',
                        '203.0.113.77', result='Success', mfa='No'))
    events.append(event(start + timedelta(minutes=13), ACCOUNTS[0], 'alex', 'AttachUserPolicy',
                        '203.0.113.77', target='svc-analytics', policy='AdministratorAccess'))
    events.append(event(start + timedelta(minutes=14), ACCOUNTS[0], 'alex', 'CreateAccessKey',
                        '203.0.113.77', target='svc-analytics'))
    # Control 1: failure burst without successful login or subsequent API activity.
    for i in range(5):
        events.append(event(start - timedelta(hours=2) + timedelta(minutes=i), ACCOUNTS[1],
                            'casey', 'ConsoleLogin', '198.51.100.88', result='Failure', mfa='Yes'))
    # Control 2: fictional approved administration, still visible to the investigator.
    for offset, name in [(0, 'AttachUserPolicy'), (1, 'CreateAccessKey')]:
        events.append(event(start - timedelta(hours=3) + timedelta(minutes=offset), ACCOUNTS[2],
                            'pat-admin', name, '192.0.2.50', target='svc-reporting'))
    for i, e in enumerate(events):
        payload = json.dumps(e, sort_keys=True, separators=(',', ':'))
        e['eventID'] = str(uuid.uuid5(uuid.NAMESPACE_URL, f'cloudtrail-demo:{seed}:{i}:{payload}'))
    return sorted(events, key=lambda e: (e['eventTime'], e['eventID']))


def manifest(events, anchor, seed):
    from collections import Counter
    return {'synthetic': True, 'schema_version': 1, 'anchor': anchor.isoformat(), 'seed': seed,
            'event_count': len(events), 'earliest': events[0]['eventTime'], 'latest': events[-1]['eventTime'],
            'event_counts': dict(sorted(Counter(e['eventName'] for e in events).items())),
            'core': {'account': ACCOUNTS[0], 'caller': 'alex', 'target': 'svc-analytics',
                     'source_ip': '203.0.113.77', 'event_count': 9},
            'controls': ['casey: isolated failures', 'pat-admin: fictional approved administration']}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, default=Path('data/synthetic_cloudtrail.jsonl'))
    p.add_argument('--seed', type=int, default=41)
    p.add_argument('--anchor', type=parse_anchor, help='Fixed ISO time; defaults to current UTC minute')
    p.add_argument('--force', action='store_true', help='Replace existing synthetic output and manifest')
    args = p.parse_args()
    anchor = args.anchor or datetime.now(timezone.utc).replace(second=0, microsecond=0)
    events = generate(anchor, args.seed)
    meta = args.output.with_suffix('.manifest.json')
    if not args.force and (args.output.exists() or meta.exists()):
        p.error('Output exists; use --force to replace synthetic demo files')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(''.join(json.dumps(e, separators=(',', ':')) + '\n' for e in events), encoding='utf-8')
    meta.write_text(json.dumps(manifest(events, anchor, args.seed), indent=2) + '\n', encoding='utf-8')
    print(f'Wrote {len(events)} synthetic events to {args.output}; manifest: {meta}')
    print(f'UTC event range: {events[0]["eventTime"]} to {events[-1]["eventTime"]}')
    print('Fixed anchors require an absolute Splunk time range covering these events.')


if __name__ == '__main__':
    main()
