#!/usr/bin/env python3
"""Check enterprise scenario ground truth against independent Python findings."""
import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from generate_events import ENTERPRISE_ACCOUNTS
from check_data import read_jsonl, validate
from expected_results import sequence_matches, queue_candidates


def verify(events, meta):
    errors=validate(events,ENTERPRISE_ACCOUNTS)
    if errors:
        return errors,None
    ids={e['eventID']:e for e in events}
    if (len(events)!=meta['event_count'] or events[0]['eventTime']!=meta['earliest']
            or events[-1]['eventTime']!=meta['latest']
            or dict(Counter(e['eventName'] for e in events))!=meta['event_counts']):
        errors.append('Event counts or range do not match manifest')
    if len({e['userIdentity']['arn'] for e in events})!=meta['caller_principals']:
        errors.append('Caller principal count does not match manifest')
    matches=sequence_matches(events)
    candidates=queue_candidates(events,matches)
    if len(matches)!=meta['expected_sequence_actions'] or len(candidates)!=meta['expected_queue_candidates']:
        errors.append('Unexpected total number of sequence matches or queue candidates')
    assigned=set()
    for case in meta['cases']:
        if not set(case['event_ids']).issubset(ids):
            errors.append(f'Missing evidence for {case["case_id"]}')
        selected=[r for r in matches if r['event_id'] in case['event_ids']]
        if len(selected)!=case['expected_sequence_actions']:
            errors.append(f'Unexpected sequence action count for {case["case_id"]}')
        case_candidates=[r for r in candidates if set(r['event_ids']) & set(case['event_ids'])]
        if len(case_candidates)!=case['expected_queue_candidates']:
            errors.append(f'Unexpected candidate count for {case["case_id"]}')
        for row in case_candidates:
            if row['priority']!=case['expected_priority']:
                errors.append(f'Unexpected priority for {case["case_id"]}')
        assigned.update(r['event_id'] for r in selected)
    if assigned!={r['event_id'] for r in matches}:
        errors.append('Unplanned background sequence matches detected')
    report={'scope':'Local Python reference only; SPL and dashboard verification required',
            'events':len(events),'account_count':len({e['recipientAccountId'] for e in events}),
            'caller_principals':len({e['userIdentity']['arn'] for e in events}),
            'event_counts':dict(sorted(Counter(e['eventName'] for e in events).items())),
            'events_by_utc_date':dict(sorted(Counter(e['eventTime'][:10] for e in events).items())),
            'events_by_region':dict(sorted(Counter(e['awsRegion'] for e in events).items())),
            'failed_api_calls':sum(bool(e.get('errorCode')) for e in events),
            'sequence_action_count':len(matches),'queue_candidate_count':len(candidates),
            'queue_candidates':candidates,
            'approved_lookalike_note':'The approved case deliberately remains in the queue. Context is not automatic suppression.'}
    return errors,report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('path',type=Path)
    args=p.parse_args()
    try:
        meta=json.loads(args.path.with_suffix('.manifest.json').read_text())
        if meta.get('synthetic') is not True or meta.get('profile')!='enterprise':
            p.exit(1,'Not an enterprise synthetic manifest\n')
        if hashlib.sha256(args.path.read_bytes()).hexdigest()!=meta['jsonl_sha256']:
            p.exit(1,'Manifest hash mismatch\n')
        errors,report=verify(read_jsonl(args.path),meta)
        if errors:
            p.exit(1,'\n'.join(errors)+'\n')
        print(json.dumps(report,indent=2))
    except (OSError,ValueError,KeyError,TypeError) as exc:
        p.exit(1,f'FAIL: {exc}\n')


if __name__=='__main__':
    main()
