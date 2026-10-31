#!/usr/bin/env python3
"""OPTIONAL: read-only CloudTrail Event History export in one AWS region. Keep output private."""
import argparse
import json
from pathlib import Path

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--region', default='ap-southeast-2')
    parser.add_argument('--profile', required=True, help='Named AWS profile (never hardcode keys)')
    parser.add_argument('--output', default='data/real_cloudtrail_PRIVATE.jsonl')
    parser.add_argument('--max-events', type=int, default=150)
    args = parser.parse_args()
    import boto3  # pip install boto3
    client = boto3.Session(profile_name=args.profile, region_name=args.region).client('cloudtrail')
    paginator = client.get_paginator('lookup_events')
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with out.open('w', encoding='utf-8') as f:
        for page in paginator.paginate(PaginationConfig={'PageSize': 50}):
            for record in page.get('Events', []):
                f.write(json.dumps(json.loads(record['CloudTrailEvent'])) + '\n')
                count += 1
                if count >= args.max_events:
                    break
            if count >= args.max_events:
                break
    print(f'Exported {count} events from {args.region} to PRIVATE file {out}.')
    print('Do not commit, publish or upload raw real-account CloudTrail to public repos or shared trials.')

if __name__ == '__main__':
    main()
