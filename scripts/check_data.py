#!/usr/bin/env python3
"""Read-only validation of this project's synthetic JSONL, never real AWS exports."""
import argparse
import hashlib
import ipaddress
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from generate_events import ACCOUNTS, ENTERPRISE_ACCOUNTS, SOURCES, READ_ONLY_EVENTS

NETWORKS = tuple(ipaddress.ip_network(n) for n in ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24'))
FORBIDDEN = re.compile(r'(?i)(secretaccesskey|sessiontoken|authorization|password|privatekey)')


def validate(events, allowed_accounts=None):
    allowed_accounts = set(ACCOUNTS if allowed_accounts is None else allowed_accounts)
    errors = []
    seen = set()
    previous = None
    if not events:
        return ['No events found']
    for number, e in enumerate(events, 1):
        prefix = f'Event {number}: '
        if not isinstance(e, dict):
            errors.append(prefix + 'must be a JSON object')
            continue
        try:
            raw_time = e['eventTime']
            if not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', raw_time):
                raise ValueError('eventTime must use UTC YYYY-MM-DDTHH:MM:SSZ')
            dt = datetime.fromisoformat(raw_time.replace('Z', '+00:00'))
            if previous and dt < previous:
                errors.append(prefix + 'not in chronological order')
            previous = dt
            eid = e['eventID']
            if not isinstance(eid, str) or not eid:
                raise ValueError('eventID must be a nonempty string')
            if eid in seen:
                errors.append(prefix + 'duplicate eventID')
            seen.add(eid)
            ip = ipaddress.ip_address(e['sourceIPAddress'])
            if not any(ip in network for network in NETWORKS):
                errors.append(prefix + 'IP is outside documentation-only ranges')
            account = e['recipientAccountId']
            if account not in allowed_accounts or e['userIdentity']['accountId'] != account:
                errors.append(prefix + 'identity/account is outside this demo or mismatched')
            if e['userIdentity']['type'] != 'IAMUser':
                errors.append(prefix + 'this simulation profile supports IAMUser only')
            name = e['eventName']
            if e['eventSource'] != SOURCES.get(name):
                errors.append(prefix + 'unsupported event or incorrect eventSource')
            if name == 'ConsoleLogin':
                if e['responseElements']['ConsoleLogin'] not in ('Success', 'Failure'):
                    errors.append(prefix + 'invalid console result')
                if e['additionalEventData']['MFAUsed'] not in ('Yes', 'No'):
                    errors.append(prefix + 'invalid MFA value')
            elif name in ('AttachUserPolicy', 'CreateAccessKey'):
                if not e['requestParameters']['userName']:
                    errors.append(prefix + 'missing target user')
            if e.get('readOnly') != (name in READ_ONLY_EVENTS):
                errors.append(prefix + 'incorrect readOnly value')
            if e.get('errorCode') and e.get('responseElements') is not None:
                errors.append(prefix + 'denied API call must not have a success response')
        except (KeyError, TypeError, ValueError) as exc:
            errors.append(prefix + f'invalid schema: {exc}')
        def scan(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    if FORBIDDEN.search(key) or key.lower() == 'accesskeyid':
                        errors.append(prefix + f'credential-bearing field forbidden in synthetic fixture: {key}')
                    scan(child)
            elif isinstance(value, list):
                for child in value:
                    scan(child)
            elif isinstance(value, str) and ('-----BEGIN ' in value or re.search(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b', value)):
                errors.append(prefix + 'credential-like value forbidden in synthetic fixture')
        scan(e)
    return errors


def read_jsonl(path):
    events = []
    for line_number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
        if not line.strip():
            raise ValueError(f'Line {line_number}: blank line')
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError(f'Line {line_number}: invalid JSON') from exc
    return events


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('path', type=Path)
    p.add_argument('--profile', choices=['teaching', 'enterprise'], default='teaching')
    p.add_argument('--manifest', type=Path, help='Also check generated counts, range, and core identity')
    args = p.parse_args()
    try:
        events = read_jsonl(args.path)
        errors = validate(events, ENTERPRISE_ACCOUNTS if args.profile == "enterprise" else ACCOUNTS)
        if args.manifest and not errors:
            meta = json.loads(args.manifest.read_text())
            counts = dict(Counter(e['eventName'] for e in events))
            if 'jsonl_sha256' in meta and meta['jsonl_sha256'] != hashlib.sha256(args.path.read_bytes()).hexdigest():
                errors.append('Manifest SHA256 does not match JSONL bytes')
            core = meta['core']
            selected = [e for e in events if e['recipientAccountId'] == core['account']
                        and e['userIdentity'].get('userName') == core['caller']
                        and e['sourceIPAddress'] == core['source_ip']]
            if (meta['event_count'] != len(events) or meta['event_counts'] != counts
                    or meta['earliest'] != events[0]['eventTime'] or meta['latest'] != events[-1]['eventTime']
                    or core['event_count'] != len(selected) or meta.get('synthetic') is not True):
                errors.append('Manifest does not match event counts, time range, or core identity')
        if errors:
            p.exit(1, '\n'.join(errors) + '\n')
        print(f'PASS: {len(events)} synthetic events; UTC, chronological, unique IDs, documentation IPs, expected schema.')
        print('Credential checks are fixture safeguards, not a general secret scanner or Splunk validation.')
    except (OSError, ValueError, KeyError, TypeError) as exc:
        p.exit(1, f'FAIL: {exc}\n')


if __name__ == '__main__':
    main()
