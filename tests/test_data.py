import copy
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from generate_events import ACCOUNTS, event, generate, parse_anchor
from check_data import read_jsonl, validate

ANCHOR = datetime(2026, 10, 25, 12, 0, tzinfo=timezone.utc)


class TestSyntheticEvents(unittest.TestCase):
    def setUp(self):
        self.events = generate(ANCHOR)
        self.alex = [e for e in self.events if e['userIdentity']['userName'] == 'alex']

    def test_exact_core_sequence_and_target(self):
        self.assertEqual(len(self.alex), 9)
        self.assertEqual([e['eventName'] for e in self.alex], ['ConsoleLogin']*7 + ['AttachUserPolicy', 'CreateAccessKey'])
        for e in self.alex[:6]:
            self.assertEqual(e['responseElements']['ConsoleLogin'], 'Failure')
        self.assertEqual(self.alex[6]['responseElements']['ConsoleLogin'], 'Success')
        self.assertEqual(self.alex[6]['additionalEventData']['MFAUsed'], 'No')
        self.assertEqual(self.alex[7]['requestParameters']['policyArn'], 'arn:aws:iam::aws:policy/AdministratorAccess')
        self.assertTrue(all(e['requestParameters']['userName'] == 'svc-analytics' for e in self.alex[7:]))
        times = [datetime.fromisoformat(e['eventTime'].replace('Z', '+00:00')) for e in self.alex]
        self.assertEqual([int((t-times[0]).total_seconds()/60) for t in times], [0,1,2,3,4,5,7,13,14])
        self.assertTrue(all(e['recipientAccountId'] == ACCOUNTS[0] and e['sourceIPAddress'] == '203.0.113.77' for e in self.alex))

    def test_dataset_contract(self):
        self.assertEqual(len(self.events), 88)
        self.assertEqual(validate(self.events), [])
        self.assertEqual({e['recipientAccountId'] for e in self.events}, set(ACCOUNTS))
        self.assertEqual({e['recipientAccountId'] for e in self.events if e['eventName']=='ListUsers'}, set(ACCOUNTS))
        self.assertEqual(len({e['eventID'] for e in self.events}), 88)
        self.assertTrue(all(e['eventTime'] <= ANCHOR.strftime('%Y-%m-%dT%H:%M:%SZ') for e in self.events))

    def test_benign_controls(self):
        casey = [e for e in self.events if e['userIdentity']['userName'] == 'casey']
        self.assertEqual(len(casey), 5)
        self.assertTrue(all(e['responseElements']['ConsoleLogin'] == 'Failure' for e in casey))
        admin = [e for e in self.events if e['userIdentity']['userName'] == 'pat-admin']
        self.assertEqual([e['eventName'] for e in admin], ['AttachUserPolicy','CreateAccessKey'])
        self.assertEqual(admin[0]['requestParameters']['policyArn'], 'arn:aws:iam::aws:policy/ReadOnlyAccess')
        self.assertEqual(admin[1]['requestParameters']['userName'], 'svc-reporting')

    def test_reproducible_seed_anchor_and_timezone(self):
        self.assertEqual(self.events, generate(ANCHOR))
        self.assertNotEqual(self.events, generate(ANCHOR, 42))
        self.assertEqual(self.events, generate(ANCHOR.astimezone(timezone(timedelta(hours=11)))))
        self.assertNotEqual(self.events, generate(ANCHOR + timedelta(days=1)))

    def test_naive_anchor_rejected(self):
        with self.assertRaises(ValueError):
            generate(datetime(2026,10,25))
        with self.assertRaises(Exception):
            parse_anchor('2026-10-25T12:00:00')

    def test_multiple_anchors_keep_burst_in_bucket(self):
        for minute in (0,14,15,29,45,59):
            events = generate(ANCHOR.replace(minute=minute))
            failures = [e for e in events if e['userIdentity']['userName']=='alex' and e['eventName']=='ConsoleLogin'][:6]
            self.assertEqual(len({int(datetime.fromisoformat(e['eventTime'].replace('Z','+00:00')).timestamp())//900 for e in failures}), 1)

    def test_denied_api_schema(self):
        e = event(ANCHOR, ACCOUNTS[0], 'alex', 'CreateAccessKey', '203.0.113.77', target='svc-analytics', error='AccessDenied')
        e['eventID'] = 'denied-fixture'
        self.assertIsNone(e['responseElements'])
        self.assertEqual(validate([e]), [])

    def test_validator_rejects_duplicate_ids(self):
        self.assertTrue(any('duplicate' in s for s in validate(self.events + [self.events[-1]])))

    def test_validator_rejects_invalid_schema_and_credentials(self):
        mutations = [
            ('eventTime','2026-99-99T00:00:00Z'), ('eventTime','2026-10-25T12:00:00+11:00'),
            ('sourceIPAddress','8.8.8.8'), ('eventSource','ec2.amazonaws.com'),
            ('recipientAccountId',ACCOUNTS[1]), ('secretAccessKey','do-not-store'),
            ('userAgent','-----BEGIN PRIVATE KEY-----'), ('accessKeyId','AKIA'+'A'*16),
        ]
        for key,value in mutations:
            with self.subTest(key=key,value=value):
                e=copy.deepcopy(self.events[0]); e[key]=value
                self.assertTrue(validate([e]))
        self.assertTrue(validate([None]))
        self.assertTrue(validate([]))
        self.assertTrue(any('chronological' in s for s in validate(list(reversed(self.events)))))

    def test_jsonl_and_cli_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            output=Path(d)/'events.jsonl'
            cmd=[sys.executable,str(ROOT/'scripts/generate_events.py'),'--output',str(output),'--anchor','2026-10-25T12:00:00Z']
            first=subprocess.run(cmd,capture_output=True,text=True)
            self.assertEqual(first.returncode,0,first.stderr)
            self.assertEqual(read_jsonl(output),self.events)
            before=output.read_bytes()
            self.assertNotEqual(subprocess.run(cmd,capture_output=True).returncode,0)
            self.assertEqual(output.read_bytes(),before)
            self.assertEqual(subprocess.run(cmd+['--force'],capture_output=True).returncode,0)
            self.assertEqual(output.read_bytes(),before)
            checker=[sys.executable,str(ROOT/'scripts/check_data.py'),str(output),'--manifest',str(output.with_suffix('.manifest.json'))]
            self.assertEqual(subprocess.run(checker,capture_output=True).returncode,0)
            meta=json.loads(output.with_suffix('.manifest.json').read_text()); meta['event_count']=1
            output.with_suffix('.manifest.json').write_text(json.dumps(meta))
            self.assertNotEqual(subprocess.run(checker,capture_output=True).returncode,0)
            output.write_text('{}\n\n')
            with self.assertRaisesRegex(ValueError,'blank line'):
                read_jsonl(output)
            output.write_text('{bad}\n')
            with self.assertRaisesRegex(ValueError,'invalid JSON'):
                read_jsonl(output)


if __name__ == '__main__':
    unittest.main()
