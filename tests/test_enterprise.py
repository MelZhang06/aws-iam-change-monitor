import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from generate_events import ENTERPRISE_ACCOUNTS, READ_ONLY_EVENTS, SOURCES, generate
from generate_enterprise import generate_enterprise, output_paths, SERVICES
from check_data import validate
from expected_results import queue_candidates
from verify_enterprise import verify

ANCHOR=datetime(2026,10,28,tzinfo=timezone.utc)


class TestEnterpriseSimulation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events,cls.meta,cls.accounts,cls.identities,cls.changes=generate_enterprise(ANCHOR,count=2000)

    def test_scope_cardinality_and_json_contract(self):
        self.assertEqual(len(self.events),2000)
        self.assertEqual({e['recipientAccountId'] for e in self.events},set(ENTERPRISE_ACCOUNTS))
        self.assertEqual(len({e['userIdentity']['arn'] for e in self.events}),300)
        self.assertEqual({e['userIdentity']['type'] for e in self.events},{'IAMUser'})
        self.assertEqual(validate(self.events,ENTERPRISE_ACCOUNTS),[])
        self.assertTrue(validate(self.events))  # Teaching profile must not silently accept new accounts.
        self.assertEqual(len(self.accounts),20)
        self.assertEqual(len(self.identities),300)
        self.assertEqual(len(self.changes),42)

    def test_every_service_matches_and_readonly_is_correct(self):
        self.assertEqual(len({e['eventName'] for e in self.events}),11)
        for e in self.events:
            self.assertEqual(e['eventSource'],SOURCES[e['eventName']])
            self.assertEqual(e['readOnly'],e['eventName'] in READ_ONLY_EVENTS)
            if e.get('errorCode'):
                self.assertIsNone(e['responseElements'])
        self.assertTrue(any(e.get('errorCode')=='AccessDenied' for e in self.events))

    def test_time_window_and_business_patterns(self):
        start=ANCHOR-timedelta(days=7)
        times=[datetime.fromisoformat(e['eventTime'].replace('Z','+00:00')) for e in self.events]
        self.assertTrue(all(start<=t<ANCHOR for t in times))
        self.assertEqual(times,sorted(times))
        self.assertEqual(len({e['eventTime'][:10] for e in self.events}),7)
        people=[e for e in self.events if e['userIdentity']['userName'] not in SERVICES]
        def in_office(e):
            t=datetime.fromisoformat(e['eventTime'].replace('Z','+00:00')).astimezone(ZoneInfo('Australia/Melbourne'))
            return t.weekday()<5 and 8<=t.hour<18
        self.assertGreater(sum(in_office(e) for e in people)/len(people),0.70)
        automation=[e for e in self.events if e['userIdentity']['userName'] in SERVICES]
        self.assertFalse(any(e['eventName']=='ConsoleLogin' for e in automation))
        self.assertGreater(len({e['eventTime'][11:13] for e in automation}),18)

    def test_reproducibility_and_distinct_teaching_namespace(self):
        again=generate_enterprise(ANCHOR,count=2000)
        self.assertEqual(self.events,again[0])
        self.assertEqual(self.meta,again[1])
        self.assertNotEqual(self.events,generate_enterprise(ANCHOR,seed=42,count=2000)[0])
        self.assertEqual(self.events,generate_enterprise(ANCHOR.astimezone(timezone(timedelta(hours=11))),count=2000)[0])
        self.assertFalse({e['eventID'] for e in self.events}&{e['eventID'] for e in generate(ANCHOR)})

    def test_known_scenarios_without_unplanned_sequence_matches(self):
        errors,report=verify(self.events,self.meta)
        self.assertEqual(errors,[])
        self.assertEqual(report['sequence_action_count'],5)
        self.assertEqual(report['queue_candidate_count'],3)
        self.assertEqual(sorted(r['matching_actions'] for r in report['queue_candidates']),[1,2,2])
        self.assertEqual(Counter(r['priority'] for r in report['queue_candidates']),{'High — demo rule':2,'Review':1})
        for name in ('isolated-failures','denied-access-changes','mfa-protected-control'):
            case=next(c for c in self.meta['cases'] if c['case_id']==name)
            matched_ids={i for r in report['queue_candidates'] for i in r['event_ids']}
            self.assertFalse(matched_ids&set(case['event_ids']))

    def test_approved_lookalike_not_silently_suppressed(self):
        case=next(c for c in self.meta['cases'] if c['case_id']=='approved-lookalike')
        candidate=next(r for r in queue_candidates(self.events) if set(r['event_ids'])&set(case['event_ids']))
        self.assertEqual(candidate['priority'],'High — demo rule')
        by_id={e['eventID']:e for e in self.events}
        for eid in candidate['event_ids']:
            e=by_id[eid]
            approved=[c for c in self.changes if c['account_id']==e['recipientAccountId']
                      and c['caller_arn']==e['userIdentity']['arn']
                      and c['affected_user']==e['requestParameters']['userName']
                      and c['event_name']==e['eventName']
                      and c['policy_arn']==e['requestParameters'].get('policyArn','')
                      and c['valid_from']<=e['eventTime']<=c['valid_to']]
            self.assertEqual(len(approved),1)
        # Alex's elevated changes do not have approval rows.
        alex=next(c for c in self.meta['cases'] if c['case_id']=='suspicious-admin-and-key')
        self.assertFalse(any(c['caller_arn']==f'arn:aws:iam::{alex["account_id"]}:user/alex' for c in self.changes))

    def test_repeated_names_do_not_merge_accounts(self):
        self.assertEqual(len({e['recipientAccountId'] for e in self.events if e['userIdentity']['userName']=='alex'}),20)
        candidates=queue_candidates(self.events)
        alex=[r for r in candidates if r['actor']=='alex']
        self.assertEqual(len(alex),1)
        self.assertEqual(alex[0]['account_id'],'111122223333')

    def test_verifier_catches_missing_or_changed_evidence(self):
        self.assertTrue(verify(self.events[:-1],self.meta)[0])
        modified=copy.deepcopy(self.events)
        case=next(c for c in self.meta['cases'] if c['case_id']=='suspicious-admin-and-key')
        for e in modified:
            if e['eventID'] in case['event_ids'] and e['eventName']=='ConsoleLogin' and e['responseElements']['ConsoleLogin']=='Success':
                e['additionalEventData']['MFAUsed']='Yes'
        self.assertTrue(verify(modified,self.meta)[0])

    def test_no_detection_labels_in_ingested_events(self):
        for e in self.events:
            self.assertFalse({'case_id','malicious','expected_priority','approved_change','scenario'}&set(e))

    def test_bad_parameters(self):
        for count in (0,999,1000001):
            with self.assertRaises(ValueError):
                generate_enterprise(ANCHOR,count=count)
        with self.assertRaises(ValueError):
            generate_enterprise(ANCHOR.replace(tzinfo=None))

    def test_cli_outputs_validation_and_overwrite_protection(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'enterprise.jsonl'
            cmd=[sys.executable,str(ROOT/'scripts/generate_enterprise.py'),'--anchor','2026-10-28T00:00:00Z','--count','1000','--output',str(path)]
            result=subprocess.run(cmd,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            paths=output_paths(path)
            before={k:p.read_bytes() for k,p in paths.items()}
            self.assertNotEqual(subprocess.run(cmd,capture_output=True).returncode,0)
            self.assertEqual(before,{k:p.read_bytes() for k,p in paths.items()})
            self.assertEqual(subprocess.run(cmd+['--force'],capture_output=True).returncode,0)
            self.assertEqual(before,{k:p.read_bytes() for k,p in paths.items()})
            self.assertEqual(hashlib.sha256(before['events']).hexdigest(),json.loads(before['manifest'])['jsonl_sha256'])
            check=[sys.executable,str(ROOT/'scripts/check_data.py'),str(path),'--profile','enterprise','--manifest',str(paths['manifest'])]
            checked=subprocess.run(check,capture_output=True,text=True)
            self.assertEqual(checked.returncode,0,checked.stderr)
            verification=subprocess.run([sys.executable,str(ROOT/'scripts/verify_enterprise.py'),str(path)],capture_output=True,text=True)
            self.assertEqual(verification.returncode,0,verification.stderr)
            path.write_text(path.read_text()+'\n')
            self.assertNotEqual(subprocess.run(check,capture_output=True).returncode,0)


if __name__=='__main__':
    unittest.main()
