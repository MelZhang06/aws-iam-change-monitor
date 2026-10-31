import copy
import sys
import unittest
import tempfile
from unittest.mock import patch
from datetime import datetime,timedelta,timezone
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import change_scenario as c


class TestChangeScenario(unittest.TestCase):
    def setUp(self):
        self.at=datetime(2026,10,28,10,tzinfo=timezone.utc)
        self.assets,self.roles,self.changes=c.contexts(self.at)

    def test_primary_triggers_before_key_without_login(self):
        events=c.scenario('policy',self.at,'first')
        self.assertEqual([e['eventName'] for e in events],['ListAccessKeys','AttachUserPolicy'])
        self.assertEqual(sum(c.detects(e,self.assets) for e in events),1)
        self.assertFalse(c.approvals(events[-1],self.changes))

    def test_partial_approval_is_action_specific(self):
        policy=c.scenario('policy',self.at,'first')[-1]
        key=c.scenario('followup',self.at+timedelta(minutes=2),'first')[0]
        self.assertEqual(c.approvals(key,self.changes),['DEMO-ROTATE-001'])
        self.assertEqual(c.approvals(policy,self.changes),[])
        self.assertEqual(key['userIdentity']['accessKeyId'],policy['userIdentity']['accessKeyId'])

    def test_rotation_is_not_the_high_policy_rule(self):
        events=c.scenario('normal',self.at,'first')
        self.assertFalse(any(c.detects(e,self.assets) for e in events))
        self.assertTrue(all(c.approvals(e,self.changes) for e in events))
        # One old key -> create a second -> deactivate old -> delete old.
        keys={c.identifier('AKIA',c.ACCOUNT+'svc-report-archive'+'old'):'Active'}
        for e in events:
            if e['eventName']=='CreateAccessKey':
                self.assertLess(len(keys),2)
                keys[e['responseElements']['accessKey']['accessKeyId']]='Active'
            elif e['eventName']=='UpdateAccessKey':
                self.assertIn(e['requestParameters']['accessKeyId'],keys)
                keys[e['requestParameters']['accessKeyId']]='Inactive'
            elif e['eventName']=='DeleteAccessKey':
                self.assertEqual(keys.pop(e['requestParameters']['accessKeyId']),'Inactive')
        self.assertEqual(len(keys),1)

    def test_denied_not_success_and_boundary_not_suppression(self):
        denied=c.scenario('denied',self.at,'first')[0]
        self.assertFalse(c.detects(denied,self.assets))
        bounded=c.scenario('bounded',self.at,'first')[0]
        self.assertTrue(c.detects(bounded,self.assets))
        asset=next(a for a in self.assets if a['account_id']==c.ACCOUNT and a['target_user']=='svc-bounded')
        self.assertEqual(asset['boundary'],'ReportReadBoundary')

    def test_unknown_and_stale_context_not_dropped(self):
        unknown=c.scenario('unknown',self.at,'first')[0]
        self.assertTrue(c.detects(unknown,self.assets))
        expired=copy.deepcopy(self.assets)
        for a in expired:a['snapshot_to']=c.stamp(self.at-timedelta(days=1))
        self.assertTrue(c.detects(c.scenario('policy',self.at,'first')[-1],expired))

    def test_approval_account_target_role_policy_status_and_time(self):
        e=c.scenario('followup',self.at,'first')[0]
        for field,value in [('account_id','900000000001'),('target_arn',c.target_arn('other')),
                            ('role_arn','arn:aws:iam::111122223333:role/Other'),('policy_arn',c.ADMIN),
                            ('status','Draft'),('valid_to',c.stamp(self.at-timedelta(days=1)))]:
            rows=copy.deepcopy(self.changes)
            for row in rows:row[field]=value
            self.assertEqual(c.approvals(e,rows),[],field)

    def test_session_identity_not_username_or_ip(self):
        first=c.scenario('policy',self.at,'one')[-1]
        other=c.scenario('policy',self.at,'two')[-1]
        self.assertNotEqual(first['userIdentity']['accessKeyId'],other['userIdentity']['accessKeyId'])
        self.assertEqual(first['sourceIPAddress'],other['sourceIPAddress'])
        self.assertNotIn('userName',first['userIdentity'])

    def test_generator_has_unique_ids_and_no_findings(self):
        events=c.generate(self.at,2000)
        self.assertEqual(c.validate(events),[])
        self.assertEqual(len({e['eventID'] for e in events}),2000)
        self.assertEqual(len({e['recipientAccountId'] for e in events}),20)
        self.assertFalse(any(c.detects(e,self.assets) for e in events))
        self.assertEqual(events,c.generate(self.at,2000))

    def test_rejects_session_schema_and_secret_material(self):
        events=c.scenario('policy',self.at,'first')
        self.assertEqual(c.validate(events),[])
        broken=copy.deepcopy(events)
        broken[0]['userIdentity']['sessionContext']['attributes']['creationDate']='2099-01-01T00:00:00Z'
        self.assertTrue(c.validate(broken))
        broken=copy.deepcopy(events);broken[0]['secretAccessKey']='not-a-real-secret'
        self.assertTrue(c.validate(broken))

    def test_late_event_is_still_a_finding(self):
        item=c.scenario('late',self.at,'first')[0]
        self.assertEqual(c.utc(item['eventTime']),self.at-timedelta(hours=2))
        self.assertTrue(c.detects(item,self.assets))
        self.assertEqual(c.validate([item]),[])

    def test_timezone_and_size_validation(self):
        with self.assertRaises(ValueError):c.generate(self.at.replace(tzinfo=None),20)
        with self.assertRaises(ValueError):c.generate(self.at,1)

    def test_key_quota_and_synthetic_cleanup_across_runs(self):
        state=c.apply_state(c.scenario('policy',self.at,'one'))
        key=c.scenario('followup',self.at,'one')
        state=c.apply_state(key,state)
        self.assertEqual(state,c.apply_state(key,state))
        with self.assertRaises(ValueError):c.apply_state(c.scenario('followup',self.at,'two'),state)
        state=c.apply_state(c.scenario('cleanup',self.at,'one'),state)
        target=state['targets'][c.ACCOUNT+':svc-report-export']
        self.assertEqual(len(target['keys']),1)
        self.assertNotIn(c.ADMIN,target['policies'])
        state=c.apply_state(c.scenario('followup',self.at,'two'),state)
        self.assertEqual(len(state['targets'][c.ACCOUNT+':svc-report-export']['keys']),2)

    def test_rejects_impossible_key_lifecycle(self):
        bad=c.scenario('normal',self.at,'one')[-1:]
        with self.assertRaises(ValueError):c.apply_state(bad)

    def test_context_refresh_preserves_history_and_replay_state(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(c,'DATA',Path(directory)):
            protected={'history.jsonl':b'original history\n','stream.jsonl':b'original stream\n',
                       'replay_state.json':b'{"preserve":true}', 'manifest.json':b'{}'}
            for name,data in protected.items():(c.DATA/name).write_bytes(data)
            old=b'old context\n'
            (c.DATA/'gss_assets.csv').write_bytes(old)
            c.refresh_context(self.at)
            for name,data in protected.items():self.assertEqual((c.DATA/name).read_bytes(),data)
            archived=list((c.DATA/'context_archive').glob('*/gss_assets.csv'))
            self.assertEqual(len(archived),1)
            self.assertEqual(archived[0].read_bytes(),old)
            self.assertIn('snapshot_to',(c.DATA/'gss_assets.csv').read_text())


if __name__=='__main__':unittest.main()
