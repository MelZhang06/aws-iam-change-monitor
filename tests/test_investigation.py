import copy
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from generate_events import generate
from expected_results import sequence_matches, summarize

ANCHOR=datetime(2026,10,25,12,tzinfo=timezone.utc)


def set_time(e, dt):
    e['eventTime']=dt.strftime('%Y-%m-%dT%H:%M:%SZ')


class TestInvestigationReference(unittest.TestCase):
    """Tests expected investigation behavior; they do NOT execute SPL."""
    def setUp(self):
        self.events=generate(ANCHOR)
        self.core=[e for e in self.events if e['userIdentity']['userName']=='alex']

    def test_expected_findings_and_benign_controls(self):
        result=summarize(self.events)
        self.assertEqual(result['unique_events'],88)
        self.assertEqual(result['event_counts'],{'ConsoleLogin':66,'ListUsers':18,'AttachUserPolicy':2,'CreateAccessKey':2})
        self.assertEqual(sorted(b['failed_logins'] for b in result['failure_bursts']),[5,6])
        self.assertEqual(result['successful_no_mfa'],1)
        self.assertEqual(result['sensitive_iam_rows'],4)
        self.assertEqual([r['seconds_after_login'] for r in result['sequence_matches']],[360,420])
        self.assertEqual({r['target'] for r in result['sequence_matches']},{'svc-analytics'})

    def test_duplicate_upload_does_not_inflate_reference(self):
        self.assertEqual(summarize(self.events),summarize(self.events+self.events))

    def test_fewer_failures_or_mfa_prevents_sequence(self):
        self.assertEqual(sequence_matches(self.core[2:]),[])
        self.core[6]['additionalEventData']['MFAUsed']='Yes'
        self.assertEqual(sequence_matches(self.core),[])

    def test_denied_change_not_successful_change(self):
        for e in self.core[7:]:
            e['errorCode']='AccessDenied'; e['responseElements']=None
        self.assertEqual(sequence_matches(self.core),[])

    def test_account_principal_and_source_must_match(self):
        for field in ('account','principal','source'):
            events=copy.deepcopy(self.core)
            for e in events[7:]:
                if field=='account': e['recipientAccountId']='444455556666'
                if field=='principal': e['userIdentity']['arn']='arn:aws:iam::111122223333:user/someone-else'
                if field=='source': e['sourceIPAddress']='203.0.113.78'
            with self.subTest(field=field):
                self.assertEqual(sequence_matches(events),[])

    def test_masked_or_missing_arn_is_not_strong_correlation(self):
        for e in self.core[:6]:
            e['userIdentity']={'type':'IAMUser','accountId':'111122223333','userName':'HIDDEN_DUE_TO_SECURITY_REASONS'}
        self.assertEqual(sequence_matches(self.core),[])
        result=summarize(self.core)
        self.assertEqual(result['failure_bursts'][0]['failed_logins'],6)

    def test_failure_threshold_and_quarter_hour_boundary(self):
        events=copy.deepcopy(self.core)
        start=ANCHOR.replace(hour=10,minute=13)
        for i,e in enumerate(events):
            set_time(e,start+timedelta(minutes=[0,1,2,3,4,5,7,13,14][i]))
        # Fixed buckets split 2/4 failures, but ordered rolling sequence still qualifies.
        self.assertEqual(summarize(events)['failure_bursts'],[])
        self.assertEqual(len(sequence_matches(events)),2)

    def test_post_login_window_inclusive_upper_bound_and_order(self):
        signin=datetime.fromisoformat(self.core[6]['eventTime'].replace('Z','+00:00'))
        for delta,expected in ((900,1),(901,0),(0,0),(-1,0)):
            events=copy.deepcopy(self.core[:8])
            set_time(events[7],signin+timedelta(seconds=delta))
            with self.subTest(delta=delta):
                self.assertEqual(len(sequence_matches(events)),expected)

    def test_same_second_failures_do_not_precede_login(self):
        signin=datetime.fromisoformat(self.core[6]['eventTime'].replace('Z','+00:00'))
        for e in self.core[:6]:
            set_time(e,signin)
        self.assertEqual(sequence_matches(self.core),[])

    def test_prior_failures_outside_window_do_not_qualify(self):
        signin=datetime.fromisoformat(self.core[6]['eventTime'].replace('Z','+00:00'))
        for i,e in enumerate(self.core[:6]):
            set_time(e,signin-timedelta(minutes=30+i))
        self.assertEqual(sequence_matches(self.core),[])


if __name__=='__main__':
    unittest.main()
