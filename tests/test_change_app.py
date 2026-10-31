import sys
import unittest
from pathlib import Path
from xml.etree import ElementTree

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import build_change_app as b


class TestChangeApp(unittest.TestCase):
    def test_discovery_does_not_require_followup_or_login(self):
        query=b.LIVE_DETECT
        self.assertIn('_index_earliest=-15m',query)
        self.assertIn('eventName="AttachUserPolicy"',query)
        self.assertNotIn('ConsoleLogin',query)
        self.assertNotIn('streamstats',query)
        self.assertNotIn('CreateAccessKey',query)
        self.assertIn('environment="Unknown"',query)
        self.assertIn('isnull(errorCode)',query)
        self.assertIn('json_object(',query)

    def test_dashboard_queue_reads_delivered_alert_records(self):
        dashboard=b.make_dashboard()
        query=dashboard['dataSources']['ds_delivered_alerts']['options']['query']
        self.assertIn('index=aws_iam_change_alerts',query)
        self.assertNotIn('AttachUserPolicy',query)
        self.assertNotIn('index=aws_iam_change_demo ',query)

    def test_case_window_target_and_role_visibility(self):
        self.assertIn('target_user=$case_target|s$',b.SELECT)
        self.assertIn('account_id=$case_account|s$',b.SELECT)
        self.assertIn('tonumber($case_from|s$)',b.SELECT)
        self.assertIn('Session=actor_arn',b.TIMELINE)
        self.assertIn('Credential=coalesce(actor_key',b.TIMELINE)
        self.assertNotIn('actor_arn=$',b.SELECT) # do not hide another caller on same target

    def test_action_scope_is_not_blanket_approval(self):
        self.assertIn('join type=left max=0 scope_key',b.APPROVAL)
        self.assertIn('event_name',b.APPROVAL)
        self.assertIn('policy_arn',b.APPROVAL)
        self.assertIn('_time>=start_epoch AND _time<=end_epoch',b.APPROVAL)
        self.assertIn('by eventID _time',b.APPROVAL)

    def test_dashboard_references_and_safe_initial_state(self):
        dashboard=b.make_dashboard()
        for visual in dashboard['visualizations'].values():
            for source in visual.get('dataSources',{}).values():
                self.assertIn(source,dashboard['dataSources'])
        defaults=dashboard['defaults']['tokens']['default']
        self.assertEqual(defaults['case_from']['value'],'0')
        self.assertEqual(defaults['case_to']['value'],'1')
        for source in dashboard['dataSources'].values():
            if source['type']=='ds.chain':self.assertIn(source['options']['extend'],dashboard['dataSources'])
        for name in ('context','timeline','scope','raw'):
            source=dashboard['dataSources']['ds_'+name]
            self.assertEqual(source['type'],'ds.search')
            self.assertEqual(source['options']['queryParameters'],{'earliest':'$case_from$','latest':'$case_to$'})


if __name__=='__main__':unittest.main()
