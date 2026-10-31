"""Regression checks for time-scope and drilldown failures seen in Splunk.

These verify artifact contracts, not SPL execution or Dashboard Studio rendering.
Live results and interaction checks are documented separately.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
from build_enterprise_dashboard import make_dashboard


class TestDashboardScope(unittest.TestCase):
    def setUp(self):
        self.dashboard = make_dashboard(1792540800,1793145600)

    def test_all_index_searches_follow_global_time(self):
        defaults = self.dashboard['defaults']['dataSources']['ds.search']['options']['queryParameters']
        self.assertEqual(defaults, {'earliest':'$global_time.earliest$','latest':'$global_time.latest$'})
        for source in self.dashboard['dataSources'].values():
            if source['type']=='ds.search':
                self.assertNotIn('queryParameters',source['options'])
                self.assertNotIn('earliest=0',source['options']['query'])

    def test_drilldown_identity_and_window_are_not_username_only(self):
        viz = self.dashboard['visualizations']['viz_queue']
        names = {entry['token'] for entry in viz['eventHandlers'][0]['options']['tokens']}
        self.assertEqual(names, {'selected_account','selected_principal','selected_src','selected_start','selected_end','selected_caller'})
        for name in ('selected_owner','selected_timeline','selected_changes','selected_raw'):
            query = self.dashboard['dataSources']['ds_'+name]['options']['query']
            for token in ('account','principal','src','start','end'):
                self.assertIn('$selected_'+token+'|s$',query)

    def test_initial_selection_cannot_accidentally_match_real_rows(self):
        tokens = self.dashboard['defaults']['tokens']['default']
        self.assertEqual(tokens['selected_account']['value'],'__unselected__')
        self.assertEqual(tokens['selected_start']['value'],'0')
        self.assertEqual(tokens['selected_end']['value'],'1')
        for key in ('viz_owner','viz_timeline','viz_approvals','viz_raw'):
            self.assertTrue(self.dashboard['visualizations'][key]['hideWhenNoData'])

    def test_portable_references_and_shared_transforming_sources(self):
        sources = self.dashboard['dataSources']
        for source in sources.values():
            if source['type']=='ds.chain':
                self.assertIn(source['options']['extend'],sources)
                self.assertNotIn('index=',source['options']['query'])
        for viz in self.dashboard['visualizations'].values():
            for source_id in viz.get('dataSources',{}).values():
                self.assertIn(source_id,sources)

    def test_approval_join_considers_all_records_and_time_interval(self):
        query = self.dashboard['dataSources']['ds_investigation_queue']['options']['query']
        self.assertIn('join type=left max=0 approval_key',query)
        self.assertIn('_time>=approval_start AND _time<=approval_end',query)
        for field in ('account_id','principal_arn','target_user','eventName','policy_arn'):
            self.assertIn(field,query.split('approval_key=')[1].split('\n')[0])
        self.assertIn('by eventID _time',query)
        self.assertIn('Matching approval - verify',query)


if __name__=='__main__':
    unittest.main()
