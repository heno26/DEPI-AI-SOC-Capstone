"""Regression: Windows Service Control Manager EVTX conversion."""
import unittest
from Core import log_parser


class TestBT03SystemProvider(unittest.TestCase):
    def example(self, provider='Service Control Manager'):
        return {
            'timestamp': '2022-04-04T14:11:47.8527230Z',
            'event_id': 7036, 'record_id': 1862,
            'provider': provider, 'computer': 'WIN-TKC15D7KHUR',
            'event_data': {'param1': 'Software Protection', 'param2': 'running'},
        }

    def test_service_control_manager_is_windows(self):
        e = log_parser._event_from_json(self.example(), 'E001', 1)
        self.assertEqual(e['source_kind'], 'windows')
        self.assertEqual(str(e['event_id']), '7036')
        self.assertEqual(e['host'], 'WIN-TKC15D7KHUR')
        self.assertEqual(e['fields']['event_data.param1'], 'Software Protection')

    def test_unrelated_generic_provider_stays_generic(self):
        e = log_parser._event_from_json(self.example('Unrelated Provider'), 'E001', 1)
        self.assertEqual(e['source_kind'], 'generic')

    def test_wazuh_precedence_preserved(self):
        data = self.example()
        data['rule'] = {'id': '100001', 'level': 3}
        e = log_parser._event_from_json(data, 'E001', 1)
        self.assertEqual(e['source_kind'], 'wazuh')


if __name__ == '__main__':
    unittest.main()
