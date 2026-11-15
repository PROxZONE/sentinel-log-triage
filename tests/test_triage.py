import json
from pathlib import Path
import tempfile
import unittest
from triage import analyse, load_events, timestamp, markdown


def event(second, result='failure', user='analyst', ip='192.0.2.10'):
    return {'timestamp': timestamp(f'2026-01-01T00:{second // 60:02}:{second % 60:02}Z'),
            'source_ip': ip, 'username': user, 'result': result}


class TriageTests(unittest.TestCase):
    def test_rolling_window_not_fixed_buckets(self):
        report = analyse([event(i) for i in (58, 59, 60, 61, 62)], window_seconds=5)
        self.assertEqual(report['findings'][0]['failure_count'], 5)

    def test_spread_out_failures_are_not_a_burst(self):
        self.assertEqual(analyse([event(i * 60) for i in range(5)], window_seconds=10)['findings'], [])

    def test_success_must_follow_same_source_and_username(self):
        rows = [event(i) for i in range(5)]
        self.assertFalse(analyse(rows + [event(6, 'success', 'another-user')])['findings'][0]['success_after_burst'])
        self.assertTrue(analyse(rows + [event(6, 'success')])['findings'][0]['success_after_burst'])

    def test_input_order_does_not_change_result(self):
        rows = [event(i) for i in range(6)]
        self.assertEqual(analyse(rows), analyse(list(reversed(rows))))

    def test_naive_timezone_is_rejected(self):
        with self.assertRaises(ValueError):
            timestamp('2026-01-01T00:00:00')

    def test_invalid_line_is_not_silently_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'bad.jsonl'
            path.write_text(json.dumps({'timestamp': 'bad'}) + '\n', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'line 1'):
                load_events(path)

    def test_markdown_escapes_user_content(self):
        text = markdown(analyse([event(i, user='<img>|name') for i in range(5)]))
        self.assertNotIn('<img>', text)
        self.assertIn(r'\|name', text)


if __name__ == '__main__':
    unittest.main()
