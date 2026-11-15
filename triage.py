#!/usr/bin/env python3
"""Offline authentication-event triage. Standard library only."""
from __future__ import annotations

import argparse
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
import html
import ipaddress
import json
from pathlib import Path


def timestamp(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError('timestamp must be an ISO 8601 string')
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('timestamp must include its timezone')
    return parsed.astimezone(timezone.utc)


def load_events(path: Path) -> list[dict]:
    events = []
    with path.open(encoding='utf-8') as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
                if not isinstance(item, dict):
                    raise ValueError('event must be an object')
                item = {key: item[key] for key in ('timestamp', 'source_ip', 'username', 'result')}
                item['timestamp'] = timestamp(item['timestamp'])
                item['source_ip'] = str(ipaddress.ip_address(item['source_ip']))
                if not isinstance(item['username'], str) or not 1 <= len(item['username']) <= 100:
                    raise ValueError('username must contain 1–100 characters')
                if item['result'] not in ('success', 'failure'):
                    raise ValueError('result must be success or failure')
                events.append(item)
            except (ValueError, KeyError, TypeError) as exc:
                raise ValueError(f'line {line_number}: {exc}') from exc
    return events


def analyse(events: list[dict], threshold: int = 5, window_seconds: int = 300) -> dict:
    if threshold < 2 or window_seconds < 1:
        raise ValueError('threshold must be >= 2 and window_seconds must be >= 1')
    groups = defaultdict(list)
    for event in sorted(events, key=lambda row: row['timestamp']):
        groups[event['source_ip']].append(event)
    findings = []
    for source_ip, rows in sorted(groups.items()):
        window = deque()
        peak = []
        for row in (row for row in rows if row['result'] == 'failure'):
            while window and (row['timestamp'] - window[0]['timestamp']).total_seconds() > window_seconds:
                window.popleft()
            window.append(row)
            if len(window) > len(peak):
                peak = list(window)
        if len(peak) < threshold:
            continue
        usernames = sorted({row['username'] for row in peak})
        end = peak[-1]['timestamp']
        subsequent_success = any(
            row['result'] == 'success' and row['username'] in usernames
            and end < row['timestamp'] <= end + timedelta(seconds=window_seconds)
            for row in rows
        )
        findings.append({
            'source_ip': source_ip, 'failure_count': len(peak),
            'window_start': peak[0]['timestamp'].isoformat(), 'window_end': end.isoformat(),
            'usernames': usernames, 'success_after_burst': subsequent_success,
            'interpretation': 'Review the failure burst and surrounding authentication context.',
        })
    return {
        'schema_version': 1,
        'parameters': {'threshold': threshold, 'window_seconds': window_seconds},
        'total_events': len(events),
        'failed_events': sum(row['result'] == 'failure' for row in events),
        'successful_events': sum(row['result'] == 'success' for row in events),
        'findings': findings,
        'limitations': 'Heuristic observations; neither malicious intent nor compromise is established.',
    }


def markdown(report: dict) -> str:
    safe = lambda value: html.escape(str(value)).replace('|', r'\|').replace('\n', ' ')
    rows = ['# Authentication triage report', '',
            f"Events: **{report['total_events']}** · Findings: **{len(report['findings'])}**", '',
            '| Source IP | Failures in window | Usernames | Later success |',
            '| --- | ---: | --- | --- |']
    for finding in report['findings']:
        rows.append(f"| {safe(finding['source_ip'])} | {finding['failure_count']} | "
                    f"{safe(', '.join(finding['usernames']))} | {finding['success_after_burst']} |")
    return '\n'.join(rows + ['', report['limitations'], ''])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path, help='JSONL authentication events')
    parser.add_argument('--threshold', type=int, default=5)
    parser.add_argument('--window', type=int, default=300, help='rolling window in seconds')
    parser.add_argument('--json', dest='json_output', type=Path)
    parser.add_argument('--markdown', type=Path)
    args = parser.parse_args()
    try:
        report = analyse(load_events(args.input), args.threshold, args.window)
        encoded = json.dumps(report, indent=2, ensure_ascii=False) + '\n'
        for target, contents in ((args.json_output, encoded), (args.markdown, markdown(report))):
            if target:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(contents, encoding='utf-8')
        print(encoded, end='')
        return 0
    except (OSError, ValueError) as exc:
        parser.exit(2, f'error: {exc}\n')


if __name__ == '__main__':
    raise SystemExit(main())
