"""Hermetic tests for the v2 prediction adapters and compatible-edge builder.

Fixtures copy the exact format of the published activation evidence (Zeek
8.0.11 + pinned bro-simple-scan notice.log, Snort 3.13.2.0 alert_json) using
the same documentation addresses. One test parses the real published raw
evidence JSON so format drift in these adapters fails loudly. These are format
and contract tests, not detector accuracy results.
"""

import json
import os
import unittest

from research.v2.adapters import compatibility, matching, snort_alert, zeek_notice

REPO = os.path.dirname(os.path.abspath(__file__))
PUBLISHED_EVIDENCE = os.path.join(
    REPO, 'research', 'v2', 'results', 'raw', 'activation-portable-2026-11-13.json')

ZEEK_HEADER = (
    '#separator \\x09\n'
    '#set_separator\t,\n'
    '#empty_field\t(empty)\n'
    '#unset_field\t-\n'
    '#path\tnotice\n'
    '#open\t2026-11-13-03-29-41\n'
    '#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tfuid\tfile_mime_type\t'
    'file_desc\tproto\tnote\tmsg\tsub\tsrc\tdst\tp\tn\tpeer_descr\tactions\temail_dest\t'
    'suppress_for\tremote_location.country_code\tremote_location.region\tremote_location.city\t'
    'remote_location.latitude\tremote_location.longitude\n'
    '#types\ttime\tstring\taddr\tport\taddr\tport\tstring\tstring\tstring\tenum\tenum\tstring\t'
    'string\taddr\taddr\tport\tcount\tstring\tset[enum]\tset[string]\tinterval\tstring\tstring\t'
    'string\tdouble\tdouble\n')
ZEEK_CLOSE = '#close\t2026-11-13-03-29-41\n'


def zeek_row(ts, note, msg, sub='local', src='192.0.2.1', suppress='3600.000000'):
    return ('\t'.join([ts, '-', '-', '-', '-', '-', '-', '-', '-', '-', note, msg, sub, src,
                       '-', '-', '-', '-', 'Notice::ACTION_LOG', '(empty)', suppress,
                       '-', '-', '-', '-', '-']) + '\n')


ZEEK_PORT_SCAN = zeek_row(
    '1700000024.910000', 'Scan::Port_Scan',
    '192.0.2.1 scanned at least 250 unique ports on host 198.51.100.2 in 0m25s')
ZEEK_ADDRESS_SCAN = zeek_row(
    '1700000025.000000', 'Scan::Address_Scan',
    '192.0.2.1 scanned at least 30 unique hosts on port 80/tcp in 1m0s')
ZEEK_RANDOM_SCAN = zeek_row(
    '1700000026.000000', 'Scan::Random_Scan',
    '192.0.2.1 scanned at least 40 hosts on 12 ports in 2m5s')
ZEEK_MULTI_HOST = zeek_row(
    '1700000027.000000', 'Scan::Port_Scan',
    '192.0.2.1 scanned at least 9 unique ports on hosts 198.51.100.2, 198.51.100.3 in 0m10s')
ZEEK_MULTI_PORT = zeek_row(
    '1700000028.000000', 'Scan::Address_Scan',
    '192.0.2.1 scanned at least 7 unique hosts on ports 80/tcp, 443/tcp in 0m10s')
ZEEK_KNOCKKNOCK = zeek_row(
    '1700000029.000000', 'Scan::Address_Scan',
    'kk: 192.0.2.1 scanned at least 21 unique hosts on port 22/tcp in 3m0s')
ZEEK_OTHER_NOTICE = zeek_row(
    '1700000030.000000', 'Scan::OtherThing',
    '192.0.2.1 scanned at least 250 unique ports on host 198.51.100.2 in 0m25s')
ZEEK_UNRELATED = zeek_row(
    '1700000031.000000', 'HTTP::SQL_Injection_Attacker', 'something else entirely')

SNORT_PORT_SCAN = ('{ "timestamp" : "11/14-22:13:21.400000", "seconds" : 1700000001, '
                   '"pkt_num" : 29, "proto" : "TCP", "src_addr" : "192.0.2.1", '
                   '"dst_addr" : "198.51.100.2", "src_port" : 40014, "dst_port" : 1014, '
                   '"gid" : 122, "sid" : 1, "msg" : "(port_scan) TCP portscan" }\n')
SNORT_SWEEP = ('{ "timestamp" : "11/14-22:13:30.000000", "seconds" : 1700000010, '
               '"pkt_num" : 55, "proto" : "TCP", "src_addr" : "192.0.2.1", '
               '"dst_addr" : "198.51.100.9", "src_port" : 40020, "dst_port" : 80, '
               '"gid" : 122, "sid" : 3, "msg" : "(port_scan) TCP portsweep" }\n')
SNORT_UDP = ('{ "timestamp" : "11/14-22:13:40.000000", "seconds" : 1700000020, '
             '"pkt_num" : 60, "proto" : "UDP", "src_addr" : "192.0.2.1", '
             '"dst_addr" : "198.51.100.2", "src_port" : 40021, "dst_port" : 53, '
             '"gid" : 122, "sid" : 17, "msg" : "(port_scan) UDP portscan" }\n')
SNORT_OTHER_GID = ('{ "timestamp" : "11/14-22:13:50.000000", "seconds" : 1700000030, '
                   '"pkt_num" : 61, "proto" : "TCP", "src_addr" : "192.0.2.1", '
                   '"dst_addr" : "198.51.100.2", "src_port" : 40022, "dst_port" : 21, '
                   '"gid" : 1, "sid" : 1000001, "msg" : "(rules) other" }\n')


def vertical_episode(episode_id='ep-v1', capture_id='cap-test', scanner='192.0.2.1',
                     target='198.51.100.2', first=1_700_000_000_000_000_000,
                     last=1_700_000_025_000_000_000, intent='attack'):
    return {'episode_id': episode_id, 'capture_id': capture_id, 'scanner': scanner,
            'intent': intent, 'family': 'vertical_syn', 'target': target,
            'target_port': None, 'first_probe_ns': first, 'last_probe_ns': last}


def horizontal_episode(episode_id='ep-h1', capture_id='cap-test', scanner='192.0.2.1',
                       target_port=80, first=1_700_000_000_000_000_000,
                       last=1_700_000_025_000_000_000, intent='attack'):
    return {'episode_id': episode_id, 'capture_id': capture_id, 'scanner': scanner,
            'intent': intent, 'family': 'horizontal_syn', 'target': None,
            'target_port': target_port, 'first_probe_ns': first, 'last_probe_ns': last}


class ZeekNoticeTests(unittest.TestCase):
    def test_real_format_port_scan(self):
        predictions, ignored = zeek_notice.parse_notice_log(
            ZEEK_HEADER + ZEEK_PORT_SCAN + ZEEK_CLOSE, 'cap-a')
        self.assertEqual(ignored, 0)
        self.assertEqual(len(predictions), 1)
        pred = predictions[0]
        self.assertEqual(pred['engine'], 'zeek')
        self.assertEqual(pred['alert_id'], 'zeek:cap-a:notice.log:L9')
        self.assertEqual(pred['family'], 'generic-scan')
        self.assertEqual(pred['direction'], 'vertical')
        self.assertEqual(pred['scanner'], '192.0.2.1')
        self.assertEqual(pred['target_host'], '198.51.100.2')
        self.assertIsNone(pred['target_port'])
        self.assertEqual(pred['event_time_ns'], 1_700_000_024_910_000_000)
        self.assertIsNone(pred['decision_time_ns'])
        self.assertEqual(pred['qualifiers']['engine_count'], 250)
        self.assertEqual(pred['qualifiers']['engine_duration_s'], 25)
        self.assertEqual(pred['qualifiers']['suppress_for_s'], 3600)
        self.assertFalse(pred['qualifiers']['knockknock'])
        self.assertEqual(pred['qualifiers']['side'], 'local')

    def test_all_documented_shapes(self):
        log = (ZEEK_HEADER + ZEEK_ADDRESS_SCAN + ZEEK_RANDOM_SCAN + ZEEK_MULTI_HOST
               + ZEEK_MULTI_PORT + ZEEK_KNOCKKNOCK + ZEEK_UNRELATED + ZEEK_CLOSE)
        predictions, ignored = zeek_notice.parse_notice_log(log, 'cap-a')
        self.assertEqual(ignored, 1)
        self.assertEqual(len(predictions), 5)
        address, random_scan, multi_host, multi_port, knock = predictions
        self.assertEqual(address['direction'], 'horizontal')
        self.assertEqual(address['target_port'], 80)
        self.assertIsNone(address['target_host'])
        self.assertEqual(random_scan['direction'], 'random')
        self.assertEqual(random_scan['qualifiers']['engine_count'], 40)
        self.assertEqual(multi_host['direction'], 'vertical')
        self.assertEqual(multi_host['target_hosts'], ['198.51.100.2', '198.51.100.3'])
        self.assertEqual(multi_port['direction'], 'horizontal')
        self.assertEqual(multi_port['target_ports'], [80, 443])
        self.assertTrue(knock['qualifiers']['knockknock'])
        self.assertEqual(knock['qualifiers']['engine_duration_s'], 180)

    def test_unknown_scan_msg_raises(self):
        bad = zeek_row('1700000032.000000', 'Scan::Port_Scan', 'an unexpected message')
        with self.assertRaises(zeek_notice.ZeekNoticeError):
            zeek_notice.parse_notice_log(ZEEK_HEADER + bad + ZEEK_CLOSE, 'cap-a')

    def test_unknown_scan_note_is_not_silently_dropped(self):
        # Scan::OtherThing is not a notice the pinned package can emit; it must
        # be ignored by count, never parsed as scan evidence.
        predictions, ignored = zeek_notice.parse_notice_log(
            ZEEK_HEADER + ZEEK_OTHER_NOTICE + ZEEK_CLOSE, 'cap-a')
        self.assertEqual(predictions, [])
        self.assertEqual(ignored, 1)

    def test_note_msg_direction_contradiction_raises(self):
        bad = zeek_row('1700000033.000000', 'Scan::Address_Scan',
                       '192.0.2.1 scanned at least 250 unique ports on host 198.51.100.2 in 0m25s')
        with self.assertRaises(zeek_notice.ZeekNoticeError):
            zeek_notice.parse_notice_log(ZEEK_HEADER + bad + ZEEK_CLOSE, 'cap-a')

    def test_src_msg_contradiction_raises(self):
        bad = zeek_row('1700000034.000000', 'Scan::Port_Scan',
                       '203.0.113.9 scanned at least 250 unique ports on host 198.51.100.2 in 0m25s')
        with self.assertRaises(zeek_notice.ZeekNoticeError):
            zeek_notice.parse_notice_log(ZEEK_HEADER + bad + ZEEK_CLOSE, 'cap-a')

    def test_missing_header_and_column_mismatch_raise(self):
        with self.assertRaises(zeek_notice.ZeekNoticeError):
            zeek_notice.parse_notice_log(ZEEK_PORT_SCAN, 'cap-a')
        truncated = ZEEK_HEADER + '1700000024.910000\tonly-two\n'
        with self.assertRaises(zeek_notice.ZeekNoticeError):
            zeek_notice.parse_notice_log(truncated, 'cap-a')

    def test_exact_fractional_seconds(self):
        predictions, _ = zeek_notice.parse_notice_log(
            ZEEK_HEADER + zeek_row('1700000024.000001', 'Scan::Port_Scan',
                                   '192.0.2.1 scanned at least 250 unique ports on host 198.51.100.2 in 0m25s')
            + ZEEK_CLOSE, 'cap-a')
        self.assertEqual(predictions[0]['event_time_ns'], 1_700_000_024_000_001_000)


class SnortAlertTests(unittest.TestCase):
    def test_real_format_port_scan(self):
        predictions, ignored = snort_alert.parse_alert_json(SNORT_PORT_SCAN, 'cap-a')
        self.assertEqual(ignored, 0)
        self.assertEqual(len(predictions), 1)
        pred = predictions[0]
        self.assertEqual(pred['engine'], 'snort')
        self.assertEqual(pred['alert_id'], 'snort:cap-a:alert_json.txt:L1:pkt29')
        self.assertEqual(pred['direction'], 'vertical')
        self.assertEqual(pred['scanner'], '192.0.2.1')
        self.assertEqual(pred['target_host'], '198.51.100.2')
        self.assertEqual(pred['event_time_ns'], 1_700_000_001_400_000_000)
        self.assertEqual(pred['qualifiers']['sid'], 1)
        self.assertEqual(pred['qualifiers']['trigger_pkt_num'], 29)

    def test_sweep_udp_and_other_gid(self):
        predictions, ignored = snort_alert.parse_alert_json(
            SNORT_SWEEP + SNORT_UDP + SNORT_OTHER_GID, 'cap-a')
        self.assertEqual(ignored, 1)
        self.assertEqual(len(predictions), 2)
        sweep, udp = predictions
        self.assertEqual(sweep['direction'], 'horizontal')
        self.assertEqual(sweep['target_port'], 80)
        self.assertEqual(sweep['qualifiers']['trigger_dst_addr'], '198.51.100.9')
        self.assertEqual(udp['direction'], 'vertical')
        self.assertEqual(udp['event_time_ns'], 1_700_000_020_000_000_000)

    def test_unknown_sid_msg_proto_and_shape_raise(self):
        unknown_sid = SNORT_PORT_SCAN.replace('"sid" : 1', '"sid" : 99')
        with self.assertRaises(snort_alert.SnortAlertError):
            snort_alert.parse_alert_json(unknown_sid, 'cap-a')
        wrong_msg = SNORT_PORT_SCAN.replace('TCP portscan', 'TCP portsweep')
        with self.assertRaises(snort_alert.SnortAlertError):
            snort_alert.parse_alert_json(wrong_msg, 'cap-a')
        wrong_proto = SNORT_PORT_SCAN.replace('"proto" : "TCP"', '"proto" : "UDP"')
        with self.assertRaises(snort_alert.SnortAlertError):
            snort_alert.parse_alert_json(wrong_proto, 'cap-a')
        with self.assertRaises(snort_alert.SnortAlertError):
            snort_alert.parse_alert_json('not json\n', 'cap-a')
        with self.assertRaises(snort_alert.SnortAlertError):
            snort_alert.parse_alert_json('{"gid": 122}\n', 'cap-a')


class CompatibilityTests(unittest.TestCase):
    def zeek_vertical(self, event_time_ns=1_700_000_024_910_000_000, scanner='192.0.2.1',
                      target='198.51.100.2', alert_id='zeek:cap-test:notice.log:L9'):
        return {'engine': 'zeek', 'capture_id': 'cap-test',
                'alert_id': alert_id, 'family': 'generic-scan',
                'direction': 'vertical', 'scanner': scanner, 'target_host': target,
                'target_hosts': None, 'target_port': None, 'target_ports': None,
                'event_time_ns': event_time_ns, 'decision_time_ns': None,
                'qualifiers': {}, 'evidence_reference': 'x', 'raw_record_reference': 'x'}

    def test_within_delayed_early(self):
        episode = vertical_episode()
        within = self.zeek_vertical(event_time_ns=1_700_000_010_000_000_000)
        delayed = dict(within, alert_id='a-delayed', event_time_ns=1_700_000_040_000_000_000)
        early = dict(within, alert_id='a-early', event_time_ns=1_699_999_999_000_000_000)
        result = compatibility.build_candidates([episode], [within, delayed, early])
        self.assertEqual(len(result['candidates']), 2)
        by_alert = {c['alert_id']: c for c in result['candidates']}
        self.assertEqual(by_alert[within['alert_id']]['timing_class'], 'within')
        self.assertEqual(by_alert[within['alert_id']]['distance_ns'], 0)
        self.assertEqual(by_alert['a-delayed']['timing_class'], 'delayed')
        self.assertEqual(by_alert['a-delayed']['distance_ns'], 15_000_000_000)
        self.assertEqual(result['rejects'],
                         [{'episode_id': 'ep-v1', 'alert_id': 'a-early',
                           'reason': 'alert-before-episode'}])

    def test_wrong_scanner_capture_target_direction(self):
        episode = vertical_episode()
        wrong_scanner = self.zeek_vertical(scanner='192.0.2.99', alert_id='a-scan')
        wrong_capture = dict(self.zeek_vertical(), capture_id='cap-other',
                             alert_id='a-cap')
        wrong_target = self.zeek_vertical(target='198.51.100.44', alert_id='a-tgt')
        horizontal_pred = dict(self.zeek_vertical(), direction='horizontal',
                               target_host=None, target_port=1014, alert_id='a-dir')
        result = compatibility.build_candidates(
            [episode], [wrong_scanner, wrong_capture, wrong_target, horizontal_pred])
        self.assertEqual(result['candidates'], [])
        reasons = {(r['alert_id'], r['reason']) for r in result['rejects']}
        self.assertEqual(reasons, {('a-tgt', 'target-mismatch'),
                                   ('a-dir', 'direction-mismatch')})
        self.assertEqual(result['gate_failures'][wrong_scanner['alert_id']]['scanner'], 1)
        self.assertEqual(result['gate_failures']['a-cap']['capture'], 1)

    def test_horizontal_and_random_aggregate(self):
        episode = horizontal_episode()
        sweep = {'engine': 'snort', 'capture_id': 'cap-test', 'alert_id': 'a-sweep',
                 'family': 'generic-scan', 'direction': 'horizontal',
                 'scanner': '192.0.2.1', 'target_host': None, 'target_hosts': None,
                 'target_port': 80, 'target_ports': None,
                 'event_time_ns': 1_700_000_010_000_000_000, 'decision_time_ns': None,
                 'qualifiers': {}, 'evidence_reference': 'x', 'raw_record_reference': 'x'}
        random_pred = dict(sweep, alert_id='a-random', direction='random',
                           target_port=None)
        result = compatibility.build_candidates([episode], [sweep, random_pred])
        by_alert = {c['alert_id']: c for c in result['candidates']}
        self.assertEqual(by_alert['a-sweep']['edge_class'], 'engine-direction')
        self.assertEqual(by_alert['a-random']['edge_class'], 'random-aggregate')

    def test_unsupported_direction_yields_no_candidates(self):
        episode = vertical_episode()
        distributed = dict(self.zeek_vertical(), direction='distributed',
                           alert_id='a-dist')
        result = compatibility.build_candidates(
            [episode], [distributed])
        self.assertEqual(result['candidates'], [])
        self.assertEqual(result['gate_failures']['a-dist'], {'unsupported-direction': 1})

    def test_intent_and_group_evidence_recorded(self):
        benign = vertical_episode(episode_id='ep-benign', intent='benign')
        blind = dict(self.zeek_vertical(), target_host=None, target_hosts=None)
        result = compatibility.build_candidates([benign], [blind])
        self.assertEqual(len(result['candidates']), 1)
        candidate = result['candidates'][0]
        self.assertEqual(candidate['intent'], 'benign')
        self.assertEqual(candidate['group_evidence'], 'unknown-group')

    def test_validation_errors(self):
        with self.assertRaises(compatibility.CompatibilityError):
            compatibility.build_candidates([vertical_episode(target=None)], [])
        with self.assertRaises(compatibility.CompatibilityError):
            compatibility.build_candidates([vertical_episode(intent='unknown')], [])
        bad_pred = self.zeek_vertical()
        bad_pred['event_time_ns'] = 1.5
        with self.assertRaises(compatibility.CompatibilityError):
            compatibility.build_candidates([vertical_episode()], [bad_pred])

    def test_matching_integration_picks_nearest_delayed(self):
        # Two episodes separated by more than W; a delayed alert between them
        # must match the nearer interval, and a duplicate alert stays unmatched.
        first = vertical_episode(episode_id='ep-1', last=1_700_000_025_000_000_000)
        second = vertical_episode(episode_id='ep-2', first=1_700_000_400_000_000_000,
                                  last=1_700_000_425_000_000_000)
        delayed = self.zeek_vertical(event_time_ns=1_700_000_040_000_000_000)
        duplicate = dict(delayed, alert_id='a-dup')
        episodes = [first, second]
        predictions = [delayed, duplicate]
        built = compatibility.build_candidates(episodes, predictions)
        episode_ids, alert_ids, edges = compatibility.matching_input(
            episodes, predictions, built['candidates'])
        result = matching.match_candidates(episode_ids, alert_ids, edges)
        # Both alerts are 15s from ep-1 and 360s from ep-2; one matches ep-1,
        # the other is duplicate burden and remains unmatched.
        self.assertEqual(result['cardinality'], 1)
        self.assertEqual(result['pairs'], [('ep-1', 'a-dup')])
        self.assertEqual(result['unmatched_episodes'], ['ep-2'])
        self.assertEqual(result['unmatched_alerts'], ['zeek:cap-test:notice.log:L9'])


class PublishedEvidenceTests(unittest.TestCase):
    def test_adapters_parse_real_published_activation_outputs(self):
        with open(PUBLISHED_EVIDENCE) as handle:
            evidence = json.load(handle)
        raw = evidence['raw_text']
        predictions, ignored = zeek_notice.parse_notice_log(
            raw['zeek-positive/notice.log'], 'activation-positive')
        self.assertEqual(ignored, 0)
        self.assertEqual(len(predictions), 1)
        pred = predictions[0]
        self.assertEqual(pred['direction'], 'vertical')
        self.assertEqual(pred['scanner'], '192.0.2.1')
        self.assertEqual(pred['target_host'], '198.51.100.2')
        self.assertEqual(pred['qualifiers']['engine_count'], 250)

        predictions, ignored = snort_alert.parse_alert_json(
            raw['snort-positive/alert_json.txt'], 'activation-positive')
        self.assertEqual(ignored, 0)
        self.assertEqual(len(predictions), 1)
        self.assertEqual(predictions[0]['direction'], 'vertical')
        self.assertEqual(predictions[0]['qualifiers']['sid'], 1)

        for name in ('zeek-negative/notice.log',):
            if raw.get(name):
                parsed, _ = zeek_notice.parse_notice_log(raw[name], 'activation-negative')
                self.assertEqual(parsed, [])
        self.assertEqual(raw['snort-negative/alert_json.txt'], '')


if __name__ == '__main__':
    unittest.main()
