"""Synthetic captures and malformed byte fixtures only."""
import contextlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
import make_demo as demo
import workbench as wb


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'test.pcap'
    def write(self,frames,**kw):
        self.path.write_bytes(demo.capture(frames,**kw))
    def run_report(self,**kw):
        return wb.investigate(self.path,**kw)
    def test_four_magic_variants(self):
        for order in ('<','>'):
            for nano in (False,True):
                self.write([demo.tcp_frame(443)],order=order,nano=nano)
                self.assertEqual(self.run_report()['stats']['decoded_packets'],1)
    def test_synthetic_demo(self):
        self.write([demo.tcp_frame(p) for p in range(20,32)]+[demo.dns_frame()])
        r=self.run_report()
        self.assertEqual(r['stats']['decoded_packets'],13)
        self.assertEqual(r['stats']['dns_questions'],1)
        self.assertEqual(len(r['alerts']),1)
        self.assertEqual(r['alerts'][0]['distinct_destination_ports'],10)
    def test_below_threshold(self):
        self.write([demo.tcp_frame(p) for p in range(9)])
        self.assertEqual(self.run_report()['alerts'],[])
    def test_repeated_port_not_scan(self):
        self.write([demo.tcp_frame(443)]*20)
        self.assertEqual(self.run_report()['alerts'],[])
        self.assertEqual(self.run_report()['top_flows'][0]['packets'],20)
    def test_syn_ack_not_scan(self):
        self.write([demo.tcp_frame(p,18) for p in range(12)])
        self.assertEqual(self.run_report()['alerts'],[])
    def test_window_expires(self):
        self.write([demo.tcp_frame(p) for p in range(12)])
        self.assertEqual(self.run_report(window=2)['alerts'],[])
    def test_inclusive_window(self):
        self.write([demo.tcp_frame(p) for p in range(10)])
        self.assertEqual(len(self.run_report(window=9)['alerts']),1)
    def test_redaction(self):
        self.write([demo.tcp_frame(p) for p in range(12)]+[demo.dns_frame()])
        r=self.run_report();text=json.dumps(r)
        for private in ('192.0.2.10','198.51.100.20','demo.test'):
            self.assertNotIn(private,text)
        self.assertEqual(r['alerts'][0]['source'],r['top_flows'][0]['source'])
        self.assertNotEqual(r['alerts'][0]['source'],self.run_report()['alerts'][0]['source'])
    def test_flow_sort(self):
        self.write([demo.tcp_frame(443)]*3+[demo.tcp_frame(80)])
        self.assertEqual(self.run_report()['top_flows'][0]['target_port'],443)
    def test_packet_limit(self):
        self.write([demo.tcp_frame(443)]*2)
        self.assertTrue(self.run_report(max_packets=1)['notices'])
        self.assertEqual(self.run_report(max_packets=2)['notices'],[])
    def test_byte_limit(self):
        self.write([demo.tcp_frame(443)])
        self.assertTrue(self.run_report(max_bytes=24)['notices'])
    def test_truncated_record(self):
        self.write([demo.tcp_frame(443)])
        self.path.write_bytes(self.path.read_bytes()[:-1])
        self.assertTrue(self.run_report()['notices'])
    def test_short_record_header(self):
        self.write([]);self.path.write_bytes(self.path.read_bytes()+b'\x00')
        self.assertTrue(self.run_report()['notices'])
    def test_invalid_record_metadata(self):
        self.write([])
        self.path.write_bytes(self.path.read_bytes()+struct.pack('<4I',0,1000000,1,1)+b'x')
        self.assertTrue(self.run_report()['notices'])
    def test_header_rejection(self):
        self.path.write_bytes(b'not a capture')
        with self.assertRaises(ValueError): self.run_report()
        self.write([]);data=bytearray(self.path.read_bytes());data[20:24]=struct.pack('<I',101);self.path.write_bytes(data)
        with self.assertRaises(ValueError): self.run_report()
    def test_invalid_limits(self):
        for kwargs in ({'window':0},{'ports':1},{'max_packets':0},{'max_bytes':1}):
            with self.assertRaises(ValueError): self.run_report(**kwargs)
    def test_skip_malformed_and_unsupported(self):
        self.write([b'x',b'\0'*14,demo.frame(1,b'\0'*8)])
        r=self.run_report()
        self.assertEqual(r['stats']['decoded_packets'],0)
        self.assertEqual(sum(r['stats']['skipped_by_reason'].values()),3)
    def test_vlan(self):
        f=demo.tcp_frame(443);vlan=f[:12]+b'\x81\x00\x00\x01\x08\x00'+f[14:]
        self.write([vlan]);self.assertEqual(self.run_report()['stats']['decoded_packets'],1)
    def test_fragment_skipped(self):
        f=bytearray(demo.tcp_frame(443));f[20:22]=struct.pack('!H',0x2000)
        self.write([bytes(f)])
        self.assertEqual(self.run_report()['stats']['skipped_by_reason'],{'fragmented-ipv4':1})
    def test_bad_tcp_length(self):
        f=bytearray(demo.tcp_frame(443));f[46]=0xf0
        self.write([bytes(f)])
        self.assertEqual(self.run_report()['stats']['skipped_by_reason'],{'malformed-tcp':1})
    def test_dns_bounds(self):
        for data in (b'',b'\0'*12,b'\0'*4+b'\0\1'+b'\0'*6+b'\xc0\x00',b'\0'*4+b'\0\1'+b'\0'*6+b'\x40'+b'x'*64):
            self.assertIsNone(wb.dns_question(data))
    def test_cli_exit_codes(self):
        self.write([])
        with contextlib.redirect_stdout(io.StringIO()):self.assertEqual(wb.main([str(self.path)]),0)
        self.write([demo.tcp_frame(p) for p in range(12)])
        out=io.StringIO()
        with contextlib.redirect_stdout(out):self.assertEqual(wb.main([str(self.path),'--format','json']),1)
        self.assertEqual(json.loads(out.getvalue())['stats']['capture_records'],12)
        with contextlib.redirect_stdout(io.StringIO()):self.assertEqual(wb.main([str(self.path),'--max-packets','1']),2)
        with contextlib.redirect_stderr(io.StringIO()):self.assertEqual(wb.main([str(self.path)+'missing']),2)
    def test_demo_refuses_overwrite(self):
        self.path.write_bytes(b'private-capture')
        with self.assertRaises(FileExistsError):demo.main([str(self.path)])
        self.assertEqual(self.path.read_bytes(),b'private-capture')
    def test_demo_generator(self):
        with contextlib.redirect_stdout(io.StringIO()):demo.main([str(self.path)])
        self.assertEqual(self.run_report()['stats']['capture_records'],13)


if __name__=='__main__':unittest.main()
