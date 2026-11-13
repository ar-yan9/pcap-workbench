"""Hermetic activation-runner checks. No installed engines, privileges or traffic."""
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent


def load(name, path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner=load('activate_baselines',ROOT/'research/v2/runners/activate_baselines.py')
generator=load('activation_controls',ROOT/'research/v2/generators/activation_controls.py')


class GenerationTests(unittest.TestCase):
    def test_deterministic_and_hashes(self):
        with tempfile.TemporaryDirectory() as td:
            first=generator.generate(Path(td)/'one')
            second=generator.generate(Path(td)/'two')
            self.assertEqual(first,second)
            self.assertEqual(first['positive']['packets'],600)
            self.assertEqual(first['negative']['packets'],64)
            self.assertEqual(first['positive']['sha256'],'444641f7d8b70237b4487c9775a437e649b98224d18927458e1e6db46723ba8e')
            self.assertEqual(first['negative']['sha256'],'f1babb767bff24579996482bbbc9f08bdda9a1520da13f58dd82c640a02cc72d')

    def test_every_packet_checksum(self):
        with tempfile.TemporaryDirectory() as td:
            generator.generate(Path(td))
            for kind,count in [('positive',600),('negative',64)]:
                raw=(Path(td)/(kind+'.pcap')).read_bytes()
                self.assertEqual(struct.unpack_from('<I',raw,20)[0],1)
                offset,seen=24,0
                while offset<len(raw):
                    _,_,caplen,wirelen=struct.unpack_from('<IIII',raw,offset)
                    self.assertEqual(caplen,wirelen)
                    packet=raw[offset+16:offset+16+caplen]
                    ip,tcp=packet[14:34],packet[34:]
                    self.assertEqual(generator.checksum(ip),0)
                    self.assertEqual(generator.checksum(ip[12:20]+struct.pack('!BBH',0,6,len(tcp))+tcp),0)
                    offset+=16+caplen
                    seen+=1
                self.assertEqual(seen,count)
                self.assertEqual(offset,len(raw))

    def test_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as td:
            generator.generate(Path(td))
            before=(Path(td)/'positive.pcap').read_bytes()
            with self.assertRaises(FileExistsError):generator.generate(Path(td))
            self.assertEqual((Path(td)/'positive.pcap').read_bytes(),before)

    @unittest.skipUnless(os.name == 'posix', 'symlink creation may require Windows privileges')
    def test_refuses_symlink_output_file(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            (root/'victim').write_text('keep')
            (root/'positive.pcap').symlink_to(root/'victim')
            with self.assertRaises(FileExistsError):generator.generate(root)
            self.assertEqual((root/'victim').read_text(),'keep')


class AuditTests(unittest.TestCase):
    def test_checksums_pass(self):
        self.assertEqual(runner.checksum_audit('1\t1\t1\n2\t1\t1\n',2)['tcp_good'],2)

    def test_checksums_reject_partial_or_bad(self):
        for text in ['1\t1\t1\n','1\t1\t1\n2\t0\t1\n','1\t1\t1\n2\t\t1\n','1\t1\t1\n3\t1\t1\n']:
            with self.subTest(text=text),self.assertRaises(ValueError):runner.checksum_audit(text,2)

    def test_versions_are_exact(self):
        for name,text in [('zeek','zeek version 8.0.11'),('tshark','TShark (Wireshark) 3.6.2'),('snort','Version 3.13.2.0\nUsing DAQ version 3.0.29.0')]:
            runner.require_version(name,text)
        for name,text in [('zeek','zeek version 8.0.110'),('zeek','zeek version 8.0.11-dev'),('tshark','TShark (Wireshark) 3.6.20'),('snort','Version 3.13.2.0-dev\nUsing DAQ version 3.0.29.0'),('snort','Version 3.13.2.0\nUsing DAQ version 2.0.7.0')]:
            with self.subTest(name=name),self.assertRaises(ValueError):runner.require_version(name,text)

    def test_zeek_header_and_close_required(self):
        for text in ['x\ty\n','#fields\tx\ty\n1\t2\n','#fields\tx\ty\n1\n#close\t2026\n']:
            with tempfile.TemporaryDirectory() as td:
                p=Path(td)/'test.log';p.write_text(text)
                with self.assertRaises(ValueError):runner.read_zeek(p)

    def test_zeek_reads_dynamic_columns(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'test.log';p.write_text('#fields\ty\tx\n2\t1\n#close\t2026\n')
            self.assertEqual(runner.read_zeek(p),[{'y':'2','x':'1'}])

    def test_zeek_control_checks(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)
            (p/'conn.log').write_text('#fields\torig_pkts\tresp_pkts\n300\t300\n#close\t2026\n')
            notice='#fields\tnote\tsrc\tmsg\nScan::Port_Scan\t192.0.2.1\tscanned 198.51.100.2\n#close\t2026\n'
            (p/'notice.log').write_text(notice)
            self.assertEqual(runner.check_zeek(p,600,True)['scan_alerts'],1)
            with self.assertRaises(ValueError):runner.check_zeek(p,601,True)
            with self.assertRaises(ValueError):runner.check_zeek(p,600,False)
            (p/'notice.log').write_text(notice.replace('192.0.2.1','192.0.2.99'))
            with self.assertRaises(ValueError):runner.check_zeek(p,600,True)

    def test_zeek_missing_positive_is_not_success(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)
            (p/'conn.log').write_text('#fields\torig_pkts\tresp_pkts\n32\t32\n#close\t2026\n')
            self.assertEqual(runner.check_zeek(p,64,False)['scan_alerts'],0)
            with self.assertRaises(ValueError):runner.check_zeek(p,64,True)

    def make_snort(self,p,count=600):
        # Real Snort reports an analyzed counter in both DAQ and detection.
        (p/'run.stdout').write_text('daq\n received: %d\n analyzed: %d\n-----\ndetection\n analyzed: %d\n-----\nport_scan\n packets: %d\n'%(count,count,count,count))
        (p/'alert_json.txt').write_text(json.dumps({'gid':122,'sid':1,'src_addr':'192.0.2.1','dst_addr':'198.51.100.2'})+'\n')

    def test_snort_scopes_packet_counters(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);self.make_snort(p)
            self.assertEqual(runner.check_snort(p,600,True)['analyzed'],600)

    def test_snort_rejects_wrong_count_or_module(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);self.make_snort(p)
            with self.assertRaises(ValueError):runner.check_snort(p,601,True)
            (p/'run.stdout').write_text((p/'run.stdout').read_text().replace('port_scan','not_enabled'))
            with self.assertRaises(ValueError):runner.check_snort(p,600,True)

    def test_snort_negative_requires_clean_alerts(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);self.make_snort(p,64)
            with self.assertRaises(ValueError):runner.check_snort(p,64,False)
            (p/'alert_json.txt').unlink()
            self.assertEqual(runner.check_snort(p,64,False)['scan_alerts'],0)
            (p/'alert_json.txt').write_text('{"gid": 116, "sid": 1}\n')
            with self.assertRaises(ValueError):runner.check_snort(p,64,False)

    def test_snort_missing_positive_and_bad_json_fail(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);self.make_snort(p)
            (p/'alert_json.txt').unlink()
            with self.assertRaises(ValueError):runner.check_snort(p,600,True)
            (p/'alert_json.txt').write_text('truncated {')
            with self.assertRaises(ValueError):runner.check_snort(p,600,True)


@unittest.skipUnless(os.name == 'posix', 'POSIX process groups are required by the engine runner')
class ProcessTests(unittest.TestCase):
    def test_nonzero_exit_logs_preserved(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)
            result=runner.run_command([sys.executable,'-c','import sys;print("failed");sys.exit(3)'],p,os.environ.copy(),'run',5)
            self.assertEqual(result['exit_code'],3)
            self.assertFalse(result['timed_out'])
            self.assertEqual((p/'run.stdout').read_text(),'failed\n')

    def test_timeout_is_failure(self):
        with tempfile.TemporaryDirectory() as td:
            result=runner.run_command([sys.executable,'-c','import time;time.sleep(5)'],Path(td),os.environ.copy(),'run',0.1)
            self.assertTrue(result['timed_out'])
            self.assertNotEqual(result['exit_code'],0)

    def test_failed_provisioning_leaves_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);result=runner.execute(p/'absent',p/'no-sources',p/'output')
            self.assertEqual(result['status'],'failed')
            self.assertTrue((p/'output/run-manifest.json').exists())
            self.assertIn('FileNotFoundError',result['error'])

    def test_existing_output_not_touched(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);(p/'keep').write_text('old')
            with self.assertRaises(FileExistsError):runner.execute(p,p,p)
            self.assertEqual((p/'keep').read_text(),'old')
            self.assertFalse((p/'run-manifest.json').exists())


if __name__=='__main__':
    unittest.main()
