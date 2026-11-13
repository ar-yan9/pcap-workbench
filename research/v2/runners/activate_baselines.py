#!/usr/bin/env python3
"""Offline baseline activation only. No network traffic or accuracy claims.

POSIX runner (Linux provisioned/tested). Requires a provisioned prefix with Zeek 8.0.11, Snort 3.13.2.0/LibDAQ 3.0.29,
and TShark 3.6.2, plus the pinned scanner source checkouts. Does not install them.
Run outputs/captures stay local. A fresh output directory is mandatory.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

PINS = {
    'bro-simple-scan': '35cf19cf64ba9f9989022a56dce0c8ad6ae2f3f2',
    'bro-is-darknet': '7564a8f2035aa62359199b64086ff14749f35f73',
}


def utc():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def run_command(argv, cwd, env, stem, timeout=60):
    """No shell; kill the full child process group on timeout; retain all logs."""
    require(os.name == 'posix', 'engine execution requires POSIX process groups')
    start = utc()
    before = time.monotonic()
    timed_out = False
    with (cwd / (stem + '.stdout')).open('xb') as out, (cwd / (stem + '.stderr')).open('xb') as err:
        with subprocess.Popen([str(a) for a in argv], cwd=cwd, env=env,
                              stdout=out, stderr=err, start_new_session=True) as process:
            try:
                rc = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                rc = process.wait()
    return {'argv': [str(a) for a in argv], 'start_utc': start, 'end_utc': utc(),
            'elapsed_seconds': time.monotonic() - before, 'exit_code': rc,
            'timed_out': timed_out, 'stdout': stem + '.stdout', 'stderr': stem + '.stderr'}


def read_zeek(path):
    """Parse Zeek ASCII using its own field header. Missing/truncated logs fail."""
    fields = None
    records = []
    closed = False
    for line in Path(path).read_text().splitlines():
        if line.startswith('#fields\t'):
            fields = line.split('\t')[1:]
        elif line.startswith('#close\t'):
            closed = True
        elif not line.startswith('#') and line:
            require(fields is not None, 'Zeek record before fields')
            values = line.split('\t')
            require(len(values) == len(fields), 'Zeek column mismatch')
            records.append(dict(zip(fields, values)))
    require(fields is not None and closed, 'Zeek log missing header/close')
    return records


def checksum_audit(text, expected_packets):
    lines = text.splitlines()
    require(len(lines) == expected_packets, 'checksum audit packet count mismatch')
    for n, line in enumerate(lines, 1):
        require(line.split('\t') == [str(n), '1', '1'],
                'bad, missing or unverified checksum at packet %d' % n)
    return {'packets': expected_packets, 'ipv4_good': expected_packets,
            'tcp_good': expected_packets}


def check_zeek(directory, expected_packets, positive):
    connections = read_zeek(directory / 'conn.log')
    total = sum(int(c['orig_pkts']) + int(c['resp_pkts']) for c in connections)
    require(total == expected_packets, 'Zeek did not account for every control packet')
    notice_path = directory / 'notice.log'
    notices = read_zeek(notice_path) if notice_path.exists() else []
    scans = [r for r in notices if r.get('note', '').startswith('Scan::')]
    require(len(scans) == (1 if positive else 0), 'unexpected Zeek scan count')
    if positive:
        require(scans[0].get('note') == 'Scan::Port_Scan', 'wrong Zeek scan kind')
        require(scans[0].get('src') == '192.0.2.1', 'wrong Zeek scanner')
        require('198.51.100.2' in scans[0].get('msg', ''), 'wrong Zeek target')
    return {'connections': len(connections), 'accounted_packets': total,
            'scan_alerts': len(scans), 'scan_records': scans}


def check_snort(directory, expected_packets, positive):
    text = (directory / 'run.stdout').read_text()
    daq = re.search(r'^daq\s*\n(.*?)(?=^-{3,}|\Z)', text, re.M | re.S)
    require(daq is not None, 'Snort DAQ statistics missing')
    received = re.findall(r'^\s*received:\s+(\d+)\s*$', daq[1], re.M)
    analyzed = re.findall(r'^\s*analyzed:\s+(\d+)\s*$', daq[1], re.M)
    require(received == [str(expected_packets)] and analyzed == [str(expected_packets)],
            'Snort packet accounting incomplete or ambiguous')
    require(re.search(r'^port_scan\s*$', text, re.M) is not None,
            'Snort port_scan module statistics missing')
    path = directory / 'alert_json.txt'
    alerts = [json.loads(line) for line in path.read_text().splitlines() if line.strip()] if path.exists() else []
    scans = [r for r in alerts if r.get('gid') == 122]
    require(len(scans) == (1 if positive else 0), 'unexpected Snort scan count')
    # Other decoder/inspector alerts indicate a fixture or setup problem, not success.
    require(len(alerts) == len(scans), 'unexpected non-scan control alerts')
    if positive:
        require(scans[0].get('sid') == 1 and scans[0].get('src_addr') == '192.0.2.1'
                and scans[0].get('dst_addr') == '198.51.100.2', 'wrong Snort scan identity')
    return {'received': expected_packets, 'analyzed': expected_packets,
            'scan_alerts': len(scans), 'scan_records': scans}


def require_version(name, text):
    patterns = {'zeek': r'\bversion 8\.0\.11(?=\s|$)',
                'snort': r'\bVersion 3\.13\.2\.0(?=\s|$)',
                'tshark': r'TShark \(Wireshark\) 3\.6\.2(?=\s|$)'}
    require(re.search(patterns[name], text) is not None, 'wrong version for ' + name)
    if name == 'snort':
        require(re.search(r'Using DAQ version 3\.0\.29\.0(?=\s|$)', text) is not None,
                'wrong LibDAQ version')


def execute(prefix, sources, output, timeout=60):
    prefix, sources, output = prefix.resolve(), sources.resolve(), output.absolute()
    require(timeout > 0, 'timeout must be positive')
    # Zeek's @load directives use token paths, so fail explicitly rather than
    # silently loading the wrong scripts from an unusual checkout path.
    require(not any(c.isspace() or c in '\"' for c in str(sources)),
            'scanner source path must not contain whitespace or quotes')
    # mkdir without exist_ok protects old runs, symlinks and accidental root reuse.
    output.mkdir(parents=False, exist_ok=False)
    manifest = {'purpose': 'activation controls only, not research accuracy/performance',
                'status': 'running', 'start_utc': utc(), 'commands': [], 'checks': {},
                'source_revision': None}
    try:
        env = os.environ.copy()
        env['LD_LIBRARY_PATH'] = os.pathsep.join([str(prefix/'usr/lib/x86_64-linux-gnu'),
                                                str(prefix/'lib')])
        zeekroot = prefix/'opt/zeek/share/zeek'
        env['ZEEKPATH'] = os.pathsep.join([str(zeekroot), str(zeekroot/'policy'),
                                         str(zeekroot/'site'), str(zeekroot/'builtin-plugins')])
        env['TZ'] = 'UTC'
        # Do not load unspecified local/user scripts from the caller's environment.
        env.pop('ZEEK_SCRIPT_PREFIXES', None)
        env.pop('ZEEK_PLUGIN_PATH', None)
        binaries = {'zeek': prefix/'opt/zeek/bin/zeek', 'snort': prefix/'bin/snort',
                    'tshark': prefix/'usr/bin/tshark'}
        manifest['binary_sha256'] = {name: digest(path) for name,path in binaries.items()}
        here = Path(__file__).resolve()
        manifest['runner_sha256'] = digest(here)
        generator = here.parents[1]/'generators/activation_controls.py'
        manifest['generator_sha256'] = digest(generator)
        source = subprocess.check_output(['git','-C',str(here.parents[3]),'rev-parse','HEAD'],text=True).strip()
        manifest['source_revision'] = source
        manifest['source_dirty'] = bool(subprocess.check_output(
            ['git','-C',str(here.parents[3]),'status','--porcelain'],text=True))
        manifest['scanner_pins'] = {}
        for name, commit in PINS.items():
            path = sources/name
            head = subprocess.check_output(['git','-C',str(path),'rev-parse','HEAD'], text=True).strip()
            require(head == commit, 'wrong scanner pin: '+name)
            dirty = subprocess.check_output(['git','-C',str(path),'status','--porcelain','--untracked-files=all'],text=True)
            require(not dirty, 'dirty scanner checkout: '+name)
            manifest['scanner_pins'][name] = head
        for name, binary in binaries.items():
            command = run_command([binary, '-V' if name=='snort' else '--version'],
                                  output, env, 'version-'+name, timeout)
            manifest['commands'].append(command)
            require(command['exit_code']==0 and not command['timed_out'], 'version probe failed: '+name)
            text = (output/command['stdout']).read_text()+(output/command['stderr']).read_text()
            require_version(name,text)
        spec = importlib.util.spec_from_file_location('activation_controls',generator)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        controls = module.generate(output/'pcaps')
        manifest['corpus'] = controls
        # Load dependency first, so package's fallback @load does not depend on zkg layout.
        policy = output/'scanner.zeek'
        policy.write_text('@load '+str(sources/'bro-is-darknet/scripts')+'\n@load '+
                          str(sources/'bro-simple-scan/scripts')+'\n')
        require('"' not in str(prefix) and '\n' not in str(prefix), 'unsupported prefix path')
        config = output/'snort.lua'
        config.write_text('include '+json.dumps(str(prefix/'etc/snort/snort.lua'))+'\n'+
                          'ips.enable_builtin_rules = true\n'+
                          "alert_json = { file = true, fields = 'timestamp seconds pkt_num proto src_addr dst_addr src_port dst_port gid sid msg' }\n")
        manifest['config_sha256'] = {'zeek_loader':digest(policy),'snort_control':digest(config),
                                   'snort_defaults':digest(prefix/'etc/snort/snort_defaults.lua'),
                                   'snort_main':digest(prefix/'etc/snort/snort.lua')}
        validate = run_command([binaries['snort'],'--daq-dir',prefix/'lib/daq','-T','-c',config],
                               output,env,'validate-snort',timeout)
        manifest['commands'].append(validate)
        require(validate['exit_code']==0 and not validate['timed_out'], 'Snort validation failed')
        for kind in ['positive','negative']:
            capture = output/'pcaps'/controls[kind]['filename']
            count = controls[kind]['packets']
            audit = run_command([binaries['tshark'],'-r',capture,'-o','tcp.check_checksum:TRUE',
                                 '-o','ip.check_checksum:TRUE','-T','fields','-e','frame.number',
                                 '-e','tcp.checksum.status','-e','ip.checksum.status'],
                                output,env,'checksum-'+kind,timeout)
            manifest['commands'].append(audit)
            require(audit['exit_code']==0 and not audit['timed_out'], 'checksum subprocess failed')
            manifest['checks']['checksum-'+kind] = checksum_audit((output/audit['stdout']).read_text(),count)
            for engine in ['zeek','snort']:
                directory = output/(engine+'-'+kind)
                directory.mkdir()
                argv = ([binaries['zeek'],'-r',capture,policy] if engine=='zeek' else
                        [binaries['snort'],'--daq-dir',prefix/'lib/daq','-c',config,'-r',capture,'-l',directory])
                command = run_command(argv,directory,env,'run',timeout)
                command['directory'] = directory.name
                manifest['commands'].append(command)
                require(command['exit_code']==0 and not command['timed_out'], engine+' control subprocess failed')
                checker = check_zeek if engine=='zeek' else check_snort
                manifest['checks'][engine+'-'+kind] = checker(directory,count,kind=='positive')
        manifest['status'] = 'passed'
    except Exception as exc:
        manifest['status'] = 'failed'
        manifest['error'] = type(exc).__name__+': '+str(exc)
    finally:
        manifest['end_utc'] = utc()
        manifest['file_sha256'] = {str(p.relative_to(output)):digest(p) for p in sorted(output.rglob('*')) if p.is_file()}
        (output/'run-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    return manifest


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix',type=Path,required=True)
    parser.add_argument('--sources',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--timeout',type=int,default=60)
    args=parser.parse_args()
    if args.timeout<1:
        parser.error('timeout must be positive')
    result=execute(args.prefix,args.sources,args.output,args.timeout)
    print(json.dumps({'status':result['status'],'error':result.get('error'),
                      'manifest':str(args.output/'run-manifest.json')},indent=2))
    sys.exit(0 if result['status']=='passed' else 2)
