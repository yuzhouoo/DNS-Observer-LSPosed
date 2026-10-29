"""Execute the production read-only probe against fake procfs and firewall commands."""
import os
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as temp:
    d = pathlib.Path(temp)
    proc = d / 'proc'
    proc.mkdir()
    bin_dir = d / 'bin'
    bin_dir.mkdir()
    state = d / 'state'
    state.mkdir()
    source = (ROOT / 'app/src/main/assets/dns-box-status.sh').read_text()
    script = d / 'probe.sh'
    script.write_text(source.replace('/proc/', str(proc) + '/'))
    def command(name, text):
        p = bin_dir / name
        p.write_text('#!/bin/sh\n' + text)
        p.chmod(0o755)
    command('id', 'echo 0\n')
    command('ip', 'case "$*" in *"rule show"*) cat "$STATE/rules";; esac\n')
    for name in ['iptables', 'ip6tables']:
        command(name, '[ -f "$STATE/fail" ] && exit 1\ncase "$*" in *mangle*) cat "$STATE/mangle";; *nat*) cat "$STATE/nat";; esac\n')
    (state / 'rules').write_text('0: from all lookup local\n100: from all fwmark 0x1000000/0x1000000 lookup 2024\n')
    (state / 'mangle').write_text('')
    (state / 'nat').write_text('')
    env = dict(os.environ, PATH=str(bin_dir)+':'+os.environ['PATH'], STATE=str(state))
    def probe():
        r = subprocess.run(['sh', str(script)], env=env, text=True, capture_output=True)
        if r.returncode:
            return None
        return dict(line.split('=',1) for line in r.stdout.splitlines())
    assert probe()['BOX'] == 'stopped'
    p = proc / '125'
    p.mkdir()
    (p / 'exe').symlink_to('/data/adb/box/bin/mihomo')
    def stat(start):
        (p / 'stat').write_text('125 (mihomo worker) ' + ' '.join(['S'] + ['0']*18 + [str(start)]) + '\n')
    stat(100)
    assert probe()['BOX'] == 'starting'
    (state / 'mangle').write_text('-N BOX_LOCAL\n-A OUTPUT -j BOX_LOCAL\n-A BOX_LOCAL -p udp --dport 53 -j RETURN\n')
    first = probe()
    assert first['BOX'] == 'running'
    assert '125:100:mihomo' in first['SIGNATURE']
    # Own installs and traffic never count as Box rules changes.
    with (state / 'mangle').open('a') as f:
        f.write('-N DO6G061\n-A OUTPUT -j DO6G061\n')
    assert probe() == first
    stat(101)
    assert probe()['SIGNATURE'] != first['SIGNATURE'], 'PID reuse must be detected'
    (state / 'nat').write_text('-N NAT_DNS_HIJACK6\n-A OUTPUT -j NAT_DNS_HIJACK6\n')
    assert probe()['SIGNATURE'] != first['SIGNATURE']
    (p / 'exe').unlink()
    assert probe()['BOX'] == 'stopping'
    (state / 'mangle').write_text('')
    (state / 'nat').write_text('')
    assert probe()['BOX'] == 'stopped'
    (state / 'fail').touch()
    assert probe() is None, 'read failure must never look like a stopped Box'
print('Box root probe: PASS')
