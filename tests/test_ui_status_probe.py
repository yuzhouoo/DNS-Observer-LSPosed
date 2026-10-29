"""Exercise read-only UI probe with Root and firewall failures, residue and mixed sysctls."""
from pathlib import Path
from tempfile import TemporaryDirectory
import os,subprocess
source=Path('app/src/main/assets/dns-ui-status.sh').read_text()
with TemporaryDirectory() as tmp:
    root=Path(tmp);conf=root/'conf'
    for name in ['all','default','lo','wlan0']:
        (conf/name).mkdir(parents=True);(conf/name/'disable_ipv6').write_text('0\n')
    def stub(name,text):
        p=root/name;p.write_text('#!/bin/sh\n'+text);p.chmod(0o755)
    stub('id','echo "${MOCK_UID:-0}"\n')
    stub('iptables','[ "${FAIL4:-0}" = 0 ] || exit 3\nprintf "%s\\n" "${RULE4:-}"\n')
    stub('ip6tables','[ "${FAIL6:-0}" = 0 ] || exit 3\nprintf "%s\\n" "${RULE6:-}"\n')
    stub('ip','[ "${FAILIP:-0}" = 0 ] || exit 3\ncase "$*" in *"rule show"*) echo "${ROUTE:-}";; *"table 19754"*) echo "${TABLE:-}";; esac\n')
    source=source.replace('/proc/sys/net/ipv6/conf',str(conf)).replace('/data/local/tmp',str(root))
    def call(**values):
        return subprocess.run(['sh','-c',source,'--','12345'],capture_output=True,text=True,
            env=dict(os.environ,PATH=f'{root}:{os.environ["PATH"]}',**values),timeout=5)
    def read(**values):
        r=call(**values);assert r.returncode==0,(r.stdout,r.stderr)
        return dict(line.split('=',1) for line in r.stdout.splitlines())
    assert read()==dict(V4='off',V6='off',SYSTEM='enabled')
    assert read(FAIL4='1')['V4']=='unknown'
    assert read(FAIL6='1')['V6']=='unknown'
    assert read(FAILIP='1')['V6']=='unknown'
    assert read(RULE4='-N DOBSR53')['V4']=='present'
    assert read(RULE6='-N DO6G061')['V6']=='present'
    assert read(ROUTE='15010: from all lookup 19754')['V6']=='present'
    assert read(TABLE='local ::/0 dev lo')['V6']=='present'
    assert read(RULE4='-N DOBSR53_OTHER')['V4']=='off'
    assert read(RULE6='-N DO6G061_BACKUP')['V6']=='off'
    marker=root/'dobsr53_12345.run' ;marker.write_text('orphan');assert read()['V4']=='present';marker.unlink()
    for p in conf.glob('*/disable_ipv6'):p.write_text('1\n')
    assert read()['SYSTEM']=='disabled'
    (conf/'wlan0/disable_ipv6').write_text('0\n');assert read()['SYSTEM']=='blocked'
    (conf/'all/disable_ipv6').write_text('0\n');assert read()['SYSTEM']=='blocked'
    (conf/'default/disable_ipv6').write_text('0\n');assert read()['SYSTEM']=='mixed'
    (conf/'wlan0/disable_ipv6').write_text('bad\n');assert read()['SYSTEM']=='unknown'
    assert call(MOCK_UID='10000').returncode!=0
    # The status probe must not invoke any write-capable firewall or routing commands.
    assert not any(x in source for x in [' -D ', ' -A ', ' -I ', ' -F ', ' -X ', 'sysctl -w', ' route add', ' rule del'])
print('PASS: UI probe keeps denied/failed checks unknown and detects partial, orphaned, dual-stack state without mutation')
