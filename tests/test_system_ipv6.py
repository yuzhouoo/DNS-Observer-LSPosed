"""Run the production transaction script against simulated kernel nodes, never host sysctls."""
from pathlib import Path
from tempfile import TemporaryDirectory
import os
import subprocess

source = Path('app/src/main/assets/system-ipv6.sh').read_text()
with TemporaryDirectory() as tmp:
    root = Path(tmp)
    conf = root/'conf'
    home = root/'state'
    boot = root/'boot'
    boot.write_text('boot-one\n')
    def node(name, value):
        path = conf/name/'disable_ipv6'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(str(value)+'\n')
    original = {'all': 0, 'default': 0, 'lo': 0, 'wlan0': 0, 'rmnet_data0': 1}
    for k, v in original.items(): node(k, v)
    # Model Linux's all -> individual interfaces side effect, plus one-shot I/O faults.
    writer = root/'write.py'
    writer.write_text('''import os,sys
from pathlib import Path
conf=Path(sys.argv[1]); name=sys.argv[2]; value=sys.argv[3]
fault=Path(os.environ['FAULT'])
if fault.exists() and fault.read_text().strip()==name:
    fault.unlink(); sys.exit(1)
(conf/name/'disable_ipv6').write_text(value+'\\n')
if name=='all':
    for p in conf.glob('*/disable_ipv6'):
        if p.parent.name!='default': p.write_text(value+'\\n')
''')
    fault = root/'fault'
    env = dict(os.environ, FAULT=str(fault))
    script = source.replace('dir=/proc/sys/net/ipv6/conf', f'dir="{conf}"')
    script = script.replace('home=/data/adb/dnsobserver-ipv6', f'home="{home}"')
    script = script.replace('boot_file=/proc/sys/kernel/random/boot_id', f'boot_file="{boot}"')
    script = script.replace('printf \'%s\\n\' "$2" > "$dir/$1/disable_ipv6"',
                            f'python3 "{writer}" "$dir" "$1" "$2"')
    def call(mode):
        # Same POSIX single-quote escaping as the Java su -c command.
        command = "sh -c '"+script.replace("'", "'\\''")+"' -- "+mode
        return subprocess.run(['sh', '-c', command], env=env, capture_output=True, text=True, timeout=10)
    def values(): return {p.parent.name: int(p.read_text()) for p in conf.glob('*/disable_ipv6')}
    def ok(mode):
        r = call(mode)
        assert r.returncode == 0, (mode, r.stdout, r.stderr)
        return r.stdout
    assert 'IPV6_NOT_FULLY_DISABLED' in ok('status')
    assert not home.exists(), 'status must be read-only'
    assert 'IPV6_DISABLED' in ok('on')
    assert set(values().values()) == {1}
    saved = (home/'original').read_bytes()
    ok('on')
    assert (home/'original').read_bytes() == saved
    node('new0', 1)
    assert 'IPV6_ENABLED_VERIFIED' in ok('off')
    assert set(values().values()) == {0}, values()
    assert not (home/'original').exists()
    # Explicit enable does not depend on a backup. Repeated OFF is idempotent.
    ok('off'); assert set(values().values()) == {0}
    # Exact user regression: all/default/lo=1 and the historical saved values are also 1.
    for name in values():node(name,1)
    ok('on')
    assert all(line.endswith(' 1') for line in (home/'original').read_text().splitlines())
    ok('off'); assert set(values().values()) == {0}
    # Same regression when there is no saved state at all.
    for name in values():node(name,1)
    assert not (home/'original').exists()
    ok('off'); assert set(values().values()) == {0}
    # Partial disable failure restores the exact mixed starting state, not all zeros.
    for k,v in original.items():node(k,v)
    before=values()
    fault.write_text('wlan0');r=call('on')
    assert r.returncode != 0 and 'ROLLBACK_OK' in r.stdout,(r.stdout,r.stderr)
    assert values()==before
    ok('on');disabled=values()
    # A failed explicit enable returns to fully disabled, retaining recovery data.
    fault.write_text('wlan0');r=call('off')
    assert r.returncode != 0 and 'ROLLBACK_OK' in r.stdout,(r.stdout,r.stderr)
    assert values()==disabled and (home/'original').exists()
    ok('off');assert set(values().values())=={0}
    # An obsolete/corrupt historical backup cannot block explicit enable.
    ok('on');(home/'original').write_text('../escape 0\n')
    ok('off');assert set(values().values())=={0}
    ok('on');node('wlan0',0)
    assert 'IPV6_NOT_FULLY_DISABLED' in ok('status')
    ok('on');assert set(values().values())=={1}
    boot.write_text('boot-two\n')
    ok('off');assert set(values().values())=={0}
    (home/'lock').mkdir();(home/'lock'/'pid').write_text(str(os.getpid()))
    before=values();assert call('on').returncode==8;assert values()==before
    (home/'lock'/'pid').unlink();(home/'lock').rmdir()
    script=script.replace('python3 "'+str(writer)+'" "$dir" "$1" "$2"',
                         '[ "$1" != wlan0 ] || return 1\n    python3 "'+str(writer)+'" "$dir" "$1" "$2"')
    r=call('on');assert r.returncode==9 and 'ROLLBACK_FAILED' in r.stdout
    assert (home/'original').exists() and (home/'before').exists()
print('PASS: explicit IPv6 enable despite original all=1 or missing/corrupt backup; disable/enable readback, new interfaces, exact failure rollback, boot, lock and drift')
