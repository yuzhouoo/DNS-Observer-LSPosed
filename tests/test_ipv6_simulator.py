from pathlib import Path
from tempfile import TemporaryDirectory
import subprocess, os, json
src=Path('app/src/main/assets/dns-ipv6-tproxy-probe.sh').read_text()
# Simulator validates rules, not watchdog scheduling; do not spawn persistent background sleeps.
src=src.replace('/system/bin/sh "$0" watch "$UID_ARG" "$TOKEN" </dev/null >/dev/null 2>&1 &', ': # test mock watchdog')
with TemporaryDirectory() as temp:
    t=Path(temp)
    script=t/'probe.sh'
    script.write_text(src.replace('"/data/local/tmp/dobs6t55_${UID_ARG}.run"',f'"{t}/dobs6t55_${{UID_ARG}}.run"'))
    state=t/'state.json'; state.write_text(json.dumps({'chain':False,'entries':[],'rule':False,'route':False}))
    # Fully stateful mocks, to verify that recovery removes exactly scoped pieces.
    ip6=t/'ip6tables'
    ip6.write_text('''#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
p=Path(os.environ['MOCK_STATE']);s=json.loads(p.read_text());a=sys.argv[1:];cmd=' '.join(a)
if '-h' in a: sys.exit(0)
if '-S' in a:
    if a[-1]=='DO6TST55': sys.exit(0 if s['chain'] else 1)
if '-N' in a: s['chain']=True
if '-X' in a: s['chain']=False
if '-F' in a: s['entries']=[x for x in s['entries'] if '-A DO6TST55 ' not in x]
if '-I' in a:
    index=a.index('-I'); entry='-A '+a[index+1]+' '+' '.join(a[index+3:]);s['entries'].append(entry)
if '-A' in a:
    index=a.index('-A');entry='-A '+a[index+1]+' '+' '.join(a[index+2:]);s['entries'].append(entry)
if '-C' in a or '-D' in a:
    switch='-C' if '-C' in a else '-D';index=a.index(switch)
    entry='-A '+a[index+1]+' '+' '.join(a[index+2:])
    if entry not in s['entries']:sys.exit(1)
    if switch=='-D':s['entries'].remove(entry)
if '-L' in a:
    print('Chain '+a[a.index('-L')+1]+' (references)')
    print('\\n'.join(x for x in s['entries'] if a[a.index('-L')+1] in x))
p.write_text(json.dumps(s))
''');ip6.chmod(0o755)
    ip=t/'ip';ip.write_text('''#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
p=Path(os.environ['MOCK_STATE']);s=json.loads(p.read_text());a=sys.argv[1:]
if 'rule' in a:
    if 'show' in a:
        print('0: from all lookup local')
        if s['rule']:print('15000: from all fwmark 0x20000000/0x20000000 lookup 19753')
    elif 'add' in a:s['rule']=True
    elif 'del' in a:s['rule']=False
if 'route' in a:
    if 'show' in a:
        if s['route']:print('local 2001:db8:ffff::53 dev lo table 19753')
    elif 'add' in a:s['route']=True
    elif 'del' in a:s['route']=False
p.write_text(json.dumps(s))
''');ip.chmod(0o755)
    env=dict(os.environ,PATH=f'{t}:{os.environ["PATH"]}', MOCK_STATE=str(state))
    def call(mode):return subprocess.run(['sh',str(script),mode,'12345','testabc'],env=env,text=True,capture_output=True,timeout=80)
    def snap():return json.loads(state.read_text())
    r=call('install-loop');assert r.returncode==0,(r.stdout,r.stderr)
    assert snap()['chain'] and len(snap()['entries'])==4 and not snap()['rule'] and not snap()['route']
    r=call('recover');assert r.returncode==0,(r.stdout,r.stderr)
    assert 'VERIFY_CLEAN' in r.stdout and not snap()['chain'] and not snap()['entries']
    r=call('install-local');assert r.returncode==0,(r.stdout,r.stderr)
    assert snap()['chain'] and snap()['rule'] and snap()['route'] and len(snap()['entries'])==6
    r=call('recover');assert r.returncode==0,(r.stdout,r.stderr)
    assert 'VERIFY_CLEAN' in r.stdout and snap()=={'chain':False,'entries':[],'rule':False,'route':False}
    r=call('install-dns');assert r.returncode==0,(r.stdout,r.stderr)
    assert snap()['chain'] and snap()['rule'] and snap()['route'] and len(snap()['entries'])==6
    assert any('--dport 53 ' in x and '-m owner --uid-owner 12345' in x for x in snap()['entries'])
    assert any('--dport 53 ' in x and '-m mark --mark' in x for x in snap()['entries'])
    r=call('recover');assert r.returncode==0,(r.stdout,r.stderr)
    assert 'VERIFY_CLEAN' in r.stdout and snap()=={'chain':False,'entries':[],'rule':False,'route':False}
    r=call('install-pilot');assert r.returncode==0,(r.stdout,r.stderr)
    assert 'watchdog 180s' in r.stdout
    assert snap()['chain'] and snap()['rule'] and snap()['route'] and len(snap()['entries'])==6
    assert (t/'dobs6t55_12345.run').read_text().strip()=='pilot:testabc'
    r=call('recover');assert r.returncode==0,(r.stdout,r.stderr)
    assert 'VERIFY_CLEAN' in r.stdout and snap()=={'chain':False,'entries':[],'rule':False,'route':False}
    assert call('recover').returncode==0 # idempotent
    # Collision: disallow reserved policy priority owned by another component.
    present=snap();present['rule']=True;state.write_text(json.dumps(present))
    r=call('install-local');assert r.returncode!=0 and 'PRECHECK_FAILED' in r.stderr,(r.stdout,r.stderr)
    # Recovery must not silently delete arbitrary foreign route if the module owns nothing.
    r=call('recover');assert r.returncode!=0 and snap()['rule'],(r.stdout,r.stderr)
print('PASS: scoped rules, routing, idempotent clean, collision refusal, residue reporting')
