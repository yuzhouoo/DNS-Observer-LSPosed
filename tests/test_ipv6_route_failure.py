"""Run the real global install/rollback script with a kernel model for EACCES on disabled lo."""
from pathlib import Path
from tempfile import TemporaryDirectory
import json,os,subprocess
source=Path('app/src/main/assets/dns-ipv6-global.sh').read_text()
with TemporaryDirectory() as tmp:
    root=Path(tmp);conf=root/'conf';boot=root/'boot';boot.write_text('boot-one\n')
    for name,value in [('all',0),('default',0),('lo',1)]:
        (conf/name).mkdir(parents=True);(conf/name/'disable_ipv6').write_text(str(value)+'\n')
    state=root/'rules.json'
    empty={'chain':False,'entries':[],'route':False,'rule':False}
    state.write_text(json.dumps(empty))
    def stub(name,body):
        p=root/name;p.write_text('#!/usr/bin/env python3\n'+body);p.chmod(0o755)
    stub('ip6tables','''import os,sys,json
from pathlib import Path
p=Path(os.environ['MODEL']);s=json.loads(p.read_text());a=sys.argv[1:]
if '-h' in a:sys.exit(0)
if '-S' in a:
 name=a[a.index('-S')+1:]
 if name:sys.exit(0 if name[0]=='DO6G061' and s['chain'] else 1)
 print('\\n'.join(s['entries']));sys.exit(0)
if '-L' in a:
 name=a[a.index('-L')+1]
 sys.exit(0 if name in ['OUTPUT','PREROUTING'] or s['chain'] else 1)
if '-N' in a:s['chain']=True
if '-X' in a:s['chain']=False
if '-F' in a:s['entries']=[e for e in s['entries'] if not e.startswith('-A DO6G061 ')]
for flag in ['-A','-I','-C','-D']:
 if flag in a:
  i=a.index(flag);args=a[i+1:]
  if flag=='-I':args=[args[0]]+args[2:]
  e='-A '+' '.join(args)
  if flag in ['-A','-I']:s['entries'].append(e)
  elif e not in s['entries']:sys.exit(1)
  elif flag=='-D':s['entries'].remove(e)
p.write_text(json.dumps(s))
''')
    stub('ip','''import os,sys,json
from pathlib import Path
p=Path(os.environ['MODEL']);s=json.loads(p.read_text());a=sys.argv[1:]
if 'addr' in a:print('lo: inet6 ::1/128');sys.exit(0)
if 'route' in a:
 if 'show' in a:
  if s['route']:print('local ::/0 dev lo table 19754')
 elif 'add' in a:
  lo=Path(os.environ['CONF'])/'lo/disable_ipv6'
  if lo.read_text().strip()=='1' or os.environ.get('DENY_ROUTE')=='1':
   print('RTNETLINK answers: Permission denied',file=sys.stderr);sys.exit(2)
  s['route']=True
 elif 'del' in a:s['route']=False
if 'rule' in a:
 if 'show' in a:
  if s['rule']:print('15010: from all fwmark 0x40000000/0x40000000 lookup 19754')
 elif 'add' in a:s['rule']=True
 elif 'del' in a:s['rule']=False
p.write_text(json.dumps(s))
''')
    script=source.replace('CONF=/proc/sys/net/ipv6/conf',f'CONF={conf}')
    script=script.replace('BOOT_FILE=/proc/sys/kernel/random/boot_id',f'BOOT_FILE={boot}')
    script=script.replace('/data/adb/dnsobserver-v6-lo_',str(root/'lo_'))
    script=script.replace('/data/local/tmp/dobs6g61_',str(root/'run_'))
    script=script.replace('/system/bin/sh "$0" watch "$APP_UID" "$TOKEN" "$OWNER_PID" </dev/null >/dev/null 2>&1 &', ': # no persistent processes in simulator')
    env=dict(os.environ,PATH=f'{root}:{os.environ["PATH"]}',MODEL=str(state),CONF=str(conf))
    def call(mode,**extra):
        return subprocess.run(['sh','-c',script,'--',mode,'12345','abc123',str(os.getpid())],
            env=dict(env,**extra),text=True,capture_output=True,timeout=30)
    def snap():return json.loads(state.read_text())
    lo=conf/'lo/disable_ipv6';lease=root/'lo_12345'
    r=call('install-probe');assert r.returncode==0,(r.stdout,r.stderr)
    assert 'LOOPBACK_TEMP_ENABLED' in r.stdout and lo.read_text().strip()=='0'
    assert snap()['route'] and snap()['rule'] and lease.exists()
    r=call('promote');assert r.returncode==0,(r.stdout,r.stderr)
    r=call('check');assert r.returncode==0,(r.stdout,r.stderr)
    r=call('recover');assert r.returncode==0,(r.stdout,r.stderr)
    assert snap()==empty and lo.read_text().strip()=='1' and not lease.exists()
    # Genuine netlink permission failure remains an error with a complete rollback and context.
    r=call('install-probe',DENY_ROUTE='1');assert r.returncode==7,(r.stdout,r.stderr)
    assert 'ROUTE_INSTALL_FAILED' in r.stderr and 'disable_ipv6.lo=0' in r.stderr
    assert snap()==empty and lo.read_text().strip()=='1' and not lease.exists()
    # Do not override the user's system-wide IPv4-only selection.
    (conf/'all/disable_ipv6').write_text('1\n')
    r=call('install-probe');assert r.returncode==7 and 'IPV6_SYSTEM_DISABLED' in r.stderr
    assert lo.read_text().strip()=='1' and snap()==empty
    (conf/'all/disable_ipv6').write_text('0\n')
    # Already enabled lo stays enabled on shutdown.
    lo.write_text('0\n');assert call('install-probe').returncode==0
    assert call('recover').returncode==0 and lo.read_text().strip()=='0'
    # Restoration failure must retain the recovery snapshot and never report complete recovery.
    lo.write_text('1\n');assert call('install-probe').returncode==0
    good_script=script
    script=script.replace('printf \'%s\\n\' "$saved_value" > "$CONF/lo/disable_ipv6"', 'false')
    r=call('recover');assert r.returncode==11 and lease.exists() and 'RECOVERED:' not in r.stdout
    script=good_script
    assert call('recover').returncode==0 and not lease.exists()
    lo.write_text('0\n')
    # Unresolved earlier lease blocks installing over its recovery data.
    lease.write_text('boot-one oldsession 1\n')
    r=call('install-probe');assert r.returncode==4 and 'PRECHECK_FAILED' in r.stderr
    assert lease.exists() and snap()==empty
    # An earlier boot's snapshot must never change this boot's settings.
    boot.write_text('boot-two\n');r=call('recover')
    assert r.returncode==0 and lo.read_text().strip()=='0' and not lease.exists()
print('PASS: disabled-loopback EACCES repaired transactionally, real permission denial diagnosed, original lo restored, global disable respected, stale leases guarded')
