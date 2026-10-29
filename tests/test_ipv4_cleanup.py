"""Execute production IPv4 script: partial cleanup, lock failure, duplicate jumps and scoped removal."""
from pathlib import Path
from tempfile import TemporaryDirectory
import json,os,subprocess
source=Path('app/src/main/assets/dns-root.sh').read_text()
with TemporaryDirectory() as tmp:
    root=Path(tmp);state=root/'model.json'
    empty=lambda:{'chain':False,'entries':[]}
    state.write_text(json.dumps({'4':empty(),'6':empty(),'fault_used':False}))
    code='''#!/usr/bin/env python3
import os,sys,json,fcntl
from pathlib import Path
p=Path(os.environ['MODEL']);a=sys.argv[1:];family='6' if 'ip6tables' in sys.argv[0] else '4'
if a[:1]==['-w']:a=a[2:]
if a[:2]==['-t','nat']:a=a[2:]
with open(str(p)+'.lock','w') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX)
 all=json.loads(p.read_text());s=all[family]
 flag=a[0];args=a[1:]
 if flag=='-S':
  if args:
   if not s['chain'] or args[0]!='DOBSR53':sys.exit(1)
   print('-N DOBSR53');print('\\n'.join(e for e in s['entries'] if e.startswith('-A DOBSR53 ')))
  else:
   if s['chain']:print('-N DOBSR53')
   print('\\n'.join(s['entries']));print('-N OTHER_DOBSR53_BACKUP');print('-A OTHER_DOBSR53_BACKUP -j RETURN')
  sys.exit(0)
 if flag=='-C':sys.exit(0 if '-A '+' '.join(args) in s['entries'] else 1)
 if os.environ.get('REMOVE_DENIED')=='1' and flag in ['-D','-F','-X']:
  print('Permission denied',file=sys.stderr);sys.exit(4)
 if os.environ.get('LOCK_ONCE')=='1' and flag=='-X' and not all['fault_used']:
  all['fault_used']=True;p.write_text(json.dumps(all));print('xtables lock busy',file=sys.stderr);sys.exit(4)
 if flag=='-N':
  if s['chain']:sys.exit(1)
  s['chain']=True
 if flag in ['-A','-I']:
  if flag=='-I':args=[args[0]]+args[2:]
  s['entries'].append('-A '+' '.join(args))
 if flag=='-D':
  e='-A '+' '.join(args)
  if e not in s['entries']:sys.exit(1)
  s['entries'].remove(e)
 if flag=='-F':s['entries']=[e for e in s['entries'] if not e.startswith('-A DOBSR53 ')]
 if flag=='-X':
  if any(e.endswith('-j DOBSR53') for e in s['entries']):sys.exit(1)
  s['chain']=False
 p.write_text(json.dumps(all))
'''
    for name in ['iptables','ip6tables']:
        p=root/name;p.write_text(code);p.chmod(0o755)
    script=source.replace('/data/local/tmp/dobsr53_',str(root/'marker_')).replace('/data/adb/dnsobserver-v4_',str(root/'mutation_'))
    env=dict(os.environ,PATH=f'{root}:{os.environ["PATH"]}',MODEL=str(state))
    def call(mode,token="abc123",**extra):
        return subprocess.run(['sh','-c',script,'--',mode,'12345','15353','0',str(os.getpid()),token],
            env=dict(env,**extra),capture_output=True,text=True,timeout=30)
    def ok(mode,**extra):
        r=call(mode,**extra);assert r.returncode==0,(mode,r.stdout,r.stderr);return r.stdout
    def snap():return json.loads(state.read_text())
    ok('install');ok('status')
    r=call('remove',LOCK_ONCE='1');assert r.returncode!=0
    assert call('status').returncode!=0, 'partial state is not active'
    assert call('verify-clean').returncode==12, 'partial state is not clean either'
    ok('remove');assert 'VERIFY_CLEAN' in ok('verify-clean')
    assert not snap()['4']['chain'] and not snap()['4']['entries']
    # Missing marker/jumps must not hide an orphan chain.
    m=snap();m['4']['chain']=True;state.write_text(json.dumps(m))
    assert call('status').returncode!=0
    assert call('verify-clean').returncode==12
    ok('remove');ok('verify-clean')
    # Clear duplicates beyond the old 12-rule limit, preserving unrelated chains.
    ok('install');m=snap();m['4']['entries'] += ['-A OUTPUT -p udp --dport 53 -j DOBSR53']*18;state.write_text(json.dumps(m))
    ok('remove');ok('verify-clean')
    # A real deletion failure is reported, never claimed as successful removal.
    ok('install');r=call('remove',REMOVE_DENIED='1');assert r.returncode!=0 and 'Permission denied' in r.stderr
    assert call('verify-clean').returncode==12
    ok('remove');ok('verify-clean');ok('remove');ok('verify-clean')
    # A delayed old service must not delete a newer session's rules.
    ok('install',token='oldsession');ok('install',token='newsession')
    assert 'SKIP_NEWER_SESSION' in ok('remove-owned',token='oldsession')
    ok('status');ok('remove-owned',token='newsession');ok('verify-clean')
    # Repairs preserve the live service's token so its later stop remains authorized.
    ok('install',token='livesession');ok('install',token='livesession')
    assert 'SKIP_NEWER_SESSION' not in ok('remove-owned',token='livesession')
    ok('verify-clean')
    # Concurrent install/remove operations serialize; a final stop leaves no owned residue.
    procs=[subprocess.Popen(['sh','-c',script,'--',mode,'12345','15353','0',str(os.getpid()),'abc123'],
             env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True) for mode in ['install','remove']]
    for p in procs:
        out,err=p.communicate(timeout=30);assert p.returncode==0,(out,err)
    ok('remove');ok('verify-clean')
print('PASS: partial/orphan cleanup, lock retry, duplicate jumps, exact chain scoping, denied deletion and concurrent mutations')
