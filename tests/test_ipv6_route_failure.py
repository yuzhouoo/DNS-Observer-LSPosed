"""Run the real global install/rollback script with a kernel model for EACCES on disabled lo."""
from pathlib import Path
from tempfile import TemporaryDirectory
import json,os,subprocess,ipaddress,shlex
source=Path('app/src/main/assets/dns-ipv6-global.sh').read_text()
with TemporaryDirectory() as tmp:
    root=Path(tmp);conf=root/'conf';boot=root/'boot';boot.write_text('boot-one\n')
    for name,value in [('all',0),('default',0),('lo',1)]:
        (conf/name).mkdir(parents=True);(conf/name/'disable_ipv6').write_text(str(value)+'\n')
    state=root/'rules.json'
    empty={'chain':False,'entries':[],'route':False,'rule':False,'seeds':[]}
    state.write_text(json.dumps(empty))
    def stub(name,body):
        p=root/name;p.write_text('#!/usr/bin/env python3\n'+body);p.chmod(0o755)
    stub('ip6tables','''import os,sys,json
from pathlib import Path
p=Path(os.environ['MODEL']);s=json.loads(p.read_text());a=sys.argv[1:]
if '-h' in a:sys.exit(0)
if '-S' in a:
 name=a[a.index('-S')+1:]
 if name:
  if name[0] not in ['OUTPUT','PREROUTING'] and not (name[0]=='DO6G061' and s['chain']):sys.exit(1)
  print('\\n'.join(e for e in s['entries'] if e.startswith('-A '+name[0]+' ')));sys.exit(0)
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
  if flag=='-I':s['entries'].insert(0,e)
  elif flag=='-A':s['entries'].append(e)
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
  if s['route']:print(os.environ.get('ROUTE_TEXT','local ::/0 dev lo table 19754'))
 elif 'add' in a:
  lo=Path(os.environ['CONF'])/'lo/disable_ipv6'
  if lo.read_text().strip()=='1' or os.environ.get('DENY_ROUTE')=='1':
   print('RTNETLINK answers: Permission denied',file=sys.stderr);sys.exit(2)
  s['route']=True
 elif 'del' in a:s['route']=False
if 'rule' in a:
 if 'show' in a:
  if os.environ.get('BLOCK_EARLY')=='1':print('100: from all unreachable')
  for seed in s['seeds']:print(seed)
  if s['rule']:print('15010: from all fwmark 0x40000000/0x40000000 lookup 19754')
 elif 'dport' in a:
  pref=a[a.index('pref')+1];uid=a[a.index('uidrange')+1];proto=a[a.index('ipproto')+1]
  entry=pref+': from all to '+a[a.index('to')+1]+' iif lo uidrange '+uid+' ipproto '+proto+' dport 53 lookup 19754'
  if 'add' in a:
   if os.environ.get('NO_PORT_RULE')=='1':sys.exit(2)
   s['seeds'].append(entry)
  elif entry in s['seeds']:s['seeds'].remove(entry)
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
    # Empty cleanup must be quiet; shell syntax checking cannot catch !function typos.
    clean=call('recover');assert clean.returncode==0 and not clean.stderr,(clean.stdout,clean.stderr)
    # Orphaned exact seeds must be removed even when marker and chain are absent.
    orphan=dict(empty,seeds=['14990: from all to 2000::/3 iif lo uidrange 12345-12345 ipproto udp dport 53 lookup 19754'])
    state.write_text(json.dumps(orphan))
    clean=call('recover');assert clean.returncode==0 and not clean.stderr and snap()==empty,(clean.stdout,clean.stderr,snap())
    blocked=call('install-probe',BLOCK_EARLY='1');assert blocked.returncode==4 and 'IPV6_POLICY_BLOCKED' in blocked.stderr and snap()==empty
    r=call('install-probe');assert r.returncode==0,(r.stdout,r.stderr)
    assert 'LOOPBACK_TEMP_ENABLED' in r.stdout and lo.read_text().strip()=='0'
    assert snap()['route'] and snap()['rule'] and lease.exists()
    assert len(snap()['seeds'])==4
    assert all('dport 53' in x and 'uidrange 12345-12345' in x and ('to 2000::/3' in x or 'to fc00::/7' in x) for x in snap()['seeds'])
    before=snap()
    # A wrong token may not mutate an existing probe's exact UID policy.
    wrong=subprocess.run(['sh','-c',script,'--','promote','12345','wrongtoken',str(os.getpid())],env=env,capture_output=True,text=True)
    assert wrong.returncode!=0 and snap()==before

    r=call('promote');assert r.returncode==0,(r.stdout,r.stderr)
    r=call('check');assert r.returncode==0,(r.stdout,r.stderr)
    # A Box jump inserted above our selectors must invalidate status, despite all -C checks passing.
    good=snap();shadow=json.loads(json.dumps(good));shadow['entries'].insert(0,'-A OUTPUT -j BOX_LOCAL');shadow['entries'].insert(0,'-A PREROUTING -j DIVERT');state.write_text(json.dumps(shadow))
    assert call('check').returncode!=0
    before=snap();assert call('refresh',BLOCK_EARLY='1').returncode!=0 and snap()==before
    wrong=subprocess.run(['sh','-c',script,'--','refresh','12345','wrongtoken',str(os.getpid())],env=env,capture_output=True,text=True)
    assert wrong.returncode!=0 and snap()==before
    assert call('refresh').returncode==0
    assert call('check').returncode==0
    assert '-A OUTPUT -j BOX_LOCAL' in snap()['entries'] and '-A PREROUTING -j DIVERT' in snap()['entries']
    assert call('check',BLOCK_EARLY='1').returncode!=0, 'later policy block cannot look active'
    # Our scoped ACCEPT ends mangle processing after MARK; TCP/UDP 443 never match it.
    for proto in ['udp','tcp']:
        for subnet in ['2000::/3','fc00::/7']:
            es=[e for e in snap()['entries'] if e.startswith('-A OUTPUT -d '+subnet+' -p '+proto+' ')]
            assert len(es)==2 and '-j MARK' in es[0] and es[1].endswith('-j ACCEPT') and '--dport 53' in es[1]
    def output_packet(uid,proto,dest,port):
        mark=0
        for line in snap()['entries']:
            a=shlex.split(line)
            if a[:2]!=['-A','OUTPUT']:continue
            if a[-2:]==['-j','BOX_LOCAL']:return 0x1000000
            if '-d' in a and ipaddress.ip_address(dest) not in ipaddress.ip_network(a[a.index('-d')+1]):continue
            if '-p' in a and a[a.index('-p')+1]!=proto:continue
            if '--dport' in a and int(a[a.index('--dport')+1])!=port:continue
            if '--uid-owner' in a:
                i=a.index('--uid-owner');same=uid==int(a[i+1])
                if ('!' in a and same) or ('!' not in a and not same):continue
            if '--mark' in a and mark!=0x40000000:continue
            target=a[a.index('-j')+1]
            if target=='MARK':mark|=0x40000000
            if target=='ACCEPT':return mark
        return mark
    for proto in ['udp','tcp']:
        assert output_packet(12345,proto,'2001:db8:ffff::53',53)==0x40000000
        assert output_packet(20000,proto,'fd00::53',53)==0x40000000
        assert output_packet(20000,proto,'2001:db8::443',443)==0x1000000
        assert output_packet(0,proto,'2001:db8::53',53)==0x1000000, 'Root UID stays excluded'
    state.write_text(json.dumps(good))
    complete=snap();broken=json.loads(json.dumps(complete));broken['seeds'].pop();state.write_text(json.dumps(broken))
    assert call('check').returncode!=0
    state.write_text(json.dumps(complete))
    r=call('recover');assert r.returncode==0,(r.stdout,r.stderr)
    assert snap()==empty and lo.read_text().strip()=='1' and not lease.exists()
    r=call('install-probe',NO_PORT_RULE='1');assert r.returncode!=0
    assert snap()==empty and not lease.exists()
    # iproute2 prints ::/0 as default; both renderings must check and clean identically.
    for text in ['local default dev lo metric 1024 pref medium',
                 'local ::/0 proto static dev lo table 19754 metric 1024']:
        assert call('install-probe',ROUTE_TEXT=text).returncode==0
        assert call('promote',ROUTE_TEXT=text).returncode==0
        r=call('check',ROUTE_TEXT=text);assert r.returncode==0,(r.stdout,r.stderr)
        # Wrong interface/destination must never pass merely because the table exists.
        assert call('check',ROUTE_TEXT='local default dev wlan0').returncode!=0
        assert call('check',ROUTE_TEXT='local 2001:db8::1/128 dev lo').returncode!=0
        assert call('recover',ROUTE_TEXT=text).returncode==0
        assert snap()==empty
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
