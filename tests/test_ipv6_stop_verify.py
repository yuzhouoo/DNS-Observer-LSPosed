"""Run production daemon-stop code: failed signal must never imply a verified stop."""
from pathlib import Path
from tempfile import TemporaryDirectory
import os,subprocess
source=Path('app/src/main/assets/dns-ipv6-global.sh').read_text()
with TemporaryDirectory() as t:
    root=Path(t);proc=root/'proc';proc.mkdir()
    for pid,cmd,uid in [('901','dobs6_owned',0),('902','unrelated_root_service',0),('903','dobs6_other_uid',10001)]:
        d=proc/pid;d.mkdir();(d/'comm').write_text(cmd[:15]+'\n');(d/'cmdline').write_bytes(cmd.encode()+b'\0');(d/'status').write_text(f'Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n')
    # Hundreds of unrelated processes must not require cmdline subprocesses.
    for n in range(1000,2000):
        d=proc/str(n);d.mkdir();(d/'comm').write_text('unrelated\n');(d/'status').write_text('Uid: 0 0 0 0\n')
    for command in ['ip','ip6tables']:
        f=root/command;f.write_text('#!/bin/sh\nexit 0\n');f.chmod(0o755)
    script=root/'stop.sh'
    script.write_text('''kill(){
        [ "$STOP_FAIL" = 1 ] && return 1
        rm -f "$FAKE_PROC/$2/cmdline"
        return 0
    }
    sleep(){ :; }
    '''+source.replace('/proc/',str(proc)+'/'))
    def run(fail):
        return subprocess.run(['sh',str(script),'stop-owned-daemons','12345','cleanup','123'],
            env=dict(os.environ,PATH=str(root)+':'+os.environ['PATH'],FAKE_PROC=str(proc),STOP_FAIL=str(fail)),text=True,capture_output=True,timeout=5)
    failed=run(1);assert failed.returncode==14,(failed.stdout,failed.stderr)
    assert 'OWNED_DAEMON_STOP_FAILED' in failed.stderr
    stopped=run(0);assert stopped.returncode==0,(stopped.stdout,stopped.stderr)
    assert 'exit checked' in stopped.stdout
    assert (proc/'902/cmdline').exists() and (proc/'903/cmdline').exists()
print('PASS: daemon-stop failure, verified exit, unrelated/root and other UID processes preserved')
