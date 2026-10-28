from pathlib import Path
from tempfile import TemporaryDirectory
import subprocess, os
src=Path('app/src/main/assets/dns-ipv6-tproxy-probe.sh').read_text()
with TemporaryDirectory() as temp:
    t=Path(temp)
    run=t/'probe.sh'
    run.write_text(src.replace('"/data/local/tmp/dobs6t_${UID_ARG}.run"',f'"{t}/dobs6t_${{UID_ARG}}.run"'))
    ip6=t/'ip6tables'
    ip6.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$IP6_LOG"\ncase "$*" in\n  *"-S DO6TST53"*) exit 1 ;;\n  *"-C PREROUTING"*) exit 1 ;;\nesac\nexit 0\n')
    ip6.chmod(0o755)
    e=dict(os.environ,PATH=f'{t}:{os.environ["PATH"]}', IP6_LOG=str(t/'calls'))
    r=subprocess.run(['sh',str(run),'install','12345','abc123'],env=e,text=True,capture_output=True)
    assert r.returncode==0,(r.stdout,r.stderr)
    assert (t/'dobs6t_12345.run').read_text().strip()=='abc123'
    r=subprocess.run(['sh',str(run),'recover','12345','cleanup'],env=e,text=True,capture_output=True)
    assert r.returncode==0,(r.stdout,r.stderr)
    assert not (t/'dobs6t_12345.run').exists()
    commands=(t/'calls').read_text().splitlines()
    assert any('-N DO6TST53' in x for x in commands)
    assert any('-j TPROXY' in x and '--on-ip ::1' in x for x in commands)
    assert any('-I PREROUTING 1 -i lo -d ::1/128' in x and '--dport 15453' in x for x in commands)
    assert any('-F DO6TST53' in x for x in commands)
    assert all('nat' not in x for x in commands)
    assert all(not ('OUTPUT' in x) for x in commands)
print('PASS: isolated TPROXY install & explicit recovery simulated')
