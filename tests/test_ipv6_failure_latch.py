from pathlib import Path
base=Path("app/src/main/java/dev/yz/dnsobserver")
service=(base/"DnsTakeoverService.java").read_text()
globalctl=(base/"DnsIpv6GlobalController.java").read_text()
daemon=(base/"DnsIpv6GlobalDaemon.java").read_text()
script=Path("app/src/main/assets/dns-ipv6-global.sh").read_text()
assert 'ipv6EverActive=false;ipv6RepairBlocked=false' in service
assert 'if(expect6 && ipv6EverActive && !ipv6RepairBlocked)' in service
assert 'ipv6RepairBlocked=true;' in service
assert 'REPAIR_PAUSED IPv6' in service
assert 'IPv6 未勾选；本次不启动 IPv6 代理' in service
assert 'DnsIpv6GlobalController.stop(this)' in service # full forced OFF
assert 'stopRoot(app,started,rootPid,token);' in globalctl
assert 'stopRoot(ctx,process,rootPid,token);' in globalctl
assert '--nice-name=dobs6_' in globalctl
assert 'root(ctx,"stop-process",session,10,pid)' in globalctl
assert 'pid="+Os.getpid()' in daemon
assert 'BIND_ERROR protocol=' in daemon
assert 'PROCESS_STOP_REFUSED' in script and 'PROCESS_STOP:' in script
assert 'stop-owned-daemons' in script and 'stop-owned-daemons' in globalctl
assert 'dns-ipv6-global-v063.sh' in globalctl
assert 'reserved route/pref occupied (15010 / table 19754)' in script
assert not any(line.strip().startswith("pkill -f") for line in script.splitlines())
print("PASS: failed-start repair latch, PID-verified teardown, no orphan-retry loop")
