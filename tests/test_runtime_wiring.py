from pathlib import Path
import subprocess
root=Path(__file__).resolve().parents[1]
for s in (root/'module').glob('*.sh'):
 subprocess.run(['sh','-n',str(s)],check=True)
manifest=(root/'app/src/main/AndroidManifest.xml').read_text()
assert 'RuntimeControlActivity' in manifest
mod=root/'module'
assert not (mod/'bin/mihomo').exists(), 'Mihomo must not be bundled'
s=(mod/'supervisor.sh').read_text()
assert 'wanted' in s and 'disable' in s and 'while "$BASE/bin/yutong" pidcheck' in s
fw=(root/'runtime/internal/engine/firewall.go').read_text()
assert '0x0/0x20000000' in fw and 'dport","53"' in fw
assert 'ownership.json' in fw and 'expected-rules.json' in fw
ui=(root/'app/src/main/java/dev/yz/dnsobserver/RuntimeControlActivity.java').read_text()
assert 'apply("off")' in ui and 'apply("dns")' in ui and 'apply("proxy")' in ui
assert 'import-core' in (root/'app/src/main/java/dev/yz/dnsobserver/RootRuntimeBridge.java').read_text()
assert 'RootRuntimeBridge.selected(ctx)' in (root/'app/src/main/java/dev/yz/dnsobserver/DnsBootReceiver.java').read_text()
print('PASS: independent runtime module wiring, mode UI, owned firewall, no bundled Mihomo, Root boot ownership')
