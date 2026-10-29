from pathlib import Path
import xml.etree.ElementTree as ET
root=Path('app/src/main');a='{http://schemas.android.com/apk/res/android}'
manifest=ET.parse(root/'AndroidManifest.xml').getroot().find('application')
assert manifest.get(a+'label')=='@string/app_name'
assert manifest.get(a+'icon')==manifest.get(a+'roundIcon')=='@mipmap/ic_launcher'
strings={e.get('name'):e.text for e in ET.parse(root/'res/values/strings.xml').getroot()}
assert strings['app_name']=='域瞳'
for variant in ['mipmap-anydpi','mipmap-anydpi-v26','mipmap-anydpi-v33']:
 e=ET.parse(root/'res'/variant/'ic_launcher.xml').getroot()
 if variant.endswith('v33'):assert e.find('monochrome') is not None
for name in ['ic_launcher_foreground','ic_launcher_mono','ic_stat_dns']:
 e=ET.parse(root/'res/drawable'/f'{name}.xml').getroot()
 assert e.tag=='vector'
assert 'dev.yz.dnsobserver' in Path('app/build.gradle').read_text()
print('PASS: Chinese label, legacy/adaptive/monochrome launcher resources, status glyph and unchanged package identity')
