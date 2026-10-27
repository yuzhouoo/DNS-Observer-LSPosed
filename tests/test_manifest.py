import pathlib
import xml.etree.ElementTree as ET

root=pathlib.Path(__file__).resolve().parents[1]
manifest=ET.parse(root/"app/src/main/AndroidManifest.xml").getroot()
android="{http://schemas.android.com/apk/res/android}"
permissions={x.get(android+"name") for x in manifest.findall("uses-permission")}
assert "android.permission.ACCESS_NETWORK_STATE" in permissions, "ACCESS_NETWORK_STATE required for Android 14+ network-constrained JobScheduler"
assert "android.permission.QUERY_ALL_PACKAGES" in permissions, "Auditing arbitrary UIDs requires Android package-label visibility"
application=manifest.find("application")
assert any(x.get(android+"name")==".DnsControlActivity" for x in application.findall("activity")), "DNS control activity missing"
assert any(x.get(android+"name")==".DnsUpstreamJob" for x in application.findall("service")), "Upstream JobService missing"
code=(root/"app/src/main/java/dev/yz/dnsobserver/DnsUpstreamJob.java").read_text()
assert "catch (SecurityException" in code and "jobs.schedule(info)" in code, "Jobs must be safely scheduled"
code=(root/"app/src/main/java/dev/yz/dnsobserver/SecureProvider.java").read_text()
assert "DnsMetadata.enrichBatch" in code, "Provider metadata fallback missing"
print("PASS: manifest permissions, activity, JobService and DNS metadata fallback")
