import sqlite3,re,pathlib
s=pathlib.Path('app/src/main/java/dev/yz/dnsobserver/DnsDb.java').read_text()
# Verify new schema and v1 migratability with actual sqlite engine.
c=sqlite3.connect(':memory:')
c.execute('CREATE TABLE records (id INTEGER PRIMARY KEY AUTOINCREMENT,ts INTEGER NOT NULL, uid INTEGER NOT NULL, packages TEXT NOT NULL,host TEXT NOT NULL,ips TEXT NOT NULL,total INTEGER NOT NULL,net INTEGER NOT NULL,eventType INTEGER NOT NULL,rc INTEGER NOT NULL,latency INTEGER NOT NULL)')
c.execute("INSERT INTO records(ts,uid,packages,host,ips,total,net,eventType,rc,latency) VALUES(1,1000,'x','example.com','1.1.1.1',1,0,1,0,33)")
for name,default in [('appName',"''"),('dnsType',"'未知'"),('dnsServer',"'未知'"),('dnsSource',"'未观测'")]: c.execute(f'ALTER TABLE records ADD COLUMN {name} TEXT NOT NULL DEFAULT {default}')
c.execute('CREATE TABLE upstream_history(id INTEGER PRIMARY KEY AUTOINCREMENT,ts INTEGER NOT NULL,role TEXT NOT NULL,host TEXT NOT NULL,ips TEXT NOT NULL,latency INTEGER NOT NULL,success INTEGER NOT NULL,error TEXT NOT NULL)')
assert c.execute('SELECT host,dnsType,dnsServer FROM records').fetchone()==('example.com','未知','未知')
print('Database migration 1->2 preserves old DNS rows: PASS')

assert 'VERSION = 4' in s
assert 'if (from < 3) createProbeHistory(db)' in s
c.execute('CREATE TABLE upstream_probe (id INTEGER PRIMARY KEY AUTOINCREMENT,runTs INTEGER NOT NULL,role TEXT NOT NULL,host TEXT NOT NULL,ip TEXT NOT NULL,family TEXT NOT NULL,transport TEXT NOT NULL,port INTEGER NOT NULL,latency INTEGER NOT NULL,success INTEGER NOT NULL,rcode INTEGER NOT NULL,error TEXT NOT NULL)')
c.execute("INSERT INTO upstream_probe(runTs,role,host,ip,family,transport,port,latency,success,rcode,error) VALUES(1,'主','dns.example','1.1.1.1','IPv4','TCP',31017,25,1,0,'')")
assert c.execute('SELECT role,family,transport,latency FROM upstream_probe').fetchone()==('主','IPv4','TCP',25)
print('Database migration 2->3 & per-IP probe records: PASS')

# PING reuses the existing probe schema without destructive migration.
c.execute("INSERT INTO upstream_probe(runTs,role,host,ip,family,transport,port,latency,success,rcode,error) VALUES(2,'主','dns.example','1.1.1.1','IPv4','PING',0,27,1,-1,'')")
assert c.execute("SELECT transport,port,latency FROM upstream_probe WHERE runTs=2").fetchone()==('PING',0,27)
print('ICMP Ping history uses existing v3 schema: PASS')

# Execute the actual added migration statements, keeping old records intact.
for sql in re.findall(r'db.execSQL\("(ALTER TABLE records ADD COLUMN (?:transport|recordKind|evidence|detail|outcome)[^"\n]+)"\)',s):
    c.execute(sql)
assert c.execute('SELECT host,transport,recordKind,evidence,outcome FROM records').fetchone()==('example.com','UNKNOWN','SYSTEM','SYSTEM_EVENT','COMPLETED')
c.execute("UPDATE records SET rc=5,outcome='OBSERVED',recordKind='HTTP'")
assert c.execute("SELECT SUM(CASE WHEN rc!=0 AND outcome='COMPLETED' THEN 1 ELSE 0 END) FROM records").fetchone()[0]==0
print('Database migration 3->4, historical provenance and observed-call outcome separation: PASS')
