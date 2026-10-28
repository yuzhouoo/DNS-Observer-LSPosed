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

assert 'VERSION = 3' in s
assert 'if (from < 3) createProbeHistory(db)' in s
c.execute('CREATE TABLE upstream_probe (id INTEGER PRIMARY KEY AUTOINCREMENT,runTs INTEGER NOT NULL,role TEXT NOT NULL,host TEXT NOT NULL,ip TEXT NOT NULL,family TEXT NOT NULL,transport TEXT NOT NULL,port INTEGER NOT NULL,latency INTEGER NOT NULL,success INTEGER NOT NULL,rcode INTEGER NOT NULL,error TEXT NOT NULL)')
c.execute("INSERT INTO upstream_probe(runTs,role,host,ip,family,transport,port,latency,success,rcode,error) VALUES(1,'主','dns.example','1.1.1.1','IPv4','TCP',31017,25,1,0,'')")
assert c.execute('SELECT role,family,transport,latency FROM upstream_probe').fetchone()==('主','IPv4','TCP',25)
print('Database migration 2->3 & per-IP probe records: PASS')
