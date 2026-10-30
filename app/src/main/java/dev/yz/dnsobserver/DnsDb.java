package dev.yz.dnsobserver;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.os.Bundle;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public final class DnsDb extends SQLiteOpenHelper {
    private static final String NAME = "dns_log.db";
    private static final int VERSION = 4;
    public static final int MAX_RECORDS = 20000;
    public static final int PAGE_SIZE = 120;
    private static final long KEEP_MS = 14L * 86400_000L;

    public DnsDb(Context ctx) { super(ctx, NAME, null, VERSION); }

    @Override public void onCreate(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE records (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "ts INTEGER NOT NULL, uid INTEGER NOT NULL, packages TEXT NOT NULL," +
                "host TEXT NOT NULL, ips TEXT NOT NULL, total INTEGER NOT NULL," +
                "net INTEGER NOT NULL, eventType INTEGER NOT NULL, rc INTEGER NOT NULL," +
                "latency INTEGER NOT NULL," +
                "appName TEXT NOT NULL DEFAULT '',dnsType TEXT NOT NULL DEFAULT '未知'," +
                "dnsServer TEXT NOT NULL DEFAULT '未知',dnsSource TEXT NOT NULL DEFAULT '未观测',"+
                "transport TEXT NOT NULL DEFAULT 'UNKNOWN',recordKind TEXT NOT NULL DEFAULT 'SYSTEM',"+
                "evidence TEXT NOT NULL DEFAULT 'SYSTEM_EVENT',detail TEXT NOT NULL DEFAULT '',outcome TEXT NOT NULL DEFAULT 'COMPLETED')");
        db.execSQL("CREATE INDEX idx_dns_ts ON records(ts DESC)");
        db.execSQL("CREATE INDEX idx_dns_host ON records(host)");
        db.execSQL("CREATE INDEX idx_dns_uid ON records(uid)");
        createUpstreamHistory(db);
        createProbeHistory(db);
    }
    private static void createUpstreamHistory(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE IF NOT EXISTS upstream_history (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT,ts INTEGER NOT NULL," +
                "role TEXT NOT NULL,host TEXT NOT NULL,ips TEXT NOT NULL," +
                "latency INTEGER NOT NULL,success INTEGER NOT NULL,error TEXT NOT NULL)");
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_upstream_ts ON upstream_history(ts DESC)");
    }
    /** Exact per-IP, per-transport historical DNS probing results. */
    private static void createProbeHistory(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE IF NOT EXISTS upstream_probe (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, runTs INTEGER NOT NULL," +
                "role TEXT NOT NULL, host TEXT NOT NULL, ip TEXT NOT NULL," +
                "family TEXT NOT NULL, transport TEXT NOT NULL, port INTEGER NOT NULL," +
                "latency INTEGER NOT NULL, success INTEGER NOT NULL," +
                "rcode INTEGER NOT NULL, error TEXT NOT NULL)");
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_upstream_probe ON upstream_probe(runTs DESC)");
    }
    @Override public void onUpgrade(SQLiteDatabase db, int from, int to) {
        if (from < 2) {
            db.execSQL("ALTER TABLE records ADD COLUMN appName TEXT NOT NULL DEFAULT ''");
            db.execSQL("ALTER TABLE records ADD COLUMN dnsType TEXT NOT NULL DEFAULT '未知'");
            db.execSQL("ALTER TABLE records ADD COLUMN dnsServer TEXT NOT NULL DEFAULT '未知'");
            db.execSQL("ALTER TABLE records ADD COLUMN dnsSource TEXT NOT NULL DEFAULT '未观测'");
            createUpstreamHistory(db);
        }
        if (from < 3) createProbeHistory(db);
        if(from<4){
            db.execSQL("ALTER TABLE records ADD COLUMN transport TEXT NOT NULL DEFAULT 'UNKNOWN'");
            db.execSQL("ALTER TABLE records ADD COLUMN recordKind TEXT NOT NULL DEFAULT 'SYSTEM'");
            db.execSQL("ALTER TABLE records ADD COLUMN evidence TEXT NOT NULL DEFAULT 'SYSTEM_EVENT'");
            db.execSQL("ALTER TABLE records ADD COLUMN detail TEXT NOT NULL DEFAULT ''");
            db.execSQL("ALTER TABLE records ADD COLUMN outcome TEXT NOT NULL DEFAULT 'COMPLETED'");
        }
    }

    public synchronized void insertBatch(Context context, ArrayList<Bundle> events) {
        if (events == null || events.isEmpty()) return;
        SQLiteDatabase db = getWritableDatabase();
        db.beginTransaction();
        try {
            for (Bundle item : events) {
                if (item == null) continue;
                String host = TextPolicy.clamp(item.getString("host", ""), 253);
                if (host.isEmpty()) continue;
                int uid = item.getInt("uid", -1);
                String pkg = TextPolicy.clamp(item.getString("packages", ""), 400);
                if (pkg.isEmpty()) pkg = "UID " + uid;
                String[] ips = item.getStringArray("ips");
                String addr = ips == null ? "" : TextPolicy.clamp(android.text.TextUtils.join(", ", ips), 700);
                ContentValues cv = new ContentValues();
                cv.put("ts", item.getLong("ts", System.currentTimeMillis()));
                cv.put("uid", uid);
                cv.put("packages", pkg);
                cv.put("appName", TextPolicy.clamp(item.getString("appName", ""), 160));
                cv.put("dnsType", TextPolicy.clamp(item.getString("dnsType", "未知"), 70));
                cv.put("dnsServer", TextPolicy.clamp(item.getString("dnsServer", "未知"), 350));
                cv.put("dnsSource", TextPolicy.clamp(item.getString("dnsSource", "未观测"), 80));
                for(String field:new String[]{"transport","recordKind","evidence","detail","outcome"})
                    cv.put(field,TextPolicy.clamp(item.getString(field,field.equals("transport")?"UNKNOWN":field.equals("recordKind")?"SYSTEM":field.equals("evidence")?"SYSTEM_EVENT":field.equals("outcome")?"COMPLETED":""),field.equals("detail")?2500:80));
                cv.put("host", host);
                cv.put("ips", addr);
                cv.put("total", item.getInt("total", 0));
                cv.put("net", item.getInt("net", 0));
                cv.put("eventType", item.getInt("type", 0));
                cv.put("rc", item.getInt("rc", 0));
                cv.put("latency", Math.max(0, item.getInt("latency", 0)));
                db.insertOrThrow("records", null, cv);
            }
            // Bound both count and lifetime; deletes only at batch granularity.
            db.execSQL("DELETE FROM records WHERE ts < ?", new Object[]{System.currentTimeMillis() - KEEP_MS});
            db.execSQL("DELETE FROM records WHERE id NOT IN " +
                    "(SELECT id FROM records ORDER BY id DESC LIMIT " + MAX_RECORDS + ")");
            db.setTransactionSuccessful();
        } finally { db.endTransaction(); }
    }

    public synchronized Stats stats() {
        Stats stat = new Stats();
        SQLiteDatabase db = getReadableDatabase();
        try (Cursor c = db.rawQuery("SELECT COUNT(*), COUNT(DISTINCT host), " +
                "COALESCE(SUM(CASE WHEN rc != 0 AND outcome='COMPLETED' THEN 1 ELSE 0 END),0) " +
                "FROM records", null)) {
            if (c.moveToFirst()) {
                stat.total = c.getInt(0);
                stat.domains = c.getInt(1);
                stat.failures = c.getInt(2);
            }
        }
        return stat;
    }

    public synchronized List<Entry> latest(String keyword,int filter){return latest(keyword,filter,"全部");}
    public synchronized List<Entry> latest(String keyword, int filter,String protocol) {
        List<Entry> result = new ArrayList<>();
        String sql = "SELECT ts,uid,packages,host,ips,total,net,eventType,rc,latency " +
                " ,appName,dnsType,dnsServer,dnsSource,transport,recordKind,evidence,detail,outcome FROM records WHERE 1=1";
        ArrayList<String> args = new ArrayList<>();
        if (filter == 1) sql += " AND rc = 0 AND outcome='COMPLETED'";
        if (filter == 2) sql += " AND rc != 0 AND outcome='COMPLETED'";
        if(protocol!=null&&!"全部".equals(protocol)){
            if("系统解析".equals(protocol))sql+=" AND recordKind='SYSTEM'";
            else if("关键词 / 疑似".equals(protocol))sql+=" AND (transport IN ('SUSPECTED','DoT?') OR evidence='HTTP_API_KEYWORD')";
            else if("协议未知".equals(protocol))sql+=" AND transport='UNKNOWN'";
            else {sql+=" AND transport=?";args.add(protocol);}
        }
        if (keyword != null && !keyword.trim().isEmpty()) {
            // Escape LIKE wildcards so searching '_' or '%' means literal text.
            String needle = keyword.trim().replace("\\", "\\\\")
                    .replace("%", "\\%").replace("_", "\\_");
            sql += " AND (host LIKE ? ESCAPE '\\' OR packages LIKE ? ESCAPE '\\' " +
                    "OR ips LIKE ? ESCAPE '\\' OR appName LIKE ? ESCAPE '\\' " +
                    "OR dnsServer LIKE ? ESCAPE '\\' OR detail LIKE ? ESCAPE '\\' OR evidence LIKE ? ESCAPE '\\')";
            for (int i = 0; i < 7; i++) args.add("%" + needle + "%");
        }
        sql += " ORDER BY id DESC LIMIT " + PAGE_SIZE;
        try (Cursor c = getReadableDatabase().rawQuery(sql, args.toArray(new String[0]))) {
            while (c.moveToNext()) {
                Entry e = new Entry();
                e.ts = c.getLong(0); e.uid = c.getInt(1); e.packages = c.getString(2);
                e.host = c.getString(3); e.ips = c.getString(4); e.total = c.getInt(5);
                e.net = c.getInt(6); e.type = c.getInt(7); e.rc = c.getInt(8);
                e.latency = c.getInt(9);
                e.appName=c.getString(10); e.dnsType=c.getString(11);
                e.dnsServer=c.getString(12); e.dnsSource=c.getString(13);
                e.transport=c.getString(14);e.recordKind=c.getString(15);e.evidence=c.getString(16);e.detail=c.getString(17);e.outcome=c.getString(18);
                result.add(e);
            }
        }
        return result;
    }

    /**
     * Upgrade old v0.4.0 appName='' rows using newly visible app labels.
     * Never backfill DNS protocol/server: an old lookup has no recoverable
     * historical transport or server identity.
     * Called off the UI thread at most once per Activity instance.
     */
    public synchronized void backfillAppNames(Context context) {
        SQLiteDatabase sql = getWritableDatabase();
        java.util.LinkedHashMap<String,String> labels = new java.util.LinkedHashMap<>();
        try (Cursor c = sql.rawQuery(
                "SELECT DISTINCT packages FROM records WHERE appName='' OR appName='未知应用' LIMIT 600",
                null)) {
            while(c.moveToNext()) {
                String packageText=c.getString(0);
                if(packageText==null||packageText.isEmpty()||packageText.startsWith("UID ")) continue;
                String resolved="";
                for(String raw : packageText.split(",")) {
                    String pkg=raw.trim();
                    if(pkg.isEmpty())continue;
                    try {
                        android.content.pm.ApplicationInfo info=
                                context.getPackageManager().getApplicationInfo(pkg,0);
                        CharSequence found=context.getPackageManager().getApplicationLabel(info);
                        if(found!=null && found.length()>0) {
                            resolved=TextPolicy.clamp(found.toString(),160);
                            break;
                        }
                    } catch (Exception ignored) { }
                }
                if(!resolved.isEmpty()) labels.put(packageText,resolved);
            }
        }
        if(labels.isEmpty())return;
        sql.beginTransaction();
        try {
            for(java.util.Map.Entry<String,String> entry:labels.entrySet()) {
                ContentValues values=new ContentValues();
                values.put("appName",entry.getValue());
                sql.update("records",values,
                        "packages=? AND (appName='' OR appName='未知应用')",
                        new String[]{entry.getKey()});
            }
            sql.setTransactionSuccessful();
        } finally {sql.endTransaction();}
    }

    public synchronized void clearAll() {
        getWritableDatabase().delete("records", null, null);
    }

    public synchronized void exportAll(OutputStream out) throws IOException {
        // Output data is local to a user-selected Storage Access Framework URI.
        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(out, StandardCharsets.UTF_8));
        writer.write('\ufeff');
        writer.write("time,uid,packages,appName,hostname,ipAddresses,totalIpCount,netId,eventType,returnCode,latencyMs,dnsType,dnsServer,dnsSource,transport,recordKind,evidence,detail,outcome\n");
        SimpleDateFormat date = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.getDefault());
        try (Cursor c = getReadableDatabase().rawQuery(
                "SELECT ts,uid,packages,host,ips,total,net,eventType,rc,latency,appName,dnsType,dnsServer,dnsSource,transport,recordKind,evidence,detail,outcome FROM records ORDER BY id DESC", null)) {
            while (c.moveToNext()) {
                String[] values = {
                        date.format(new Date(c.getLong(0))), String.valueOf(c.getInt(1)),
                        c.getString(2), c.getString(10), c.getString(3), c.getString(4),
                        String.valueOf(c.getInt(5)), String.valueOf(c.getInt(6)),
                        String.valueOf(c.getInt(7)), String.valueOf(c.getInt(8)),
                        String.valueOf(c.getInt(9)),c.getString(11),c.getString(12),c.getString(13),c.getString(14),c.getString(15),c.getString(16),c.getString(17),c.getString(18)
                };
                for (int i = 0; i < values.length; i++) {
                    if (i != 0) writer.write(',');
                    writer.write(TextPolicy.csv(values[i]));
                }
                writer.write('\n');
            }
        }
        writer.flush();
    }


    /** Historical observations: every check is written, IP changes remain visible. */
    public synchronized void addUpstreamCheck(String role,String host,String ips,long latency,boolean ok,String error) {
        SQLiteDatabase db=getWritableDatabase();
        ContentValues v=new ContentValues();
        v.put("ts",System.currentTimeMillis());v.put("role",TextPolicy.clamp(role,16));
        v.put("host",TextPolicy.clamp(host,253));v.put("ips",TextPolicy.clamp(ips,700));
        v.put("latency",Math.max(0,Math.min(60000,latency)));v.put("success",ok?1:0);
        v.put("error",TextPolicy.clamp(error,160));
        db.insert("upstream_history",null,v);
        // Retain 30 days or 1000 most recent health samples, whichever is smaller.
        db.execSQL("DELETE FROM upstream_history WHERE ts < ?",new Object[]{System.currentTimeMillis()-30L*86400_000L});
        db.execSQL("DELETE FROM upstream_history WHERE id NOT IN (SELECT id FROM upstream_history ORDER BY id DESC LIMIT 1000)");
    }
    public synchronized List<UpstreamEntry> latestUpstream(int limit) {
        List<UpstreamEntry> out=new ArrayList<>();
        try(Cursor c=getReadableDatabase().rawQuery(
            "SELECT ts,role,host,ips,latency,success,error FROM upstream_history ORDER BY id DESC LIMIT "+Math.max(1,Math.min(limit,100)),null)) {
            while(c.moveToNext()) {
                UpstreamEntry e=new UpstreamEntry();e.ts=c.getLong(0);e.role=c.getString(1);
                e.host=c.getString(2);e.ips=c.getString(3);e.latency=c.getLong(4);
                e.success=c.getInt(5)!=0;e.error=c.getString(6);out.add(e);
            }
        }
        return out;
    }
    public synchronized void addProbeResult(String role,String host,int port,UpstreamMonitor.Result result) {
        addUpstreamCheck(role,host,result.addressText,result.latencyMs,result.success,result.error);
        if(result.samples.isEmpty())return;
        SQLiteDatabase db=getWritableDatabase();
        long now=System.currentTimeMillis();
        db.beginTransaction();
        try {
            for(DnsProbe.Sample item:result.samples) {
                ContentValues row=new ContentValues();
                row.put("runTs",now);row.put("role",TextPolicy.clamp(role,16));
                row.put("host",TextPolicy.clamp(host,253));row.put("ip",TextPolicy.clamp(item.ip,64));
                row.put("family",item.family);row.put("transport",item.transport);
                row.put("port",port);row.put("latency",item.latencyMs);
                row.put("success",item.success?1:0);row.put("rcode",item.responseCode);
                row.put("error",TextPolicy.clamp(item.error,160));
                db.insertOrThrow("upstream_probe",null,row);
            }
            db.execSQL("DELETE FROM upstream_probe WHERE runTs < ?",new Object[]{now-30L*86400_000L});
            db.execSQL("DELETE FROM upstream_probe WHERE id NOT IN (SELECT id FROM upstream_probe ORDER BY id DESC LIMIT 12000)");
            db.setTransactionSuccessful();
        } finally {db.endTransaction();}
    }
    public synchronized List<ProbeEntry> latestProbes(int limit) {
        List<ProbeEntry> out=new ArrayList<>();
        try(Cursor cursor=getReadableDatabase().rawQuery(
              "SELECT runTs,role,host,ip,family,transport,port,latency,success,rcode,error FROM upstream_probe ORDER BY id DESC LIMIT " +
              Math.max(1,Math.min(limit,400)),null)) {
            while(cursor.moveToNext()) {
                ProbeEntry e=new ProbeEntry();
                e.ts=cursor.getLong(0);e.role=cursor.getString(1);e.host=cursor.getString(2);
                e.ip=cursor.getString(3);e.family=cursor.getString(4);
                e.transport=cursor.getString(5);e.port=cursor.getInt(6);
                e.latency=cursor.getLong(7);e.success=cursor.getInt(8)!=0;
                e.rcode=cursor.getInt(9);e.error=cursor.getString(10);
                out.add(e);
            }
        }
        return out;
    }
    public static final class ProbeEntry {
        public long ts,latency;
        public String role,host,ip,family,transport,error;
        public int port,rcode;
        public boolean success;
    }
    public static final class UpstreamEntry {
        public long ts,latency; public boolean success; public String role,host,ips,error;
    }
    public static final class Stats { public int total, domains, failures; }
    public static final class Entry {
        public long ts;
        public int uid, total, net, type, rc, latency;
        public String packages, appName, host, ips, dnsType, dnsServer, dnsSource,transport,recordKind,evidence,detail,outcome;
    }
}
