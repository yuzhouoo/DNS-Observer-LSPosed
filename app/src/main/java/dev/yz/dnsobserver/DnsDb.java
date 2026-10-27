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
    private static final int VERSION = 1;
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
                "latency INTEGER NOT NULL)");
        db.execSQL("CREATE INDEX idx_dns_ts ON records(ts DESC)");
        db.execSQL("CREATE INDEX idx_dns_host ON records(host)");
        db.execSQL("CREATE INDEX idx_dns_uid ON records(uid)");
    }
    @Override public void onUpgrade(SQLiteDatabase db, int from, int to) { }

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
                "COALESCE(SUM(CASE WHEN rc != 0 THEN 1 ELSE 0 END),0) " +
                "FROM records", null)) {
            if (c.moveToFirst()) {
                stat.total = c.getInt(0);
                stat.domains = c.getInt(1);
                stat.failures = c.getInt(2);
            }
        }
        return stat;
    }

    public synchronized List<Entry> latest(String keyword, int filter) {
        List<Entry> result = new ArrayList<>();
        String sql = "SELECT ts,uid,packages,host,ips,total,net,eventType,rc,latency " +
                "FROM records WHERE 1=1";
        ArrayList<String> args = new ArrayList<>();
        if (filter == 1) sql += " AND rc = 0";
        if (filter == 2) sql += " AND rc != 0";
        if (keyword != null && !keyword.trim().isEmpty()) {
            // Escape LIKE wildcards so searching '_' or '%' means literal text.
            String needle = keyword.trim().replace("\\", "\\\\")
                    .replace("%", "\\%").replace("_", "\\_");
            sql += " AND (host LIKE ? ESCAPE '\\' OR packages LIKE ? ESCAPE '\\' " +
                    "OR ips LIKE ? ESCAPE '\\')";
            for (int i = 0; i < 3; i++) args.add("%" + needle + "%");
        }
        sql += " ORDER BY id DESC LIMIT " + PAGE_SIZE;
        try (Cursor c = getReadableDatabase().rawQuery(sql, args.toArray(new String[0]))) {
            while (c.moveToNext()) {
                Entry e = new Entry();
                e.ts = c.getLong(0); e.uid = c.getInt(1); e.packages = c.getString(2);
                e.host = c.getString(3); e.ips = c.getString(4); e.total = c.getInt(5);
                e.net = c.getInt(6); e.type = c.getInt(7); e.rc = c.getInt(8);
                e.latency = c.getInt(9);
                result.add(e);
            }
        }
        return result;
    }

    public synchronized void clearAll() {
        getWritableDatabase().delete("records", null, null);
    }

    public synchronized void exportAll(OutputStream out) throws IOException {
        // Output data is local to a user-selected Storage Access Framework URI.
        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(out, StandardCharsets.UTF_8));
        writer.write('\ufeff');
        writer.write("time,uid,packages,hostname,ipAddresses,totalIpCount,netId,eventType,returnCode,latencyMs\n");
        SimpleDateFormat date = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.getDefault());
        try (Cursor c = getReadableDatabase().rawQuery(
                "SELECT ts,uid,packages,host,ips,total,net,eventType,rc,latency FROM records ORDER BY id DESC", null)) {
            while (c.moveToNext()) {
                String[] values = {
                        date.format(new Date(c.getLong(0))), String.valueOf(c.getInt(1)),
                        c.getString(2), c.getString(3), c.getString(4),
                        String.valueOf(c.getInt(5)), String.valueOf(c.getInt(6)),
                        String.valueOf(c.getInt(7)), String.valueOf(c.getInt(8)),
                        String.valueOf(c.getInt(9))
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

    public static final class Stats { public int total, domains, failures; }
    public static final class Entry {
        public long ts;
        public int uid, total, net, type, rc, latency;
        public String packages, host, ips;
    }
}
