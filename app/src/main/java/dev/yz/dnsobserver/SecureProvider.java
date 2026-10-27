package dev.yz.dnsobserver;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;
import android.os.Process;

import java.util.ArrayList;

/**
 * Deliberately exported for IPC from system_server only. All methods reject normal apps.
 * No query/insert/update/delete IPC endpoints; only app-local SQLite reads in Activity.
 */
public final class SecureProvider extends ContentProvider {
    public static final String AUTHORITY = "dev.yz.dnsobserver.events";
    public static final String PREFS = "observer";
    private DnsDb db;
    @Override public boolean onCreate() {
        db = new DnsDb(getContext());
        return true;
    }

    @Override public Bundle call(String method, String arg, Bundle extras) {
        if (!"appendBatch".equals(method)) throw new SecurityException("invalid operation");
        if (Binder.getCallingUid() != Process.SYSTEM_UID) throw new SecurityException("system only");
        Bundle result = new Bundle();
        if (extras == null) return result;
        SharedPreferences prefs = getContext().getSharedPreferences(PREFS, 0);
        // Always persist heartbeat even when logging is paused.
        prefs.edit().putLong("heartbeat", System.currentTimeMillis())
                .putLong("lost", Math.max(0L, extras.getLong("dropped", 0)))
                .putString("lastError", TextPolicy.clamp(extras.getString("error", ""), 120))
                .apply();
        if (prefs.getBoolean("enabled", true)) {
            ArrayList<Bundle> records = extras.getParcelableArrayList("events");
            if (records != null && records.size() <= 50) db.insertBatch(getContext(), records);
        }
        result.putBoolean("ok", true);
        result.putBoolean("enabled", prefs.getBoolean("enabled", true));
        return result;
    }

    private void deny() { throw new SecurityException("direct database access denied"); }
    @Override public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        deny(); return null;
    }
    @Override public Uri insert(Uri uri, ContentValues values) { deny(); return null; }
    @Override public int delete(Uri uri, String selection, String[] selectionArgs) { deny(); return 0; }
    @Override public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) { deny(); return 0; }
    @Override public String getType(Uri uri) { deny(); return null; }
}
