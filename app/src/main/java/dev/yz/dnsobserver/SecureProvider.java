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
 * Exported system event IPC plus explicit opt-in HTTP reports restricted by caller UID and user whitelist.
 * No database read or direct CRUD IPC; HTTP reports cannot forge UID or the system heartbeat.
 */
public final class SecureProvider extends ContentProvider {
    public static final String AUTHORITY = "dev.yz.dnsobserver.events";
    public static final String PREFS = "observer";
    private DnsDb db;
    private final java.util.HashMap<Integer,long[]> httpLimits=new java.util.HashMap<>();
    private synchronized boolean httpRate(int uid,int count){
        long minute=android.os.SystemClock.elapsedRealtime()/60000;
        if(httpLimits.size()>128){httpLimits.entrySet().removeIf(e->e.getValue()[0]!=minute);if(!httpLimits.containsKey(uid)&&httpLimits.size()>128)return false;}
        long[] value=httpLimits.get(uid);
        if(value==null||value[0]!=minute){value=new long[]{minute,0};httpLimits.put(uid,value);}
        if(count<1||count>20||value[1]+count>120)return false;value[1]+=count;return true;
    }
    private Bundle httpCall(String method,Bundle extras){
        int uid=Binder.getCallingUid();Bundle result=new Bundle();
        SharedPreferences p=getContext().getSharedPreferences(PREFS,0);
        String[] packages=getContext().getPackageManager().getPackagesForUid(uid);
        String allowed=p.getString("http_observe_packages","");boolean match=false;
        if(packages!=null)for(String pkg:packages)for(String entry:allowed.split("[,\\s]+"))if(pkg.equals(entry))match=true;
        boolean enabled=match&&p.getBoolean("enabled",true)&&p.getBoolean("detailed_observation",false);
        result.putBoolean("enabled",enabled);
        if(!enabled||!"appendHttp".equals(method)||extras==null)return result;
        ArrayList<Bundle> events=extras.getParcelableArrayList("events");
        if(events==null||!httpRate(uid,events.size()))return result;
        ArrayList<Bundle> records=new ArrayList<>();
        for(Bundle item:events){
            if(item==null)continue;
            DnsObservation.Http h=DnsObservation.http(item.getString("url","")+(item.getBoolean("dnsParam",false)?"?dns="+TextPolicy.clamp(item.getString("dnsQuery","REDACTED"),6000):""),item.getString("method"),item.getString("mime"));
            if(h==null)continue;
            Bundle b=new Bundle();b.putLong("ts",System.currentTimeMillis());b.putInt("uid",uid);
            b.putString("packages",android.text.TextUtils.join(", ",packages));b.putString("host",h.host);
            b.putString("recordKind","HTTP");b.putString("outcome","OBSERVED");b.putString("transport",h.transport);
            b.putString("dnsType",h.transport+"（应用 HTTP API 观察）");b.putString("dnsServer",h.url);
            b.putString("dnsSource","调用 UID 已校验；应用侧报告，未抓取 TLS 内部或实际回包");b.putString("evidence",h.evidence);
            b.putString("detail",h.method+" "+h.url+"\n"+h.detail+"\n应用补充："+TextPolicy.clamp(item.getString("queryHint",""),512)+"\n"+TextPolicy.clamp(item.getString("apiResult",""),100));
            records.add(b);
        }
        if(!records.isEmpty()){DnsMetadata.enrichBatch(getContext(),records);db.insertBatch(getContext(),records);}
        result.putBoolean("ok",true);return result;
    }
    @Override public boolean onCreate() {
        db = new DnsDb(getContext());
        return true;
    }

    @Override public Bundle call(String method, String arg, Bundle extras) {
        if("httpConfig".equals(method)||"appendHttp".equals(method))return httpCall(method,extras);
        if ("selfTest".equals(method)) {
            // App-local read-only check, NEVER writes or forges a system Hook heartbeat.
            if (Binder.getCallingUid() != Process.myUid()) throw new SecurityException("app only");
            Bundle out = new Bundle();
            out.putBoolean("ok", true);
            return out;
        }
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
            if (records != null && records.size() <= 50) {
                // system_server's environment may not expose a caller network/label.
                // Read a permission-backed network snapshot in the app process instead.
                if(!prefs.getBoolean("detailed_observation",false))records.removeIf(b->b!=null&&!"SYSTEM".equals(b.getString("recordKind","SYSTEM")));
                DnsMetadata.enrichBatch(getContext(), records);
                db.insertBatch(getContext(), records);
            }
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
