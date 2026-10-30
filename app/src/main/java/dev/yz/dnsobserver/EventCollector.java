package dev.yz.dnsobserver;

import android.content.ContentResolver;
import android.content.Context;
import android.net.Uri;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.content.pm.ApplicationInfo;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Process;
import android.os.SystemClock;
import android.util.Log;

import java.util.ArrayDeque;
import java.util.ArrayList;

/**
 * Runs entirely off system_server Binder callback threads.
 * Bounded memory queue and fail-open: DNS resolution must never depend on logging.
 */
public final class EventCollector {
    private static final EventCollector INSTANCE = new EventCollector();
    private static final int MAX_QUEUE = 1200;
    private static final int BATCH_SIZE = 40;
    private static final long FLUSH_MS = 2200L;
    private static final long RETRY_MS = 8000L;
    private static final long HEARTBEAT_MS = 10000L;
    private final ArrayDeque<Bundle> pending = new ArrayDeque<>();
    private Context context;
    private Handler worker;
    private long dropped;
    private String lastError = "";
    private long lastErrorLogMs;

    public static EventCollector get() { return INSTANCE; }
    private EventCollector() { }

    public synchronized void start(Context systemContext) {
        if (context != null || systemContext == null) return;
        context = systemContext;
        HttpObservationHooks.attach(systemContext);
        HandlerThread t = new HandlerThread("DnsObserverWriter", Process.THREAD_PRIORITY_BACKGROUND);
        t.start();
        worker = new Handler(t.getLooper());
        // Avoid trying to launch a third-party provider in early system boot.
        worker.postDelayed(flush, 12_000L);
        Log.i("DNSObserver", "DNSObserver: collector started");
    }

    public void accept(int netId, int eventType, int returnCode, int latency,
                       String hostname, String[] ips, int ipCount, int uid) {
        if (hostname == null || hostname.isEmpty()) return;
        Bundle item = new Bundle();
        item.putLong("ts", System.currentTimeMillis());
        item.putInt("net", netId);
        item.putInt("type", eventType);
        item.putInt("rc", returnCode);
        item.putInt("latency", Math.max(0, latency));
        item.putInt("uid", uid);
        item.putString("host", TextPolicy.clamp(hostname, 253));
        item.putInt("total", Math.max(0, ipCount));
        if (ips != null) {
            int size = Math.min(ips.length, 10);
            String[] copy = new String[size];
            for (int i = 0; i < size; i++) copy[i] = TextPolicy.clamp(ips[i], 64);
            item.putStringArray("ips", copy);
        }
        synchronized (this) {
            if (pending.size() >= MAX_QUEUE) {
                pending.removeFirst();
                dropped++;
            }
            pending.addLast(item);
        }
    }

    public void auxiliary(Bundle event){
        synchronized(this){if(pending.size()>=MAX_QUEUE){pending.removeFirst();dropped++;}pending.addLast(event);}
    }
    private final java.util.concurrent.ConcurrentHashMap<String,Long> privateEndpoints=new java.util.concurrent.ConcurrentHashMap<>();
    public void connection(int net,int error,int latency,String ip,int port,int uid){
        Long validated=privateEndpoints.get(ip);
        if(port!=853&&!(port==443&&validated!=null&&android.os.SystemClock.elapsedRealtime()-validated<1800000))return;
        Bundle b=new Bundle();b.putLong("ts",System.currentTimeMillis());b.putString("host",ip);
        b.putInt("uid",uid);b.putInt("net",net);b.putInt("rc",error);b.putInt("latency",latency);
        b.putString("recordKind","CONNECTION");b.putString("outcome","OBSERVED");b.putString("transport","SUSPECTED");
        b.putString("dnsType",port==853?"疑似加密 DNS：853 连接（DoT/DoQ 未区分）":"已验证 DNS 服务器的 443 连接（可能 DoH，未确认）");b.putString("dnsServer",ip+":"+port);
        b.putString("evidence",port==853?"CONNECT_PORT_853":"CONNECT_PRIVATE_DNS_443");b.putString("detail","connect 返回="+error+"；未观察到 TLS 内部查询内容，也不据此判断 DNS 成败");auxiliary(b);
    }
    public void validation(int net,String ip,String host,boolean valid){
        if(ip!=null){if(privateEndpoints.size()>64)privateEndpoints.clear();if(valid)privateEndpoints.put(ip,android.os.SystemClock.elapsedRealtime());else privateEndpoints.remove(ip);}
        Bundle b=new Bundle();b.putLong("ts",System.currentTimeMillis());b.putString("host",host==null||host.isEmpty()?ip:host);
        b.putInt("uid",1000);b.putInt("net",net);b.putInt("rc",valid?0:1);b.putString("recordKind","VALIDATION");
        b.putString("transport","UNKNOWN");b.putString("evidence","PRIVATE_DNS_VALIDATION");
        b.putString("dnsType","私人 DNS 验证事件（非逐查询协议）");b.putString("dnsServer",ip);
        b.putString("detail","私人 DNS 验证="+valid);auxiliary(b);
    }
    private static String[] describeNetwork(Context ctx) {
        try {
            ConnectivityManager cm=(ConnectivityManager)ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
            if(cm==null) return new String[]{"未知","未知","未获取到网络服务"};
            Network net=cm.getActiveNetwork();
            LinkProperties p=net==null?null:cm.getLinkProperties(net);
            if(p==null) return new String[]{"未知","未知","无默认网络配置"};
            StringBuilder servers=new StringBuilder();
            for(java.net.InetAddress ip:p.getDnsServers()) {
                if(servers.length()>0)servers.append(", ");
                servers.append(ip.getHostAddress());
            }
            boolean dot=p.isPrivateDnsActive();
            String privateName=p.getPrivateDnsServerName();
            String kind=dot?"私人 DNS 加密配置已启用（协议未证实）":"系统解析器（传输协议未证实）";
            if(dot && privateName!=null && !privateName.isEmpty()) {
                if(servers.length()>0)servers.append(" | ");
                servers.append("Private DNS: ").append(privateName);
            }
            return new String[]{kind, servers.length()==0?"未配置":servers.toString(),
                    "默认网络配置快照，非单次请求抓包"};
        } catch(Throwable t) {return new String[]{"未知","未知","读取系统 DNS 配置失败"};}
    }

    private final Runnable flush = new Runnable() {
        @Override public void run() {
            long delay = FLUSH_MS;
            ArrayList<Bundle> batch = new ArrayList<>();
            try {
                Context ctx;
                long lost;
                synchronized (EventCollector.this) {
                    ctx = context;
                    for (int i = 0; i < BATCH_SIZE && !pending.isEmpty(); i++) {
                        batch.add(pending.removeFirst());
                    }
                    lost = dropped;
                }
                if (ctx != null) {
                    // UID -> packages resolved on this background thread with system privileges.
                    // Package visibility restrictions on the UI app cannot hide package names.
                    // Provider enriches each event by its own NetID, not one batch-wide default network.
                    for (Bundle event : batch) {

                        int uid = event.getInt("uid", -1);
                        String[] names = ctx.getPackageManager().getPackagesForUid(uid);
                        if (names != null && names.length > 0) {
                            event.putString("packages", TextPolicy.clamp(
                                    android.text.TextUtils.join(", ", names), 400));
                            // Shared UIDs may contain multiple packages. Try each label.
                            for (String pkg : names) {
                                try {
                                    ApplicationInfo ai=ctx.getPackageManager().getApplicationInfo(pkg,0);
                                    CharSequence name=ctx.getPackageManager().getApplicationLabel(ai);
                                    if(name!=null && name.length()>0) {
                                        event.putString("appName",TextPolicy.clamp(name.toString(),160));
                                        break;
                                    }
                                } catch(Throwable ignored) { }
                            }
                        }
                    }
                    Bundle payload = new Bundle();
                    payload.putParcelableArrayList("events", batch);
                    payload.putLong("dropped", lost);
                    payload.putLong("bootUptime", SystemClock.elapsedRealtime());
                    payload.putString("error", lastError);
                    ContentResolver cr = ctx.getContentResolver();
                    Bundle response = cr.call(Uri.parse("content://" + SecureProvider.AUTHORITY),
                            "appendBatch", null, payload);
                    if (response == null || !response.getBoolean("ok", false)) {
                        throw new IllegalStateException("provider unavailable");
                    }
                    batch.clear();
                    lastError = "";
                }
                synchronized (EventCollector.this) {
                    if (!pending.isEmpty()) delay = 120L;
                }
            } catch (Throwable t) {
                String error = t.getClass().getSimpleName() + ": "
                        + TextPolicy.clamp(t.getMessage(), 100);
                long now = SystemClock.elapsedRealtime();
                if (!error.equals(lastError) || now - lastErrorLogMs > 60_000L) {
                    Log.w("DNSObserver", "DNSObserver: IPC retry: " + error);
                    lastErrorLogMs = now;
                }
                lastError = error;
                delay = RETRY_MS;
                // Restore the failed batch at the head, preserving order as much as possible.
                synchronized (EventCollector.this) {
                    for (int i = batch.size() - 1; i >= 0; i--) {
                        if (pending.size() >= MAX_QUEUE) {
                            pending.removeLast();
                            dropped++;
                        }
                        pending.addFirst(batch.get(i));
                    }
                }
            } finally {
                Handler handler;
                synchronized (EventCollector.this) { handler = worker; }
                if (handler != null) handler.postDelayed(this, delay);
            }
        }
    };
}
