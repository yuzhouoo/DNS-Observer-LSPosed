package dev.yz.dnsobserver;

import android.content.ContentResolver;
import android.content.Context;
import android.net.Uri;
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
                    for (Bundle event : batch) {
                        int uid = event.getInt("uid", -1);
                        String[] names = ctx.getPackageManager().getPackagesForUid(uid);
                        if (names != null && names.length > 0) {
                            event.putString("packages", TextPolicy.clamp(
                                    android.text.TextUtils.join(", ", names), 400));
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
