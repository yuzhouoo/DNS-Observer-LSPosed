package dev.yz.dnsobserver;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.IBinder;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/** User-started, non-boot, fail-open normal DNS UDP/TCP relay. */
public final class DnsForwardService extends Service {
    public static final String ACTION_START = "dev.yz.dnsobserver.START_DNS";
    public static final String ACTION_STOP = "dev.yz.dnsobserver.STOP_DNS";
    public static final String PREFS = "dns_proxy";
    private static final int NOTIFY_ID = 53;
    private static final String CHANNEL = "dns_forwarding";
    private static final int MAX_QUERY = 16384;
    private static final int TIMEOUT = 3000;

    private volatile boolean running, activated;
    private volatile boolean cancellationRequested;
    private final Object firewallLock = new Object();
    private volatile InetAddress[] upstream = new InetAddress[0];
    private volatile String host, backupIp;
    private volatile int port;
    private volatile boolean useIpv6;
    private volatile DatagramSocket udp4, udp6;
    private volatile ServerSocket tcp4, tcp6;
    private volatile ThreadPoolExecutor workers;
    private Thread manager;
    private final AtomicInteger failures = new AtomicInteger();
    private final AtomicInteger cursor = new AtomicInteger();
    private String session;

    @Override public IBinder onBind(Intent intent) { return null; }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) return START_NOT_STICKY;
        String action = intent.getAction();
        if (ACTION_STOP.equals(action)) {
            cancellationRequested = true;
            new Thread(this::stopNow, "DNS-stop").start();
            return START_NOT_STICKY;
        }
        if (!ACTION_START.equals(action) || manager != null) return START_NOT_STICKY;
        try {
            showForeground();
        } catch (Exception e) {
            writeState(false, "前台服务启动失败：" + e.getClass().getSimpleName());
            stopSelf();
            return START_NOT_STICKY;
        }
        host = intent.getStringExtra("host");
        backupIp = intent.getStringExtra("bootstrap");
        port = intent.getIntExtra("port", 31017);
        useIpv6 = intent.getBooleanExtra("ipv6", false);
        session = UUID.randomUUID().toString().replace("-", "");
        manager = new Thread(this::startNow, "DNS-manager");
        manager.start();
        return START_NOT_STICKY;
    }

    private void showForeground() {
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= 26 && nm != null) {
            nm.createNotificationChannel(new NotificationChannel(CHANNEL,
                    "DNS 接管运行状态", NotificationManager.IMPORTANCE_LOW));
        }
        Notification.Builder n = Build.VERSION.SDK_INT >= 26
                ? new Notification.Builder(this, CHANNEL) : new Notification.Builder(this);
        n.setSmallIcon(android.R.drawable.stat_sys_download_done)
                .setContentTitle("DNS Observer · DNS 接管")
                .setContentText("本地 DNS 服务运行中，可在 App 内一键关闭")
                .setOngoing(true);
        startForeground(NOTIFY_ID, n.build());
    }

    private void startNow() {
        writeState(false, "准备启动，正在进行 Bootstrap 与上游检测");
        try {
            if (host == null || host.trim().isEmpty() || host.length() > 253)
                throw new IllegalArgumentException("请填写上游 DNS 域名");
            if (port < 1 || port > 65535) throw new IllegalArgumentException("上游端口不合法");
            if (backupIp != null && !backupIp.trim().isEmpty()) DnsBootstrap.parseLiteral(backupIp.trim());
            // Clear a stale redirect BEFORE asking Android's system resolver.
            // Even our app's getAllByName may be sent over netd/dnsresolver UID.
            DnsRootRules.remove(this);
            if (cancellationRequested) throw new IOException("用户已取消 DNS 接管启动");
            InetAddress[] resolved = DnsBootstrap.resolve(host.trim(), backupIp);
            if (resolved.length == 0) throw new IOException("无法解析上游 DNS 域名");
            upstream = resolved;
            // Proof of protocol response BEFORE touching firewall rules.
            if (!probeUpstream()) throw new IOException("上游 DNS UDP 服务器未返回有效响应");
            if (cancellationRequested) throw new IOException("用户已取消 DNS 接管启动");
            bindSockets();
            workers = new ThreadPoolExecutor(4, 10, 30, TimeUnit.SECONDS,
                    new ArrayBlockingQueue<>(200));
            running = true;
            startListeners();
            // Serialize installation/removal to prevent a late install after STOP.
            synchronized (firewallLock) {
                if (cancellationRequested) throw new IOException("用户已取消 DNS 接管启动");
                DnsRootRules.install(this, useIpv6, session);
                activated = true;
            }
            if (cancellationRequested) { stopNow(); return; }
            writeState(true, "接管已启动 · " + resolved.length + " 个上游地址");
            Thread health = new Thread(this::healthLoop, "DNS-health");
            health.setDaemon(true);
            health.start();
        } catch (Throwable failure) {
            writeState(false, "启动失败，已尝试回滚：" + brief(failure));
            stopNow();
        }
    }

    private void bindSockets() throws Exception {
        udp4 = new DatagramSocket(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), DnsRootRules.PORT));
        tcp4 = new ServerSocket(DnsRootRules.PORT, 64, InetAddress.getByName("127.0.0.1"));
        if (useIpv6) {
            udp6 = new DatagramSocket(new InetSocketAddress(InetAddress.getByName("::1"), DnsRootRules.PORT));
            tcp6 = new ServerSocket(DnsRootRules.PORT, 64, InetAddress.getByName("::1"));
        }
    }

    private void startListeners() {
        new Thread(() -> serveUdp(udp4), "DNS-UDP4").start();
        new Thread(() -> serveTcp(tcp4), "DNS-TCP4").start();
        if (useIpv6) {
            new Thread(() -> serveUdp(udp6), "DNS-UDP6").start();
            new Thread(() -> serveTcp(tcp6), "DNS-TCP6").start();
        }
    }

    private void serveUdp(DatagramSocket socket) {
        while (running && socket != null && !socket.isClosed()) {
            try {
                byte[] buf = new byte[MAX_QUERY];
                DatagramPacket incoming = new DatagramPacket(buf, buf.length);
                socket.receive(incoming);
                final byte[] request = Arrays.copyOf(incoming.getData(), incoming.getLength());
                final InetAddress source = incoming.getAddress();
                final int sourcePort = incoming.getPort();
                try {
                    workers.execute(() -> {
                        byte[] result;
                        try { result = forward(request, false); }
                        catch (Exception ex) { result = DnsPacket.servfail(request); }
                        if (result != null && !socket.isClosed()) {
                            try { socket.send(new DatagramPacket(result, result.length, source, sourcePort)); }
                            catch (Exception ignored) { }
                        }
                    });
                } catch (java.util.concurrent.RejectedExecutionException rejected) {
                    byte[] fail = DnsPacket.servfail(request);
                    if (fail != null) socket.send(new DatagramPacket(fail, fail.length, source, sourcePort));
                }
            } catch (Exception e) {
                if (!running) break;
            }
        }
    }

    private void serveTcp(ServerSocket server) {
        while (running && server != null && !server.isClosed()) {
            try {
                Socket client = server.accept();
                client.setSoTimeout(TIMEOUT + 1500);
                try { workers.execute(() -> handleTcp(client)); }
                catch (java.util.concurrent.RejectedExecutionException e) { client.close(); }
            } catch (IOException ignored) {
                if (!running) break;
            }
        }
    }

    private void handleTcp(Socket socket) {
        try (Socket client = socket) {
            DataInputStream in = new DataInputStream(new BufferedInputStream(client.getInputStream()));
            DataOutputStream out = new DataOutputStream(new BufferedOutputStream(client.getOutputStream()));
            // One query per connection for bounded resource use.
            int len = in.readUnsignedShort();
            if (len < 12 || len > MAX_QUERY) return;
            byte[] request = new byte[len];
            in.readFully(request);
            byte[] answer;
            try { answer = forward(request, true); }
            catch (Exception e) { answer = DnsPacket.servfail(request); }
            if (answer != null) {
                out.writeShort(answer.length); out.write(answer); out.flush();
            }
        } catch (Exception ignored) { }
    }

    private byte[] forward(byte[] request, boolean tcp) throws Exception {
        if (!DnsPacket.validQuestion(request)) return DnsPacket.servfail(request);
        InetAddress[] choices = upstream;
        if (choices.length == 0) throw new IOException("no upstream addresses");
        Exception last = null;
        for (int i = 0; i < choices.length; i++) {
            InetAddress addr = choices[Math.floorMod(cursor.getAndIncrement(), choices.length)];
            try {
                byte[] answer = tcp ? forwardTcp(addr, request) : forwardUdp(addr, request);
                if (!DnsPacket.validReply(request, answer)) throw new IOException("DNS response ID/QR mismatch");
                failures.set(0);
                return answer;
            } catch (Exception e) { last = e; }
        }
        failures.incrementAndGet();
        throw last == null ? new IOException("上游不可用") : last;
    }

    private byte[] forwardUdp(InetAddress address, byte[] req) throws Exception {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.connect(new InetSocketAddress(address, port));
            socket.setSoTimeout(TIMEOUT);
            socket.send(new DatagramPacket(req, req.length));
            byte[] buf = new byte[MAX_QUERY];
            DatagramPacket packet = new DatagramPacket(buf, buf.length);
            socket.receive(packet);
            byte[] ans = Arrays.copyOf(buf, packet.getLength());
            if (DnsPacket.validReply(req, ans) && DnsPacket.truncated(ans)) {
                return forwardTcp(address, req);
            }
            return ans;
        }
    }

    private byte[] forwardTcp(InetAddress address, byte[] request) throws Exception {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(address, port), TIMEOUT);
            socket.setSoTimeout(TIMEOUT);
            DataOutputStream out = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));
            out.writeShort(request.length); out.write(request); out.flush();
            DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            int length = in.readUnsignedShort();
            if (length < 12 || length > MAX_QUERY) throw new IOException("bad TCP DNS length");
            byte[] result = new byte[length]; in.readFully(result);
            return result;
        }
    }

    private boolean probeUpstream() {
        byte[] query = DnsPacket.probeQuestion();
        InetAddress[] addresses = upstream;
        for (InetAddress candidate : addresses) {
            try { if (DnsPacket.validReply(query, forwardUdp(candidate, query))) return true; }
            catch (Exception ignored) { }
        }
        return false;
    }

    private void healthLoop() {
        int checks = 0;
        while (running) {
            try { Thread.sleep(12000L); } catch (InterruptedException ignored) { break; }
            if (!running) break;
            if (failures.get() >= 5 && !probeUpstream()) {
                writeState(false, "上游连续请求失败，已触发自动恢复");
                stopNow(); return;
            }
            // Never call system getAllByName while redirect is active: on Android
            // the resolver's network packets may have the dnsresolver UID, not app UID.
            // Only explicitly configured raw-IP Bootstrap is safe during interception.
            if (++checks % 25 == 0 && backupIp != null && !backupIp.trim().isEmpty()) {
                try {
                    InetAddress[] latest = DnsBootstrap.resolveOnlyViaBackup(host.trim(), backupIp);
                    if (latest.length > 0) upstream = latest;
                } catch (Exception ignored) { /* Keep the last known addresses. */ }
            }
            if (activated && !DnsRootRules.active(this)) {
                writeState(false, "检测到接管规则不完整，已关闭");
                stopNow(); return;
            }
        }
    }

    private synchronized void stopNow() {
        cancellationRequested = true;
        boolean wasActive;
        String recoveryError = null;
        synchronized (firewallLock) {
            wasActive = activated;
            running = false;
            activated = false;
            // Restore original DNS path BEFORE closing the sockets.
            try { DnsRootRules.remove(this); }
            catch (Exception e) { recoveryError = brief(e); }
        }
        close(udp4); close(udp6); close(tcp4); close(tcp6);
        if (workers != null) workers.shutdownNow();
        String previous = getSharedPreferences(PREFS, MODE_PRIVATE).getString("status", "");
        if (recoveryError != null) writeState(false, "警告：Root 规则可能未恢复：" + recoveryError);
        else if (wasActive || !previous.contains("失败")) writeState(false, "接管已关闭，DNS 恢复为系统路径");
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
    }

    private static void close(DatagramSocket socket) { if (socket != null) socket.close(); }
    private static void close(ServerSocket socket) { try { if (socket != null) socket.close(); } catch (Exception ignored) { } }
    private static String brief(Throwable t) {
        String msg = t.getMessage();
        return t.getClass().getSimpleName() + (msg == null ? "" : ": " + TextPolicy.clamp(msg, 160));
    }
    private void writeState(boolean isRunning, String status) {
        getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                .putBoolean("running", isRunning).putString("status", status)
                .putLong("updated", System.currentTimeMillis()).apply();
    }
    @Override public void onDestroy() {
        cancellationRequested = true;
        if (running || activated) new Thread(this::stopNow, "DNS-destroy-cleanup").start();
        super.onDestroy();
    }
}
