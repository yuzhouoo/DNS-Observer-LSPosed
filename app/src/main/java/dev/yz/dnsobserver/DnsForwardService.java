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

    private static volatile DnsForwardService instance;
    private volatile boolean starting;
    public static void cancelPendingStart(){
        DnsForwardService s=instance;if(s!=null)s.cancellationRequested=true;
    }
    public static boolean isStarting(){DnsForwardService s=instance;return s!=null && s.starting;}
    @Override public void onCreate(){super.onCreate();instance=this;}
    public static boolean isServing(){
        DnsForwardService s=instance;
        return s!=null && s.running && s.activated && s.udp4!=null && !s.udp4.isClosed()
            && s.tcp4!=null && !s.tcp4.isClosed();
    }
    /** Repair through the living owner; preserve its session token and stop lock. */
    public static boolean reapplyRules() throws Exception {
        DnsForwardService owner=instance;
        if(owner==null)return false;
        synchronized(owner.firewallLock){
            if(owner!=instance || !isServing() || owner.cancellationRequested ||
                !owner.getSharedPreferences(PREFS,MODE_PRIVATE).getBoolean("takeover_enabled",false))return false;
            DnsStateEpoch.begin();
            try{
                DnsRootRules.install(owner,owner.useIpv6,owner.session);
                return !owner.cancellationRequested && isServing() && DnsRootRules.active(owner);
            }finally{DnsStateEpoch.end();}
        }
    }
    private volatile boolean running, activated;
    private volatile boolean cancellationRequested;
    private final Object firewallLock = new Object();
    private volatile InetAddress[] upstream = new InetAddress[0];
    private volatile String host, backupIp, secondaryHost, subHost;
    // Legacy secondary_* settings remain the third "备" group; sub_* is the new "从" group.
    private volatile InetAddress[] secondaryUpstream=new InetAddress[0];
    private volatile InetAddress[] subUpstream=new InetAddress[0];
    private volatile int secondaryPort, subPort;
    private volatile DnsFailover rolePolicy = new DnsFailover(0,0);
    private volatile String activeIpText="";
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
        secondaryHost = intent.getStringExtra("secondary_host");
        secondaryPort = intent.getIntExtra("secondary_port",31017);
        subHost = intent.getStringExtra("sub_host");
        subPort = intent.getIntExtra("sub_port",31017);
        useIpv6 = intent.getBooleanExtra("ipv6", false);
        getSharedPreferences(PREFS, MODE_PRIVATE).edit().remove("ipv6_warning").apply();
        session = UUID.randomUUID().toString().replace("-", "");
        starting=true;
        manager = new Thread(this::startNow, "DNS-manager");
        manager.start();
        return START_NOT_STICKY;
    }

    private Notification forwardingNotification(String text){
        int flags=android.app.PendingIntent.FLAG_UPDATE_CURRENT|android.app.PendingIntent.FLAG_IMMUTABLE;
        android.app.PendingIntent open=android.app.PendingIntent.getActivity(this,53,new Intent(this,DnsControlActivity.class),flags);
        android.app.PendingIntent stop=android.app.PendingIntent.getService(this,55,new Intent(this,DnsTakeoverService.class).setAction(DnsTakeoverService.ACTION_STOP),flags);
        return new Notification.Builder(this,CHANNEL).setSmallIcon(R.drawable.ic_stat_dns)
            .setContentTitle(getString(R.string.app_name)+" · IPv4 DNS 接管").setContentText(text)
            .setContentIntent(open).addAction(new Notification.Action.Builder(android.R.drawable.ic_menu_close_clear_cancel,"停止接管",stop).build())
            .setOnlyAlertOnce(true).setOngoing(true).build();
    }
    private void showForeground() {
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= 26 && nm != null) {
            nm.createNotificationChannel(new NotificationChannel(CHANNEL,
                    "DNS 接管运行状态", NotificationManager.IMPORTANCE_LOW));
        }
        startForeground(NOTIFY_ID, forwardingNotification("准备检查上游与本地监听；实际状态见接管控制页"));
    }

    private void startNow(){
        DnsStateEpoch.begin();
        try{startNowInternal();}finally{DnsStateEpoch.end();}
    }
    private void startNowInternal() {
        writeState(false, "准备启动，正在进行 Bootstrap 与上游检测");
        try {
            // Root checks can take seconds; never block Android's Service main thread.
            if (useIpv6 && !DnsRootRules.supportsIpv6Nat(this)) {
                useIpv6 = false;
                getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                    .putString("ipv6_warning", "本机 ip6tables IPv6 NAT 不可用；已降级为仅 IPv4 DNS 接管，IPv6 DNS 未接管")
                    .apply();
            }
            if (host == null || host.trim().isEmpty() || host.length() > 253)
                throw new IllegalArgumentException("请填写上游 DNS 域名");
            if (port < 1 || port > 65535) throw new IllegalArgumentException("上游端口不合法");
            if (secondaryHost!=null && !secondaryHost.trim().isEmpty()
                    && (secondaryPort<1 || secondaryPort>65535)) throw new IllegalArgumentException("备 DNS 端口错误");
            if (subHost!=null && !subHost.trim().isEmpty()
                    && (subPort<1 || subPort>65535)) throw new IllegalArgumentException("从 DNS 端口错误");
            if (backupIp != null && !backupIp.trim().isEmpty()) DnsBootstrap.parseLiteral(backupIp.trim());
            // Clear stale IPv4 redirect before Bootstrap-only lookups.
            DnsRootRules.remove(this);
            if (cancellationRequested) throw new IOException("用户已取消 DNS 接管启动");
            try { upstream=DnsBootstrap.resolve(host.trim(), backupIp); }
            catch(Exception e) {upstream=new InetAddress[0];}
            if(subHost!=null && !subHost.trim().isEmpty()) {
                try {subUpstream=DnsBootstrap.resolve(subHost.trim(),backupIp);}
                catch(Exception e){subUpstream=new InetAddress[0];}
            }
            if(secondaryHost!=null && !secondaryHost.trim().isEmpty()) {
                try {secondaryUpstream=DnsBootstrap.resolve(secondaryHost.trim(),backupIp);}
                catch(Exception e){secondaryUpstream=new InetAddress[0];}
            }
            int initial=-1;
            for(int role=0;role<3;role++) {
                if(probeGroup(role)) {initial=role;break;}
            }
            if(initial<0)throw new IOException("主、从、备 DNS 都没有可用的 UDP/TCP DNS 响应");
            rolePolicy=new DnsFailover(initial,android.os.SystemClock.elapsedRealtime());
            saveActiveSnapshot();
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
            String warning=getSharedPreferences(PREFS, MODE_PRIVATE).getString("ipv6_warning", "");
            writeState(true, "接管已启动 · " + DnsFailover.NAMES[rolePolicy.current()]+" DNS"
                    +(warning.isEmpty()?"":" · "+warning));
            Thread health = new Thread(this::healthLoop, "DNS-health");
            health.setDaemon(true);
            health.start();
        } catch (Throwable failure) {
            writeState(false, "启动失败，已尝试回滚：" + brief(failure));
            stopNow();
        } finally {starting=false;}
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

    private InetAddress[] addressesFor(int role) {
        return role==0?upstream:role==1?subUpstream:secondaryUpstream;
    }
    private int portFor(int role) {return role==0?port:role==1?subPort:secondaryPort;}
    private String hostFor(int role) {return role==0?host:role==1?subHost:secondaryHost;}

    private byte[] forward(byte[] request, boolean tcp) throws Exception {
        if(!DnsPacket.validQuestion(request))return DnsPacket.servfail(request);
        final int initiallyActive=rolePolicy.current();
        Exception last=null;
        // Active first, then other configured servers by fixed priority (主->从->备).
        for(int pass=0;pass<3;pass++) {
            int role=pass==0?initiallyActive:(pass<=initiallyActive?pass-1:pass);
            InetAddress[] choices=addressesFor(role);
            if(choices==null||choices.length==0)continue;
            int targetPort=portFor(role);
            for(int i=0;i<choices.length;i++) {
                InetAddress addr=choices[Math.floorMod(cursor.getAndIncrement(),choices.length)];
                try {
                    byte[] answer;
                    if(tcp) answer=forwardTcp(addr,request,targetPort);
                    else {
                        try {answer=forwardUdp(addr,request,targetPort);}
                        catch(Exception udpFailed) {
                            // A TCP-only DNS server must not be marked unreachable.
                            answer=forwardTcp(addr,request,targetPort);
                        }
                    }
                    if(!DnsPacket.validReply(request,answer))throw new IOException("DNS 响应 ID/QR 不匹配");
                    int rcode=answer[3]&15;
                    if(rcode==2||rcode==5)throw new IOException("上游返回 RCODE="+rcode);
                    failures.set(0);
                    boolean switched=rolePolicy.onForward(initiallyActive,role,
                            android.os.SystemClock.elapsedRealtime());
                    if(switched)saveActiveSnapshot();
                    return answer;
                } catch(Exception e){last=e;}
            }
        }
        failures.incrementAndGet();
        throw last==null?new IOException("主、从、备 DNS 均不可用"):last;
    }

    private byte[] forwardUdp(InetAddress address, byte[] req) throws Exception {
        return forwardUdp(address,req,port);
    }
    private byte[] forwardUdp(InetAddress address, byte[] req,int targetPort) throws Exception {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.connect(new InetSocketAddress(address, targetPort));
            socket.setSoTimeout(TIMEOUT);
            socket.send(new DatagramPacket(req, req.length));
            byte[] buf = new byte[MAX_QUERY];
            DatagramPacket packet = new DatagramPacket(buf, buf.length);
            socket.receive(packet);
            byte[] ans = Arrays.copyOf(buf, packet.getLength());
            if (DnsPacket.validReply(req, ans) && DnsPacket.truncated(ans)) {
                return forwardTcp(address, req,targetPort);
            }
            return ans;
        }
    }

    private byte[] forwardTcp(InetAddress address, byte[] request) throws Exception {
        return forwardTcp(address,request,port);
    }
    private byte[] forwardTcp(InetAddress address, byte[] request,int targetPort) throws Exception {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(address, targetPort), TIMEOUT);
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

    /** Start-up does a real DNS query over both transports, not a bare connect test. */
    private boolean probeGroup(int role) {
        InetAddress[] candidates=addressesFor(role);
        if(candidates==null||candidates.length==0)return false;
        int p=portFor(role);
        // Test up to 8 addresses at startup; the full per-IP sweep belongs to the speed test.
        for(int i=0;i<Math.min(8,candidates.length);i++) {
            InetAddress address=candidates[i];
            if(DnsProbe.measure(address,p,"UDP").success)return true;
            if(DnsProbe.measure(address,p,"TCP").success)return true;
        }
        return false;
    }

    private void healthLoop() {
        int checks=0;
        while(running) {
            try {Thread.sleep(60_000L);}catch(InterruptedException e){return;}
            if(!running)break;
            checks++;
            // IP refresh uses raw-IP Bootstrap only. Never call Android netd under REDIRECT.
            boolean refresh=checks%5==0 && backupIp!=null && !backupIp.trim().isEmpty();
            boolean full=checks%5==0;
            UpstreamMonitor.Result[] reports=new UpstreamMonitor.Result[3];
            boolean[] configured=new boolean[3],healthy=new boolean[3];
            for(int role=0;role<3 && running;role++) {
                String name=hostFor(role);
                configured[role]=name!=null&&!name.trim().isEmpty();
                if(!configured[role])continue;
                reports[role]=UpstreamMonitor.check(this,DnsFailover.NAMES[role],name,
                        portFor(role),refresh?backupIp:"",true,addressesFor(role),!full);
                healthy[role]=reports[role].success;
                if(refresh && healthy[role] && reports[role].ips.length>0) {
                    if(role==0)upstream=reports[role].ips;
                    else if(role==1)subUpstream=reports[role].ips;
                    else secondaryUpstream=reports[role].ips;
                }
            }
            if(!running)break;
            boolean any=false;for(boolean ok:healthy)any|=ok;
            if(!any) {
                writeState(true,"主、从、备 DNS 健康检测均失败；保留接管并等待下次检查");
                DnsTakeoverService.event(this,"DETECT: IPv4 上游全部不可用（未执行自动关闭）");
                continue;
            }
            if(rolePolicy.onHealth(configured,healthy,android.os.SystemClock.elapsedRealtime()))
                writeState(true,"DNS 优先级切换到 " + DnsFailover.NAMES[rolePolicy.current()]);
            saveActiveSnapshot();
            if(activated && !DnsRootRules.active(this)) {
                writeState(true,"接管规则不完整；等待接管守护开关处理");
                DnsTakeoverService.event(this,"DETECT: IPv4 DNS NAT 规则不完整");
            }
        }
    }
    private void saveActiveSnapshot() {
        int role=rolePolicy.current();
        InetAddress[] list=addressesFor(role);
        StringBuilder b=new StringBuilder();
        if(list!=null)for(InetAddress ip:list){if(b.length()>0)b.append(", ");b.append(ip.getHostAddress());}
        activeIpText=b.toString();
        String[] ipsByRole=new String[3];
        for(int i=0;i<3;i++) {
            StringBuilder roleIps=new StringBuilder();
            InetAddress[] set=addressesFor(i);
            if(set!=null)for(InetAddress ip:set){if(roleIps.length()>0)roleIps.append(",");roleIps.append(ip.getHostAddress());}
            ipsByRole[i]=roleIps.toString();
        }
        getSharedPreferences(PREFS,MODE_PRIVATE).edit()
                .putString("role_ips_0",ipsByRole[0])
                .putString("role_ips_1",ipsByRole[1])
                .putString("role_ips_2",ipsByRole[2])
                .putString("current_ip",activeIpText)
                .putString("active_host",hostFor(role))
                .putInt("active_port",portFor(role))
                .putString("active_role",DnsFailover.NAMES[role]).apply();
    }

    private synchronized void stopNow(){
        DnsStateEpoch.begin();
        try{stopNowInternal();}finally{DnsStateEpoch.end();}
    }
    private void stopNowInternal() {
        cancellationRequested = true;
        boolean wasActive;
        boolean ownsState=true;
        String recoveryError = null;
        synchronized (firewallLock) {
            wasActive = activated;
            running = false;
            activated = false;
            // Restore original DNS path BEFORE closing the sockets.
            try { if(session==null)DnsRootRules.remove(this);else ownsState=DnsRootRules.removeOwned(this,session); }
            catch (Exception e) { recoveryError = brief(e); }
        }
        close(udp4); close(udp6); close(tcp4); close(tcp6);
        if (workers != null) workers.shutdownNow();
        String previous = getSharedPreferences(PREFS, MODE_PRIVATE).getString("status", "");
        if(!ownsState){stopForeground(STOP_FOREGROUND_REMOVE);stopSelf();return;}
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
        if(isRunning)try{NotificationManager nm=(NotificationManager)getSystemService(NOTIFICATION_SERVICE);
            if(nm!=null)nm.notify(NOTIFY_ID,forwardingNotification(status));}catch(RuntimeException ignored){}

        getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                .putBoolean("running", isRunning).putString("status", status)
                .putLong("updated", System.currentTimeMillis()).apply();
    }
    @Override public void onDestroy() {
        if(instance==this)instance=null;
        cancellationRequested = true;
        if (running || activated) new Thread(this::stopNow, "DNS-destroy-cleanup").start();
        super.onDestroy();
    }
}
