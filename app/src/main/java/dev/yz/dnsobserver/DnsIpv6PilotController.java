package dev.yz.dnsobserver;

import android.content.Context;
import android.content.SharedPreferences;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/** Manual, time-limited pilot, deliberately separate from IPv4 DNS service. */
public final class DnsIpv6PilotController {
    private static final Object LOCK=new Object();
    private static final String TARGET="2001:db8:ffff::53";
    private static final int PORT=53;
    private static java.lang.Process daemon;
    private static String token;
    private static boolean starting,ownsRules;
    private static int probes;
    private static final java.util.concurrent.atomic.AtomicInteger udpOk=new java.util.concurrent.atomic.AtomicInteger();
    private static final java.util.concurrent.atomic.AtomicInteger tcpOk=new java.util.concurrent.atomic.AtomicInteger();
    private static final LinkedBlockingQueue<String> signals=new LinkedBlockingQueue<>();
    private DnsIpv6PilotController(){}
    private static final class Endpoint {
        final InetAddress ip;final int port;
        Endpoint(InetAddress ip,int port){this.ip=ip;this.port=port;}
    }
    private static void log(Context ctx,String line){
        SharedPreferences prefs=ctx.getSharedPreferences(DnsForwardService.PREFS,Context.MODE_PRIVATE);
        synchronized(DnsIpv6PilotController.class){
            String old=prefs.getString("ipv6_pilot_log","");
            String newer=(old+line+"\n");
            if(newer.length()>10000)newer="[较早日志已自动折叠]\n"+newer.substring(newer.length()-9500);
            prefs.edit().putString("ipv6_pilot_log",newer).apply();
        }
    }
    public static void clearLog(Context ctx) {
        synchronized(DnsIpv6PilotController.class) {
            ctx.getSharedPreferences(DnsForwardService.PREFS,Context.MODE_PRIVATE)
                .edit().remove("ipv6_pilot_log").commit();
        }
    }
    public static boolean isRunning(){synchronized(LOCK){return starting||(daemon!=null&&daemon.isAlive());}}
    public static String report(Context ctx) {
        return ctx.getSharedPreferences(DnsForwardService.PREFS,Context.MODE_PRIVATE)
                .getString("ipv6_pilot_log","尚未启动 IPv6 安全试运行。");
    }
    private static List<Endpoint> preflight(Context ctx)throws Exception {
        SharedPreferences prefs=ctx.getSharedPreferences(DnsForwardService.PREFS,Context.MODE_PRIVATE);
        String[] hosts={prefs.getString("host",""),prefs.getString("sub_host",""),prefs.getString("secondary_host","")};
        String[] portKeys={"port","sub_port","secondary_port"};
        String[] role={"主","从","备"};
        List<Endpoint> endpoints=new ArrayList<>();
        for(int i=0;i<3;i++){
            String host=hosts[i]==null?"":hosts[i].trim();if(host.isEmpty())continue;
            int port=Integer.parseInt(prefs.getString(portKeys[i],"31017").trim());
            if(port<1||port>65535)throw new IllegalArgumentException(role[i]+" DNS 端口不合法");
            InetAddress[] addresses=DnsBootstrap.resolve(host,prefs.getString("bootstrap",""));
            boolean found=false;
            for(int n=0;n<Math.min(addresses.length,6);n++){
                InetAddress ip=addresses[n];if(!DnsUpstreamExchange.permittedUpstream(ip))continue;
                DnsProbe.Sample udp=DnsProbe.measure(ip,port,"UDP");
                DnsProbe.Sample tcp=DnsProbe.measure(ip,port,"TCP");
                if(udp.success&&tcp.success){
                    endpoints.add(new Endpoint(ip,port));
                    log(ctx,"上游预检："+role[i]+" "+ip.getHostAddress()+":"+port+" UDP/TCP 均通过");
                    found=true;break;
                }
            }
            if(!found)log(ctx,"上游预检："+role[i]+" 无可同时使用 UDP/TCP 的地址，跳过");
        }
        if(endpoints.isEmpty())throw new IllegalStateException("主/从/备均未找到 UDP/TCP 都可用的 DNS 上游");
        return endpoints;
    }
    private static java.lang.Process spawn(Context ctx,String session,List<Endpoint> endpoints)throws Exception {
        String apk=ctx.getApplicationInfo().sourceDir;
        if(apk==null||!apk.startsWith("/data/app/")||!new java.io.File(apk).isFile())
            throw new IllegalStateException("已安装 APK 路径不可用");
        StringBuilder cmd=new StringBuilder("CLASSPATH='").append(apk.replace("'","'\\''"))
            .append("' /system/bin/app_process /system/bin dev.yz.dnsobserver.DnsIpv6PilotDaemon ").append(session);
        for(Endpoint endpoint:endpoints){
            String ip=endpoint.ip.getHostAddress();
            if(!ip.matches("[0-9a-fA-F:.]+"))throw new IllegalArgumentException("不支持含 Zone ID 的上游 IP");
            cmd.append(' ').append(ip).append(' ').append(endpoint.port);
        }
        java.lang.Process process=new ProcessBuilder("su","-c",cmd.toString()).redirectErrorStream(true).start();
        Thread drain=new Thread(()->{
            try(BufferedReader br=new BufferedReader(new InputStreamReader(process.getInputStream(),StandardCharsets.UTF_8))){
                String line;
                while((line=br.readLine())!=null){
                    // Per-query successes are aggregated, not appended endlessly.
                    if(line.startsWith("DNS6PILOT UDP_OK"))udpOk.incrementAndGet();
                    else if(line.startsWith("DNS6PILOT TCP_OK"))tcpOk.incrementAndGet();
                    else log(ctx,line.length()>400?line.substring(0,400):line);
                    if(line.startsWith("DNS6PILOT READY")||line.startsWith("DNS6PILOT ERROR"))signals.offer(line);
                }
            }catch(Exception e){log(ctx,"Root 输出流结束："+e.getClass().getSimpleName());}
        },"DNS-pilot-log");
        drain.setDaemon(true);drain.start();
        return process;
    }
    /** Actual client verification, including spoofed source IP:53 for UDP. */
    private static boolean probe(String transport)throws Exception {
        InetAddress target=InetAddress.getByName(TARGET);
        byte[] query=DnsPacket.probeQuestion();
        byte[] answer;
        if("UDP".equals(transport)){
            try(DatagramSocket s=new DatagramSocket(null)){
                s.bind(new InetSocketAddress(InetAddress.getByName("::"),0));
                s.setSoTimeout(4000);
                s.send(new DatagramPacket(query,query.length,target,PORT));
                byte[] buffer=new byte[4096];DatagramPacket response=new DatagramPacket(buffer,buffer.length);
                s.receive(response);
                if(!target.equals(response.getAddress())||response.getPort()!=PORT)return false;
                answer=Arrays.copyOf(buffer,response.getLength());
            }
        }else{
            try(Socket s=new Socket()){
                s.connect(new InetSocketAddress(target,PORT),3500);s.setSoTimeout(4000);
                DataOutputStream out=new DataOutputStream(s.getOutputStream());
                out.writeShort(query.length);out.write(query);out.flush();
                DataInputStream in=new DataInputStream(s.getInputStream());
                int n=in.readUnsignedShort();if(n<12||n>4096)return false;
                answer=new byte[n];in.readFully(answer);
            }
        }
        int rcode=answer.length>3?answer[3]&15:-1;
        return DnsPacket.validReply(query,answer) && (rcode==0||rcode==3) && !DnsPacket.truncated(answer);
    }
    public static String start(Context ctx){
        Context app=ctx.getApplicationContext();
        synchronized(LOCK){
            if(DnsIpv6GlobalController.isRunning())return "请先停止 IPv6 全局接管再启动 UID 隔离诊断";
            if(starting||(daemon!=null&&daemon.isAlive()))return "安全试运行已经启动或正在启动";
            starting=true;signals.clear();
            probes=0;udpOk.set(0);tcpOk.set(0);
            token=UUID.randomUUID().toString().replace("-","");
            app.getSharedPreferences(DnsForwardService.PREFS,Context.MODE_PRIVATE).edit()
                    .putString("ipv6_pilot_log","").apply();
            log(app,"v0.6.0-beta2：IPv4 接管保持原状；仅本 App UID → "+TARGET+":53；最多 145 秒，180 秒看门狗");
            boolean installAttempted=false;
            try {
                List<Endpoint> endpoints=preflight(app);
                daemon=spawn(app,token,endpoints);
                String ready=signals.poll(8000,TimeUnit.MILLISECONDS);
                if(ready==null||!ready.startsWith("DNS6PILOT READY"))
                    throw new IllegalStateException("Root 代理未就绪："+ready);
                installAttempted=true;
                log(app,DnsIpv6Experiment.root(app,"install-pilot",token,12));
                ownsRules=true;
                boolean udp=probe("UDP"),tcp=probe("TCP");
                probes++;log(app,"启动自检：UDP="+udp+" TCP="+tcp);
                if(!udp||!tcp)throw new IllegalStateException("首次 UDP/TCP DNS 应答校验失败，已退出并恢复");
                final java.lang.Process monitored=daemon;
                Thread cleanup=new Thread(()->{
                    try{monitored.waitFor();}catch(InterruptedException e){Thread.currentThread().interrupt();}
                    synchronized(LOCK){
                        if(daemon!=monitored)return;
                        log(app,"Root 进程退出，自动清理实验规则");
                        try{log(app,DnsIpv6Experiment.recover(app));ownsRules=false;}
                        catch(Exception e){log(app,"自动恢复未确认："+e.getMessage());}
                        daemon=null;
                    }
                },"DNS-pilot-exit-guard");
                cleanup.setDaemon(true);cleanup.start();
                log(app,"试运行启动成功：可多次点击 DNS 自检，手动停止或到期自动清理");
                return "IPv6 安全试运行已启动；UDP/TCP 首次自检通过";
            }catch(Exception e){
                log(app,"启动失败："+e.getClass().getSimpleName()+" "+e.getMessage());
                if(daemon!=null){daemon.destroy();daemon.destroyForcibly();daemon=null;}
                // A PRECHECK_FAILED means somebody else's scoped test owns the chain;
                // never delete it as part of this failed attempt.
                if(ownsRules || (installAttempted && (e.getMessage()==null ||
                        !e.getMessage().contains("PRECHECK_FAILED")))){
                    try{log(app,DnsIpv6Experiment.recover(app));ownsRules=false;}
                    catch(Exception failure){log(app,"清理未确认："+failure.getMessage());}
                }
                return "启动失败，已执行恢复检查："+e.getMessage();
            }finally{starting=false;}
        }
    }
    public static String test(Context ctx){
        synchronized(LOCK){
            if(starting||daemon==null||!daemon.isAlive())return "没有运行中的 IPv6 试运行服务";
            try{
                boolean udp=probe("UDP"),tcp=probe("TCP");
                probes++;String result="第"+probes+"轮自检 UDP="+udp+" TCP="+tcp;
                log(ctx,result);
                if(!udp||!tcp) {
                    log(ctx,"发现 DNS 响应异常，立即恢复实验规则");
                    stop(ctx);
                }
                return result;
            }catch(Exception e){log(ctx,"自检错误："+e.getMessage());stop(ctx);return "自检失败，已触发恢复："+e.getMessage();}
        }
    }

    /** Finite concurrency probe against the RUNNING pilot, without changing rule scope. */
    public static String stress(Context ctx) {
        synchronized(LOCK) {
            if(starting||daemon==null||!daemon.isAlive())return "未运行 IPv6 试运行，不能压力自检";
        }
        java.util.concurrent.ExecutorService pool=java.util.concurrent.Executors.newFixedThreadPool(4);
        java.util.List<java.util.concurrent.Future<Boolean>> futures=new java.util.ArrayList<>();
        long begin=android.os.SystemClock.elapsedRealtime();
        long deadline=begin+16000L;
        try {
            for(int i=0;i<12;i++) {
                final String transport=(i%2==0)?"UDP":"TCP";
                futures.add(pool.submit(()->probe(transport)));
            }
            int success=0,errors=0;
            for(java.util.concurrent.Future<Boolean> future:futures) {
                try {
                    long left=deadline-android.os.SystemClock.elapsedRealtime();
                    if(left<=0) {errors++;continue;}
                    if(Boolean.TRUE.equals(future.get(left,TimeUnit.MILLISECONDS)))success++;
                    else errors++;
                }catch(Exception ex){errors++;}
            }
            String summary="并发自检：成功 "+success+"/12，失败 "+errors+
                    "，耗时 "+(android.os.SystemClock.elapsedRealtime()-begin)+"ms";
            log(ctx,summary);
            // Pressure tests never independently alter firewall/routing rules.
            return summary;
        }finally {
            for(java.util.concurrent.Future<Boolean> future:futures)future.cancel(true);
            pool.shutdownNow();
        }
    }
    public static String stop(Context ctx){
        synchronized(LOCK){
            if(daemon!=null){daemon.destroy();daemon.destroyForcibly();daemon=null;}
            if(!ownsRules){log(ctx,"未持有 IPv6 试运行规则；未触碰其他实验");return "当前没有 IPv6 试运行规则";}
            String result;
            try{result=DnsIpv6Experiment.recover(ctx);ownsRules=false;}
            catch(Exception e){result="RECOVERY_FAILED: "+e.getMessage();}
            log(ctx,"累计自检 "+probes+" 轮，代理 UDP_OK="+udpOk.get()+" TCP_OK="+tcpOk.get());
            log(ctx,"手动停止："+result);
            return result;
        }
    }
}
