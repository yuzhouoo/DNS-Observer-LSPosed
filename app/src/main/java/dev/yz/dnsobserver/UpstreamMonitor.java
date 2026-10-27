package dev.yz.dnsobserver;

import android.content.Context;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;

/** Isolated periodic/bootstrap monitor. No modifications to system networking. */
public final class UpstreamMonitor {
    private UpstreamMonitor() { }
    public static final class Result {
        public InetAddress[] ips = new InetAddress[0];
        public String addressText="";
        public boolean success;
        public long latencyMs;
        public String error="";
    }
    public static Result check(Context ctx,String role,String hostname,int port,
                               String bootstrap,boolean redirectActive,InetAddress[] known) {
        Result result=new Result(); long start=android.os.SystemClock.elapsedRealtime();
        try {
            if (hostname==null || hostname.trim().isEmpty()) throw new IllegalArgumentException("未配置上游域名");
            if (port<1||port>65535) throw new IllegalArgumentException("上游端口错误");
            InetAddress[] addresses;
            if (redirectActive) {
                // Never use Android's system resolver under transparent DNS interception.
                if(bootstrap!=null && !bootstrap.trim().isEmpty()) {
                    InetAddress[] candidate;
                    try {candidate=DnsBootstrap.resolveOnlyViaBackup(hostname,bootstrap);}
                    catch(Exception failure) {candidate=known;}
                    addresses=candidate;
                } else addresses=known;
            } else addresses=DnsBootstrap.resolve(hostname,bootstrap);
            if(addresses==null||addresses.length==0) throw new java.io.IOException("未获得上游 IP");
            result.ips=addresses;
            StringBuilder buf=new StringBuilder();
            for(InetAddress ip:addresses) {if(buf.length()>0)buf.append(", ");buf.append(ip.getHostAddress());}
            result.addressText=buf.toString();
            byte[] question=DnsPacket.probeQuestion();
            for(InetAddress address:addresses) {
                long tick=android.os.SystemClock.elapsedRealtime();
                try(DatagramSocket sock=new DatagramSocket()) {
                    sock.connect(new InetSocketAddress(address,port));sock.setSoTimeout(2400);
                    sock.send(new DatagramPacket(question,question.length));
                    byte[] payload=new byte[4096]; DatagramPacket answer=new DatagramPacket(payload,payload.length);
                    sock.receive(answer);
                    byte[] bytes=java.util.Arrays.copyOf(payload,answer.getLength());
                    if(!DnsPacket.validReply(question,bytes))continue;
                    result.latencyMs=android.os.SystemClock.elapsedRealtime()-tick;
                    result.success=true;break;
                } catch(Exception ignored) { }
            }
            if(!result.success) result.error="全部上游 IP 未返回有效 UDP DNS 响应";
        } catch(Exception e) {
            result.error=e.getClass().getSimpleName()+": "+TextPolicy.clamp(e.getMessage(),90);
        }
        if(!result.success) result.latencyMs=android.os.SystemClock.elapsedRealtime()-start;
        try {new DnsDb(ctx).addUpstreamCheck(role,hostname,result.addressText,result.latencyMs,result.success,result.error);}
        catch(Exception ignored) { /* Probe must never impact DNS routing */ }
        return result;
    }
}
