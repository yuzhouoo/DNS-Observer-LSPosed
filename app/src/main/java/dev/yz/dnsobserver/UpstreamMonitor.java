package dev.yz.dnsobserver;

import android.content.Context;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/** Measures IPv4/IPv6 x ICMP Ping / UDP DNS / TCP DNS, without modifying network settings. */
public final class UpstreamMonitor {
    private UpstreamMonitor() { }
    private static final int MAX_PER_FAMILY=12;
    private static final int MAX_PARALLEL=8;
    private static final long MEASURE_DEADLINE_MS=20_000L;

    public static final class Result {
        public InetAddress[] ips=new InetAddress[0];
        public String addressText="";
        public boolean success;
        public long latencyMs=-1;
        public String error="";
        public final List<DnsProbe.Sample> samples=new ArrayList<>();
        public int skipped4,skipped6;
        public String summary(String family,String protocol) {
            int count=0;long best=Long.MAX_VALUE;int failed=0;
            for(DnsProbe.Sample s:samples)if(family.equals(s.family)&&protocol.equals(s.transport)) {
                if(s.success){count++;best=Math.min(best,s.latencyMs);}else failed++;
            }
            if(count>0)return (best<0?"RTT 未获取":best+" ms")+"  ·  "+count+" 成功"+(failed>0?" / "+failed+" 失败":"");
            if(failed>0)return "不可用（"+failed+" IP 失败）";
            return "无"+family+"地址";
        }
        public String detail() {
            StringBuilder b=new StringBuilder();
            String previous="";
            for(DnsProbe.Sample sample:samples) {
                if(!sample.ip.equals(previous)) {
                    if(!previous.isEmpty()) b.append("诊断：").append(DnsDiagnosis.forAddress(samples,previous)).append("\n\n");
                    previous=sample.ip;
                    b.append("【").append(sample.family).append(" ").append(sample.ip).append("】\n");
                }
                b.append("  ").append("PING".equals(sample.transport)?"ICMP Ping":"DNS "+sample.transport)
                 .append("  ").append(sample.success?(sample.latencyMs<0?"成功（RTT 未取得）":sample.latencyMs+" ms"):"失败 · "+sample.error).append('\n');
            }
            if(!previous.isEmpty()) b.append("诊断：").append(DnsDiagnosis.forAddress(samples,previous)).append("\n");
            if(skipped4>0||skipped6>0)b.append("本次最多检测每种 IP 12 个；未测 IPv4 ")
                .append(skipped4).append(" 个、IPv6 ").append(skipped6).append(" 个\n");
            return b.toString();
        }
    }
    public static Result check(Context ctx,String role,String hostname,int port,
                               String bootstrap,boolean redirectActive,InetAddress[] known) {
        return check(ctx,role,hostname,port,bootstrap,redirectActive,known,false);
    }
    /** quick=true limits to 2 addresses per IP family for 60-second background health checks. */
    public static Result check(Context ctx,String role,String hostname,int port,
                               String bootstrap,boolean redirectActive,InetAddress[] known,boolean quick) {
        Result result=new Result();
        try {
            if(hostname==null||hostname.trim().isEmpty())throw new IllegalArgumentException("未配置上游域名");
            if(port<1||port>65535)throw new IllegalArgumentException("上游端口错误");
            InetAddress[] addresses;
            if(redirectActive) {
                if(bootstrap!=null&&!bootstrap.trim().isEmpty()) {
                    try {addresses=DnsBootstrap.resolveOnlyViaBackup(hostname,bootstrap);}
                    catch(Exception e) {addresses=known;}
                } else addresses=known;
            } else addresses=DnsBootstrap.resolve(hostname,bootstrap);
            if(addresses==null||addresses.length==0)throw new java.io.IOException("未获得上游 IP");
            // DNS servers may return duplicated A/AAAA results; maintain stable order.
            Map<String,InetAddress> unique=new LinkedHashMap<>();
            for(InetAddress address:addresses)if(address!=null)unique.put(address.getHostAddress(),address);
            result.ips=unique.values().toArray(new InetAddress[0]);
            StringBuilder ipText=new StringBuilder();
            for(InetAddress address:result.ips){if(ipText.length()>0)ipText.append(", ");ipText.append(address.getHostAddress());}
            result.addressText=ipText.toString();
            List<InetAddress> tested=new ArrayList<>();
            int n4=0,n6=0,cap=quick?2:MAX_PER_FAMILY;
            for(InetAddress addr:result.ips) {
                if(addr instanceof Inet4Address) {if(n4++>=cap){result.skipped4++;continue;}}
                else if(n6++>=cap){result.skipped6++;continue;}
                tested.add(addr);
            }
            // Full scans test ICMP plus independent UDP/TCP DNS. Quick active-DNS checks omit ICMP.
            List<Callable<DnsProbe.Sample>> tasks=new ArrayList<>();
            for(InetAddress addr:tested){
                if(!quick) tasks.add(()->DnsIcmpProbe.measure(addr));
                tasks.add(()->DnsProbe.measure(addr,port,"UDP"));
                tasks.add(()->DnsProbe.measure(addr,port,"TCP"));
            }
            ExecutorService executor=Executors.newFixedThreadPool(Math.min(MAX_PARALLEL,Math.max(1,tasks.size())));
            try {
                List<Future<DnsProbe.Sample>> futures=executor.invokeAll(tasks,MEASURE_DEADLINE_MS,TimeUnit.MILLISECONDS);
                for(int i=0;i<futures.size();i++) {
                    Future<DnsProbe.Sample> f=futures.get(i);
                    if(f.isCancelled()) {
                        // Time-bound results preserve the IP/protocol identity.
                        int stride=quick?2:3;
                        InetAddress addr=tested.get(i/stride);
                        String proto=quick?(i%2==0?"UDP":"TCP"):(i%3==0?"PING":i%3==1?"UDP":"TCP");
                        result.samples.add(new DnsProbe.Sample(addr,"PING".equals(proto)?0:port,
                                proto,false,-1,-1,"本轮测速超时或取消"));
                    } else {
                        try{result.samples.add(f.get());}
                        catch(Exception e){
                            int stride=quick?2:3;
                            InetAddress addr=tested.get(i/stride);
                            String proto=quick?(i%2==0?"UDP":"TCP"):(i%3==0?"PING":i%3==1?"UDP":"TCP");
                            result.samples.add(new DnsProbe.Sample(addr,"PING".equals(proto)?0:port,
                                    proto,false,-1,-1,e.getClass().getSimpleName()));
                        }
                    }
                }
            } finally {executor.shutdownNow();}
            // ICMP Ping success must not mark DNS upstream healthy.
            for(DnsProbe.Sample s:result.samples)if(s.success && !"PING".equals(s.transport)) {
                result.success=true;
                if(result.latencyMs<0||s.latencyMs<result.latencyMs)result.latencyMs=s.latencyMs;
            }
            if(!result.success) {
                result.error="无可用 DNS 响应；ICMP Ping 成功不代表 DNS 服务可用（详见每 IP 诊断）";
            }
        } catch(InterruptedException e) {
            Thread.currentThread().interrupt();result.error="测速线程被中断";
        } catch(Exception e) {
            result.error=e.getClass().getSimpleName()+": "+TextPolicy.clamp(e.getMessage(),100);
        }
        try {DnsDb db=new DnsDb(ctx);db.addProbeResult(role,hostname,port,result);}
        catch(Exception ignored){/* Data logging must not affect active DNS */}
        return result;
    }
}
