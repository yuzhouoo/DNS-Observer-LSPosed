package dev.yz.dnsobserver;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.InetAddress;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** ICMP Echo RTT measurement. This is NOT a DNS query. */
public final class DnsIcmpProbe {
    private DnsIcmpProbe() {}
    private static final Pattern RTT=Pattern.compile("(?i)\\btime\\s*([=<])\\s*([0-9]+(?:\\.[0-9]+)?)\\s*ms\\b");
    private static final Pattern AVG=Pattern.compile("(?i)(?:rtt|round-trip)\\s+min/avg/max(?:/mdev|/stddev)?\\s*=\\s*[0-9.]+/([0-9.]+)");
    static long parseRtt(String output) {
        if(output==null)return -1;
        Matcher m=RTT.matcher(output);
        if(!m.find()){
            m=AVG.matcher(output);
            if(!m.find())return -1;
            try{return Math.max(0,Math.round(Double.parseDouble(m.group(1))));}
            catch(NumberFormatException e){return -1;}
        }
        try{
            if("<".equals(m.group(1)))return 1;
            return Math.max(0,Math.round(Double.parseDouble(m.group(2))));
        }catch(NumberFormatException e){return -1;}
    }
    public static DnsProbe.Sample measure(InetAddress ip) {
        Process p=null;
        try {
            String flag=ip instanceof java.net.Inet4Address?"-4":"-6";
            p=new ProcessBuilder("/system/bin/ping",flag,"-c","1","-W","2","-w","3",ip.getHostAddress())
                .redirectErrorStream(true).start();
            if(!p.waitFor(3500,TimeUnit.MILLISECONDS)){
                p.destroyForcibly();
                return sample(ip,false,-1,"Ping 超时（ICMP 可能被拦截）");
            }
            String output=readBounded(p.getInputStream());
            if(p.exitValue()==0){
                long rtt=parseRtt(output);
                return sample(ip,true,rtt,rtt<0?"收到 ICMP 应答但未能解析 RTT":"");
            }
            String lower=output.toLowerCase(Locale.ROOT);
            if(lower.contains("operation not permitted")||lower.contains("permission denied"))
                return sample(ip,false,-1,"Ping 权限不足，不能据此判断 IP 不通");
            if(lower.contains("invalid option")||lower.contains("unknown option")||lower.contains("usage: ping"))
                return sample(ip,false,-1,"系统 Ping 参数不受支持，不代表 IP 不通");
            if(lower.contains("network is unreachable")||lower.contains("network unreachable"))
                return sample(ip,false,-1,"本机没有到该 IP 的网络路由");
            return sample(ip,false,-1,"ICMP 无应答/被过滤（不能单独断定 IP 不通）");
        }catch(InterruptedException e){
            Thread.currentThread().interrupt();
            return sample(ip,false,-1,"Ping 任务取消");
        }catch(Exception e){
            return sample(ip,false,-1,"Ping 未能执行（"+e.getClass().getSimpleName()+"），不能据此判断 IP 不通");
        }finally{
            if(p!=null&&p.isAlive())p.destroyForcibly();
        }
    }
    private static String readBounded(InputStream in)throws java.io.IOException{
        ByteArrayOutputStream b=new ByteArrayOutputStream();byte[] buf=new byte[512];int n;
        while(b.size()<4096&&(n=in.read(buf,0,Math.min(buf.length,4096-b.size())))>0)b.write(buf,0,n);
        return b.toString("UTF-8");
    }
    private static DnsProbe.Sample sample(InetAddress a,boolean ok,long ms,String err){
        return new DnsProbe.Sample(a,0,"PING",ok,ms,-1,err);
    }
}
