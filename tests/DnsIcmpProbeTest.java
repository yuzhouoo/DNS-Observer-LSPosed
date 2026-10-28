package dev.yz.dnsobserver;
import java.net.InetAddress;
import java.util.ArrayList;
public final class DnsIcmpProbeTest {
    static void check(boolean yes,String text){if(!yes)throw new AssertionError(text);}
    static DnsProbe.Sample s(InetAddress ip,String kind,boolean ok,int rcode,String error){
        return new DnsProbe.Sample(ip,"PING".equals(kind)?0:31017,kind,ok,ok?20:-1,rcode,error);
    }
    public static void main(String[] args)throws Exception {
        check(DnsIcmpProbe.parseRtt("64 bytes from 127.0.0.1: ttl=64 time=1.34 ms")==1,"rtt");
        check(DnsIcmpProbe.parseRtt("time<1 ms")==1,"sub-ms");
        check(DnsIcmpProbe.parseRtt("rtt min/avg/max/mdev = 1.100/2.540/3.100/0.500 ms")==3,"avg");
        check(DnsIcmpProbe.parseRtt("100% packet loss")==-1,"loss");
        InetAddress ip=InetAddress.getByName("192.0.2.1");
        ArrayList<DnsProbe.Sample> samples=new ArrayList<>();
        samples.add(s(ip,"PING",false,-1,"ICMP 超时"));
        samples.add(s(ip,"UDP",true,0,""));samples.add(s(ip,"TCP",true,0,""));
        check(DnsDiagnosis.forAddress(samples,ip.getHostAddress()).contains("IP 并非不可达"),"ICMP blocked but DNS online");
        samples.clear();samples.add(s(ip,"PING",true,-1,""));
        samples.add(s(ip,"UDP",false,-1,"timeout"));samples.add(s(ip,"TCP",false,-1,"timeout"));
        check(DnsDiagnosis.forAddress(samples,ip.getHostAddress()).contains("端口"),"ICMP online DNS offline");
        samples.clear();samples.add(s(ip,"PING",false,-1,"no reply"));
        samples.add(s(ip,"UDP",false,-1,"timeout"));samples.add(s(ip,"TCP",false,-1,"timeout"));
        check(DnsDiagnosis.forAddress(samples,ip.getHostAddress()).contains("无法单独判定"),"cannot prove IP unreachable");
        samples.clear();samples.add(s(ip,"PING",true,-1,""));
        samples.add(s(ip,"UDP",false,5,"REFUSED"));samples.add(s(ip,"TCP",false,-1,"timeout"));
        check(DnsDiagnosis.forAddress(samples,ip.getHostAddress()).contains("有报文回应"),"rcode not routing failure");
        System.out.println("PASS: ICMP parsing and conservative tri-state diagnosis");
    }
}
