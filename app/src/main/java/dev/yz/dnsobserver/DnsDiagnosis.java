package dev.yz.dnsobserver;
import java.util.List;
/** Conservative diagnosis: ICMP failure alone never proves the IP is down. */
public final class DnsDiagnosis {
    private DnsDiagnosis(){}
    static String classify(DnsProbe.Sample ping,DnsProbe.Sample udp,DnsProbe.Sample tcp){
        boolean pi=ping!=null&&ping.success, u=udp!=null&&udp.success, t=tcp!=null&&tcp.success;
        boolean replied=(udp!=null&&udp.responseCode>=0)||(tcp!=null&&tcp.responseCode>=0);
        if(u&&t)return pi?"ICMP、UDP DNS、TCP DNS 均可用":"DNS UDP/TCP 正常；ICMP 可能被屏蔽，IP 并非不可达";
        if(u)return "UDP DNS 正常，TCP DNS 异常"+(pi?"；ICMP 正常":"；ICMP 未响应不影响 DNS 可用性");
        if(t)return "TCP DNS 正常，UDP DNS 异常"+(pi?"；ICMP 正常":"；ICMP 未响应不影响 DNS 可用性");
        if(replied)return "DNS 有报文回应但返回错误码；检查解析策略或上游服务";
        if(pi)return "ICMP 可达，但 DNS UDP/TCP 均未成功；检查 DNS 端口、服务或防火墙";
        if(ping!=null&&ping.error.contains("没有到该 IP 的网络路由"))return "本机缺少到该地址的网络路由";
        if(ping!=null&&(ping.error.contains("权限不足")||ping.error.contains("不受支持")||ping.error.contains("未能执行")))
            return "Ping 测试不可用，DNS 未成功；不能确定 IP 是否可达";
        return "ICMP、DNS 均无成功回应：可能 IP 不通或同时被过滤，无法单独判定";
    }
    static String forAddress(List<DnsProbe.Sample> samples,String ip){
        DnsProbe.Sample ping=null,udp=null,tcp=null;
        for(DnsProbe.Sample s:samples)if(ip.equals(s.ip)){
            if("PING".equals(s.transport))ping=s;
            if("UDP".equals(s.transport))udp=s;
            if("TCP".equals(s.transport))tcp=s;
        }
        return classify(ping,udp,tcp);
    }
}
