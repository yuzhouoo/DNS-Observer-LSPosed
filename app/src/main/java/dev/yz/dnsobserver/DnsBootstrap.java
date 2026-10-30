package dev.yz.dnsobserver;

import java.io.ByteArrayOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

/** Resolves ONLY the configured upstream DNS hostname before enabling interception. */
public final class DnsBootstrap {
    private DnsBootstrap() { }

    public static InetAddress[] resolve(String host, String backupIp) throws Exception {
        if(host==null||host.trim().isEmpty()||host.length()>253||host.contains("://")||host.contains("/"))
            throw new IllegalArgumentException("上游 DNS 必须为纯域名或 IP");
        String name=host.trim();
        // Literal DNS endpoints do not need a name lookup.
        try { return new InetAddress[]{parseLiteral(name)}; }
        catch(IllegalArgumentException ignore) { /* Must be a hostname: Bootstrap only. */ }
        return resolveOnlyViaBackup(name,backupIp);
    }

    /**
     * Safe while interception is ACTIVE: raw UDP 53 from this app UID only.
     * Never call system getAllByName(host) here, because Android's DNS Resolver
     * process may issue the upstream query under a different UID.
     */
    public static InetAddress[] resolveOnlyViaBackup(String host, String backupIp) throws Exception {
        if(host==null||host.trim().isEmpty()||host.contains("://")||host.contains("/"))
            throw new IllegalArgumentException("上游 DNS 域名无效");
        try { return new InetAddress[]{parseLiteral(host.trim())}; }
        catch(IllegalArgumentException ignored) { /* hostname */ }
        InetAddress bootstrap = parseLiteral(backupIp == null ? "" : backupIp.trim());
        List<InetAddress> found = new ArrayList<>();
        StringBuilder reasons=new StringBuilder();
        for (int rr : new int[]{1, 28}) {
            try { found.addAll(resolveViaIp(host, bootstrap, rr)); }
            catch (Exception error) {reasons.append(rr==1?" A: ":" AAAA: ").append(error.getClass().getSimpleName()).append(" ").append(error.getMessage());}
        }
        if (found.isEmpty()) throw new IllegalStateException("Bootstrap "+bootstrap.getHostAddress()+":53 无有效地址响应；已尝试 UDP/TCP。"+reasons);
        return found.toArray(new InetAddress[0]);
    }

    /** Do not accept a hostname as the bootstrap resolver (prevents recursion). */
    static InetAddress parseLiteral(String value) throws Exception {
        if (value == null || value.isEmpty()) throw new IllegalArgumentException("Bootstrap IP 为空");
        if (value.matches("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) {
            String[] parts = value.split("\\.");
            byte[] addr = new byte[4];
            for (int i = 0; i < 4; i++) {
                int n = Integer.parseInt(parts[i]);
                if (n > 255) throw new IllegalArgumentException("错误的 IPv4 地址");
                addr[i] = (byte)n;
            }
            return InetAddress.getByAddress(addr);
        }
        if (value.indexOf(':') != -1 && value.matches("[0-9a-fA-F:.%]+")) {
            InetAddress addr = InetAddress.getByName(value);
            if (addr instanceof Inet6Address) return addr;
        }
        throw new IllegalArgumentException("Bootstrap DNS 必须为纯 IPv4/IPv6 地址");
    }

    static List<InetAddress> resolveViaIp(String host, InetAddress dns, int type) throws Exception {return resolveViaIp(host,dns,type,53);}
    static List<InetAddress> resolveViaIp(String host, InetAddress dns, int type,int dnsPort) throws Exception {
        int id = ThreadLocalRandom.current().nextInt(65536);
        ByteArrayOutputStream raw = new ByteArrayOutputStream();
        raw.write(id >> 8); raw.write(id);
        raw.write(1); raw.write(0); // RD
        raw.write(0); raw.write(1); // one question
        for (int i=0;i<6;i++) raw.write(0);
        String normalized = host.endsWith(".") ? host.substring(0,host.length()-1) : host;
        for (String label : normalized.split("\\.")) {
            byte[] bytes = label.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            if (bytes.length==0 || bytes.length>63) throw new IllegalArgumentException("invalid hostname label");
            raw.write(bytes.length); raw.write(bytes);
        }
        raw.write(0); raw.write(0); raw.write(type); raw.write(0); raw.write(1);
        byte[] query = raw.toByteArray();
        byte[] response;
        try {response=DnsUpstreamExchange.query(dns,dnsPort,"UDP",query);}
        catch(Exception udp){
            try {response=DnsUpstreamExchange.query(dns,dnsPort,"TCP",query);}
            catch(Exception tcp){throw new java.io.IOException("UDP="+udp.getMessage()+"; TCP="+tcp.getMessage(),tcp);}
        }
        {
            int len=response.length;
            if (len<12 || u16(response,0)!=id || (response[2]&0x80)==0
                    || (response[3]&15)!=0 || (response[2]&2)!=0) return Collections.emptyList();
            int qd=u16(response,4), an=u16(response,6);
            if (qd!=1 || an>100) return Collections.emptyList();
            int offset=12;
            offset=skipName(response,offset,len);
            if (offset<0 || offset+4>len) return Collections.emptyList();
            offset+=4;
            List<InetAddress> answers=new ArrayList<>();
            for (int n=0;n<an;n++) {
                offset=skipName(response,offset,len);
                if (offset<0 || offset+10>len) break;
                int rr=u16(response,offset), klass=u16(response,offset+2), rdlen=u16(response,offset+8);
                offset+=10;
                if (offset+rdlen>len) break;
                if (klass==1 && rr==type && ((type==1 && rdlen==4)||(type==28 && rdlen==16))) {
                    byte[] addr=new byte[rdlen];
                    System.arraycopy(response,offset,addr,0,rdlen);
                    answers.add(InetAddress.getByAddress(addr));
                }
                offset+=rdlen;
            }
            return answers;
        }
    }
    private static int u16(byte[] b,int offset) {return ((b[offset]&255)<<8)|(b[offset+1]&255);}
    private static int skipName(byte[] b,int off,int end) {
        for(int i=0;i<128;i++) {
            if(off>=end)return -1;
            int n=b[off]&255;
            if(n==0)return off+1;
            if((n&0xC0)==0xC0) return off+2<=end?off+2:-1;
            if((n&0xC0)!=0 || n>63 || off+1+n>end)return -1;
            off+=1+n;
        }
        return -1;
    }
}
