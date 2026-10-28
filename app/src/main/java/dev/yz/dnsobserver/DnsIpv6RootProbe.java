package dev.yz.dnsobserver;

import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructTimeval;

import java.io.FileDescriptor;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** One-shot Root IPv6 transparent listener for a SINGLE isolated test payload.
 * Never writes routing/firewall rules; runs as app_process launched by KernelSU. */
public final class DnsIpv6RootProbe {
    private static final int IPV6_TRANSPARENT=75;
    private static final int LISTEN_PORT=15454;
    // Isolate the direct TCP preflight from the TPROXY TCP listener: no rapid rebind.
    private static final int DIRECT_TCP_PORT=15455;
    private static final int DNS_PORT=53;
    private static final String DOC_IP="2001:db8:ffff::53";
    private DnsIpv6RootProbe() {}
    private static void say(String msg) {
        System.out.println("DNS6PROBE "+msg);
        System.out.flush();
    }
    public static void main(String[] args) {
        boolean upstreamStage=args.length==5 && "UPSTREAM".equals(args[2]);
        if((args.length!=3 && !upstreamStage) || args.length<3 ||
                !args[0].matches("[a-zA-Z0-9_-]{1,64}") ||
                !args[1].matches("UDP|TCP") ||
                !(args[2].matches("DIRECT|LOOP|LOCAL|DNS53|DNSREPLY") || upstreamStage)) {
            say("ERROR bad-arguments");return;
        }
        String proto=args[1],stage=args[2];
        FileDescriptor listen=null,accepted=null,replySocket=null;
        InetSocketAddress client=new InetSocketAddress(0);
        String outcome="ERROR probe terminated without result";
        try {
            say("EUID="+Os.geteuid()+" protocol="+proto+" stage="+stage);
            boolean tcp="TCP".equals(proto);
            listen=Os.socket(OsConstants.AF_INET6,tcp?OsConstants.SOCK_STREAM:OsConstants.SOCK_DGRAM,
                    tcp?OsConstants.IPPROTO_TCP:OsConstants.IPPROTO_UDP);
            Os.setsockoptInt(listen,OsConstants.IPPROTO_IPV6,IPV6_TRANSPARENT,1);
            // A freshly closed TCP listener/accepted socket may still have TIME_WAIT state.
            // SO_REUSEADDR and a separate direct-preflight port prevent false EADDRINUSE.
            if(tcp) Os.setsockoptInt(listen,OsConstants.SOL_SOCKET,OsConstants.SO_REUSEADDR,1);
            Os.setsockoptTimeval(listen,OsConstants.SOL_SOCKET,OsConstants.SO_RCVTIMEO,
                    StructTimeval.fromMillis(6500));
            int listenPort=tcp && "DIRECT".equals(stage)?DIRECT_TCP_PORT:LISTEN_PORT;
            Os.bind(listen,InetAddress.getByName("::1"),listenPort);
            if(tcp)Os.listen(listen,1);
            say("READY transparent_ipv6=1 bind=::1:"+listenPort+" protocol="+proto);
            byte[] data=new byte[256];
            if(tcp) {
                accepted=Os.accept(listen,new InetSocketAddress(0));
                Os.setsockoptTimeval(accepted,OsConstants.SOL_SOCKET,OsConstants.SO_RCVTIMEO,
                        StructTimeval.fromMillis(4000));
            }
            int size;
            if(("DNS53".equals(stage)||"DNSREPLY".equals(stage)||"UPSTREAM".equals(stage)) && tcp) {
                byte[] frame=new byte[2];int have=0;
                while(have<2) { int n=Os.read(accepted,frame,have,2-have); if(n<=0)throw new IllegalStateException("DNS TCP short length");have+=n; }
                int want=((frame[0]&255)<<8)|(frame[1]&255);
                if(want<17||want>data.length)throw new IllegalStateException("DNS TCP invalid frame "+want);
                have=0;
                while(have<want) { int n=Os.read(accepted,data,have,want-have);if(n<=0)throw new IllegalStateException("DNS TCP truncated frame");have+=n; }
                size=have;
            } else if(("DNSREPLY".equals(stage)||"UPSTREAM".equals(stage)) && !tcp) {
                size=Os.recvfrom(listen,data,0,data.length,0,client);
            } else size=Os.read(tcp?accepted:listen,data,0,data.length);
            if("DNS53".equals(stage)||"DNSREPLY".equals(stage)||"UPSTREAM".equals(stage)) {
                byte[] query=Arrays.copyOf(data,size);
                if(!DnsPacket.validQuestion(query)) {
                    outcome="RECV_MISMATCH protocol="+proto+" stage="+stage+" invalid_question bytes="+size;
                } else if("DNSREPLY".equals(stage)||"UPSTREAM".equals(stage)) {
                    byte[] reply;
                    if("UPSTREAM".equals(stage)){
                        // A pre-resolved numeric IP: never call netd to resolve an upstream
                        // hostname while the experimental DNS interception rule is present.
                        if(!args[3].matches("[0-9a-fA-F:.]+") || !args[3].contains(".") && !args[3].contains(":")
                                || !args[4].matches("[0-9]{1,5}"))
                            throw new IllegalArgumentException("Upstream literal IP and port required");
                        InetAddress upstream=InetAddress.getByName(args[3]);
                        int port=Integer.parseInt(args[4]);
                        if(!DnsUpstreamExchange.permittedUpstream(upstream))
                            throw new IllegalArgumentException("Disallowed upstream IP");
                        reply=DnsUpstreamExchange.query(upstream,port,proto,query);
                        say("UPSTREAM_OK protocol="+proto+" rcode="+(reply[3]&15)+" bytes="+reply.length);
                    } else reply=DnsPacket.servfail(query);
                    if(reply==null)throw new IllegalStateException("Cannot construct DNS response");
                    if(tcp) {
                        byte[] framed=new byte[reply.length+2];
                        framed[0]=(byte)((reply.length>>8)&255);
                        framed[1]=(byte)(reply.length&255);
                        System.arraycopy(reply,0,framed,2,reply.length);
                        int off=0;
                        while(off<framed.length) {
                            int n=Os.write(accepted,framed,off,framed.length-off);
                            if(n<=0)throw new IllegalStateException("TCP DNS write returned "+n);
                            off+=n;
                        }
                    } else {
                        if(client.getAddress()==null||client.getPort()<1)
                            throw new IllegalStateException("UDP client address unavailable");
                        replySocket=Os.socket(OsConstants.AF_INET6,OsConstants.SOCK_DGRAM,OsConstants.IPPROTO_UDP);
                        Os.setsockoptInt(replySocket,OsConstants.IPPROTO_IPV6,IPV6_TRANSPARENT,1);
                        Os.setsockoptInt(replySocket,OsConstants.SOL_SOCKET,OsConstants.SO_REUSEADDR,1);
                        Os.bind(replySocket,InetAddress.getByName(DOC_IP),DNS_PORT);
                        int n=Os.sendto(replySocket,reply,0,reply.length,0,client.getAddress(),client.getPort());
                        if(n!=reply.length)throw new IllegalStateException("UDP DNS send truncated "+n);
                    }
                    outcome="RECV_OK protocol="+proto+" stage="+stage+" dns_question_valid=1 reply_sent=1 bytes="+size;
                } else outcome="RECV_OK protocol="+proto+" stage=DNS53 dns_question_valid=1 bytes="+size;
            } else {
                String expected="DNS6-"+proto+"-"+stage+"-"+args[0];
                String got=new String(data,0,size,StandardCharsets.US_ASCII);
                if(expected.equals(got))outcome="RECV_OK protocol="+proto+" stage="+stage+" bytes="+size;
                else outcome="RECV_MISMATCH protocol="+proto+" stage="+stage+" bytes="+size;
            }
        }catch(ErrnoException e){outcome="ERROR errno="+e.errno+" "+e.getMessage();}
        catch(Throwable t){outcome="ERROR "+t.getClass().getSimpleName()+" "+String.valueOf(t.getMessage());}
        finally {
            if(replySocket!=null)try{Os.close(replySocket);}catch(Exception ignored){}
            if(accepted!=null)try{Os.close(accepted);}catch(Exception ignored){}
            if(listen!=null)try{Os.close(listen);}catch(Exception ignored){}
        }
        // Signal success only AFTER both sockets are closed. The UI must not
        // launch the next Root listener while the previous bind is still live.
        say("CLOSED protocol="+proto+" stage="+stage);
        say(outcome);
    }
}
