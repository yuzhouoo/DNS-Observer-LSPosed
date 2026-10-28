package dev.yz.dnsobserver;

import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructTimeval;

import java.io.FileDescriptor;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

/** One-shot Root IPv6 transparent listener for a SINGLE isolated test payload.
 * Never writes routing/firewall rules; runs as app_process launched by KernelSU. */
public final class DnsIpv6RootProbe {
    private static final int IPV6_TRANSPARENT=75;
    private static final int LISTEN_PORT=15454;
    // Isolate the direct TCP preflight from the TPROXY TCP listener: no rapid rebind.
    private static final int DIRECT_TCP_PORT=15455;
    private DnsIpv6RootProbe() {}
    private static void say(String msg) {
        System.out.println("DNS6PROBE "+msg);
        System.out.flush();
    }
    public static void main(String[] args) {
        if(args.length!=3 || !args[0].matches("[a-zA-Z0-9_-]{1,64}")
                || !args[1].matches("UDP|TCP") || !args[2].matches("DIRECT|LOOP|LOCAL|DNS53")) {
            say("ERROR bad-arguments");return;
        }
        String proto=args[1],stage=args[2];
        FileDescriptor listen=null,accepted=null;
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
            if("DNS53".equals(stage) && tcp) {
                byte[] frame=new byte[2];int have=0;
                while(have<2) { int n=Os.read(accepted,frame,have,2-have); if(n<=0)throw new IllegalStateException("DNS TCP short length");have+=n; }
                int want=((frame[0]&255)<<8)|(frame[1]&255);
                if(want<17||want>data.length)throw new IllegalStateException("DNS TCP invalid frame "+want);
                have=0;
                while(have<want) { int n=Os.read(accepted,data,have,want-have);if(n<=0)throw new IllegalStateException("DNS TCP truncated frame");have+=n; }
                size=have;
            } else size=Os.read(tcp?accepted:listen,data,0,data.length);
            if("DNS53".equals(stage)) {
                byte[] query=java.util.Arrays.copyOf(data,size);
                outcome=DnsPacket.validQuestion(query)
                    ?"RECV_OK protocol="+proto+" stage=DNS53 dns_question_valid=1 bytes="+size
                    :"RECV_MISMATCH protocol="+proto+" stage=DNS53 invalid_question bytes="+size;
            } else {
                String expected="DNS6-"+proto+"-"+stage+"-"+args[0];
                String got=new String(data,0,size,StandardCharsets.US_ASCII);
                if(expected.equals(got))outcome="RECV_OK protocol="+proto+" stage="+stage+" bytes="+size;
                else outcome="RECV_MISMATCH protocol="+proto+" stage="+stage+" bytes="+size;
            }
        }catch(ErrnoException e){outcome="ERROR errno="+e.errno+" "+e.getMessage();}
        catch(Throwable t){outcome="ERROR "+t.getClass().getSimpleName()+" "+String.valueOf(t.getMessage());}
        finally {
            if(accepted!=null)try{Os.close(accepted);}catch(Exception ignored){}
            if(listen!=null)try{Os.close(listen);}catch(Exception ignored){}
        }
        // Signal success only AFTER both sockets are closed. The UI must not
        // launch the next Root listener while the previous bind is still live.
        say("CLOSED protocol="+proto+" stage="+stage);
        say(outcome);
    }
}
