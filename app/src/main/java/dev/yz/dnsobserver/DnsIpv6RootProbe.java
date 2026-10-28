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
    private DnsIpv6RootProbe() {}
    private static void say(String msg) {
        System.out.println("DNS6PROBE "+msg);
        System.out.flush();
    }
    public static void main(String[] args) {
        if(args.length!=3 || !args[0].matches("[a-zA-Z0-9_-]{1,64}")
                || !args[1].matches("UDP|TCP") || !args[2].matches("DIRECT|LOOP|LOCAL")) {
            say("ERROR bad-arguments");return;
        }
        String proto=args[1],stage=args[2];
        FileDescriptor listen=null,accepted=null;
        try {
            say("EUID="+Os.geteuid()+" protocol="+proto+" stage="+stage);
            boolean tcp="TCP".equals(proto);
            listen=Os.socket(OsConstants.AF_INET6,tcp?OsConstants.SOCK_STREAM:OsConstants.SOCK_DGRAM,
                    tcp?OsConstants.IPPROTO_TCP:OsConstants.IPPROTO_UDP);
            Os.setsockoptInt(listen,OsConstants.IPPROTO_IPV6,IPV6_TRANSPARENT,1);
            Os.setsockoptTimeval(listen,OsConstants.SOL_SOCKET,OsConstants.SO_RCVTIMEO,
                    StructTimeval.fromMillis(6500));
            Os.bind(listen,InetAddress.getByName("::1"),LISTEN_PORT);
            if(tcp)Os.listen(listen,1);
            say("READY transparent_ipv6=1 bind=::1:"+LISTEN_PORT+" protocol="+proto);
            byte[] data=new byte[256];
            if(tcp) {
                accepted=Os.accept(listen,new InetSocketAddress(0));
                Os.setsockoptTimeval(accepted,OsConstants.SOL_SOCKET,OsConstants.SO_RCVTIMEO,
                        StructTimeval.fromMillis(4000));
            }
            int size=Os.read(tcp?accepted:listen,data,0,data.length);
            String expected="DNS6-"+proto+"-"+stage+"-"+args[0];
            String got=new String(data,0,size,StandardCharsets.US_ASCII);
            if(expected.equals(got))say("RECV_OK protocol="+proto+" stage="+stage+" bytes="+size);
            else say("RECV_MISMATCH protocol="+proto+" stage="+stage+" bytes="+size);
        }catch(ErrnoException e){say("ERROR errno="+e.errno+" "+e.getMessage());}
        catch(Throwable t){say("ERROR "+t.getClass().getSimpleName()+" "+String.valueOf(t.getMessage()));}
        finally {
            if(accepted!=null)try{Os.close(accepted);}catch(Exception ignored){}
            if(listen!=null)try{Os.close(listen);}catch(Exception ignored){}
        }
    }
}
