package dev.yz.dnsobserver;

import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructTimeval;

import java.io.FileDescriptor;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;

/** Runs under a dedicated su/app_process for ONLY the IPv6 ::1:15454 experiment.
 * Never changes routes, packet marks, firewalls, or device DNS settings. */
public final class DnsIpv6RootProbe {
    private static final int TRANSPARENT_IPV6=75;
    private static final int PORT=15454;
    private DnsIpv6RootProbe() {}
    private static void message(String text) {
        System.out.println("DNS6PROBE " + text);
        System.out.flush();
    }
    private static boolean receive(FileDescriptor fd,String expected,String stage) throws Exception {
        byte[] buf=new byte[256];
        try {
            int size=Os.read(fd,buf,0,buf.length);
            String actual=new String(buf,0,size,StandardCharsets.US_ASCII);
            if(!expected.equals(actual)) {
                message(stage+"_MISMATCH size="+size);
                return false;
            }
            message(stage+"_OK");
            return true;
        } catch(ErrnoException e) {
            message(stage+"_ERROR errno="+e.errno+" "+e.getMessage());
            return false;
        }
    }
    public static void main(String[] args) {
        if(args.length!=1 || !args[0].matches("[a-zA-Z0-9_-]{1,64}")) {
            message("ERROR invalid-token");return;
        }
        FileDescriptor fd=null;
        try {
            message("EUID="+Os.geteuid());
            fd=Os.socket(OsConstants.AF_INET6,OsConstants.SOCK_DGRAM,OsConstants.IPPROTO_UDP);
            Os.setsockoptInt(fd,OsConstants.IPPROTO_IPV6,TRANSPARENT_IPV6,1);
            Os.setsockoptTimeval(fd,OsConstants.SOL_SOCKET,OsConstants.SO_RCVTIMEO,StructTimeval.fromMillis(6500));
            Os.bind(fd,InetAddress.getByName("::1"),PORT);
            message("READY transparent_ipv6=1 bind=::1:"+PORT);
            if(!receive(fd,"DNS6-DIRECT-"+args[0],"DIRECT"))return;
            receive(fd,"DNS6-TPROXY-"+args[0],"TPROXY");
        } catch(ErrnoException e) {
            message("ERROR errno="+e.errno+" "+e.getMessage());
        } catch(Throwable t) {
            message("ERROR "+t.getClass().getSimpleName()+" "+String.valueOf(t.getMessage()));
        } finally {
            if(fd!=null)try{Os.close(fd);}catch(Exception ignored){}
        }
    }
}
