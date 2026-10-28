package dev.yz.dnsobserver;

import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructTimeval;

import java.io.FileDescriptor;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/** Explicit opt-in, time-bounded Root pilot. NOT an all-device DNS interceptor.
 * Only the app's UID / RFC3849 documentation IPv6 address / port 53 is routed here.
 * Root daemon lifetime < firewall watchdog lifetime. */
public final class DnsIpv6PilotDaemon {
    static final String DOC_IP="2001:db8:ffff::53";
    static final int PORT=15454, DNS_PORT=53;
    static final int LIFETIME_SECONDS=145;
    static final int MAX_DNS=4096;
    static final int IPV6_TRANSPARENT=75;
    private static final AtomicInteger received=new AtomicInteger();
    private static final AtomicInteger replied=new AtomicInteger();
    private static final AtomicInteger failed=new AtomicInteger();
    private static volatile boolean running=true;
    private static final class Endpoint {
        final InetAddress ip;final int port;
        Endpoint(InetAddress ip,int port){this.ip=ip;this.port=port;}
    }
    private DnsIpv6PilotDaemon(){}
    private static void log(String msg){System.out.println("DNS6PILOT "+msg);System.out.flush();}
    private static void close(FileDescriptor fd){if(fd!=null)try{Os.close(fd);}catch(Exception ignored){}}
    private static void timeout(FileDescriptor fd,int millis)throws Exception {
        Os.setsockoptTimeval(fd,OsConstants.SOL_SOCKET,OsConstants.SO_RCVTIMEO,StructTimeval.fromMillis(millis));
    }
    private static FileDescriptor socket(int type,int protocol,InetAddress bind,int port)throws Exception {
        FileDescriptor fd=Os.socket(OsConstants.AF_INET6,type,protocol);
        try {
            Os.setsockoptInt(fd,OsConstants.IPPROTO_IPV6,IPV6_TRANSPARENT,1);
            Os.setsockoptInt(fd,OsConstants.SOL_SOCKET,OsConstants.SO_REUSEADDR,1);
            Os.bind(fd,bind,port);
            timeout(fd,1000);
            return fd;
        }catch(Exception e){close(fd);throw e;}
    }
    private static byte[] forward(byte[] q,String proto,Endpoint[] targets) {
        for(int i=0;i<targets.length;i++){
            Endpoint e=targets[i];
            try {
                byte[] ans=DnsUpstreamExchange.query(e.ip,e.port,proto,q);
                return ans;
            }catch(Exception error){log("FAILOVER protocol="+proto+" index="+i+" cause="+error.getClass().getSimpleName());}
        }
        failed.incrementAndGet();
        return DnsPacket.servfail(q);
    }
    private static byte[] validateAndForward(byte[] query,String proto,Endpoint[] endpoints) {
        if(query==null||query.length<17||query.length>MAX_DNS||!DnsPacket.validQuestion(query)){
            failed.incrementAndGet();return null;
        }
        received.incrementAndGet();
        return forward(query,proto,endpoints);
    }
    private static void serveUdp(FileDescriptor listen,FileDescriptor response,Endpoint[] upstream,
                                 ThreadPoolExecutor workers,long deadline) {
        while(running&&System.nanoTime()<deadline) {
            InetSocketAddress client=new InetSocketAddress(0);
            byte[] data=new byte[MAX_DNS];
            try {
                int n=Os.recvfrom(listen,data,0,data.length,0,client);
                if(n<17||client.getAddress()==null||client.getPort()<1)continue;
                byte[] q=Arrays.copyOf(data,n);
                final InetAddress ip=client.getAddress();final int clientPort=client.getPort();
                try { workers.execute(()->{
                    try {
                        byte[] ans=validateAndForward(q,"UDP",upstream);
                        if(ans==null)return;
                        int len=Os.sendto(response,ans,0,ans.length,0,ip,clientPort);
                        if(len==ans.length){replied.incrementAndGet();log("UDP_OK bytes="+len);}
                        else failed.incrementAndGet();
                    }catch(Exception e){failed.incrementAndGet();log("UDP_ERROR "+e.getClass().getSimpleName());}
                }); }catch(java.util.concurrent.RejectedExecutionException ex){failed.incrementAndGet();}
            } catch(ErrnoException e){
                if(e.errno!=OsConstants.EAGAIN && e.errno!=OsConstants.EINTR){
                    failed.incrementAndGet();log("UDP_SOCKET_ERROR errno="+e.errno);break;
                }
            } catch(Exception e){failed.incrementAndGet();log("UDP_ERROR "+e.getClass().getSimpleName());break;}
        }
    }
    private static int readExact(FileDescriptor fd,byte[] buffer,int size)throws Exception {
        int n=0;while(n<size){int got=Os.read(fd,buffer,n,size-n);if(got<=0)return -1;n+=got;}return n;
    }
    private static void serveTcp(FileDescriptor server,Endpoint[] upstream,ThreadPoolExecutor workers,long deadline){
        while(running&&System.nanoTime()<deadline){
            FileDescriptor client=null;
            try {
                client=Os.accept(server,new InetSocketAddress(0));
                final FileDescriptor conn=client;
                timeout(conn,3500);
                try{workers.execute(()->handleTcp(conn,upstream));client=null;}
                catch(java.util.concurrent.RejectedExecutionException ex){failed.incrementAndGet();}
            }catch(ErrnoException e){
                if(e.errno!=OsConstants.EAGAIN && e.errno!=OsConstants.EINTR){failed.incrementAndGet();log("TCP_ACCEPT_ERROR errno="+e.errno);break;}
            }catch(Exception e){failed.incrementAndGet();log("TCP_ERROR "+e.getClass().getSimpleName());break;}
            finally{close(client);}
        }
    }
    private static void handleTcp(FileDescriptor fd,Endpoint[] upstream){
        try {
            byte[] frame=new byte[2];if(readExact(fd,frame,2)!=2)return;
            int len=((frame[0]&255)<<8)|(frame[1]&255);
            if(len<17||len>MAX_DNS){failed.incrementAndGet();return;}
            byte[] q=new byte[len];if(readExact(fd,q,len)!=len)return;
            byte[] ans=validateAndForward(q,"TCP",upstream);if(ans==null)return;
            byte[] out=new byte[ans.length+2];out[0]=(byte)(ans.length>>8);out[1]=(byte)ans.length;
            System.arraycopy(ans,0,out,2,ans.length);
            int sent=0;while(sent<out.length){int n=Os.write(fd,out,sent,out.length-sent);if(n<=0)throw new IllegalStateException("TCP send failed");sent+=n;}
            replied.incrementAndGet();log("TCP_OK bytes="+ans.length);
        }catch(Exception e){failed.incrementAndGet();log("TCP_QUERY_ERROR "+e.getClass().getSimpleName());}
        finally{close(fd);}
    }
    public static void main(String[] args) {
        FileDescriptor udp=null,tcp=null,reply=null;
        ThreadPoolExecutor workers=null;
        try {
            if(Os.geteuid()!=0||args.length<3||args.length>7||args.length%2!=1||
                    !args[0].matches("[A-Za-z0-9_-]{1,64}"))throw new IllegalArgumentException("Bad pilot args/Root privileges");
            Endpoint[] upstream=new Endpoint[(args.length-1)/2];
            for(int i=0;i<upstream.length;i++){
                String literal=args[1+i*2],p=args[2+i*2];
                if(!literal.matches("[0-9a-fA-F:.]+")||!p.matches("[0-9]{1,5}"))throw new IllegalArgumentException("Numeric IP required");
                InetAddress addr=InetAddress.getByName(literal);int port=Integer.parseInt(p);
                if(port<1||port>65535||!DnsUpstreamExchange.permittedUpstream(addr))throw new IllegalArgumentException("Invalid upstream endpoint");
                upstream[i]=new Endpoint(addr,port);
            }
            InetAddress loop=InetAddress.getByName("::1"),doc=InetAddress.getByName(DOC_IP);
            udp=socket(OsConstants.SOCK_DGRAM,OsConstants.IPPROTO_UDP,loop,PORT);
            tcp=socket(OsConstants.SOCK_STREAM,OsConstants.IPPROTO_TCP,loop,PORT);
            reply=socket(OsConstants.SOCK_DGRAM,OsConstants.IPPROTO_UDP,doc,DNS_PORT);
            Os.listen(tcp,32);
            workers=new ThreadPoolExecutor(2,4,10L,TimeUnit.SECONDS,new ArrayBlockingQueue<>(32));
            final FileDescriptor fUdp=udp,fReply=reply,fTcp=tcp;
            final ThreadPoolExecutor fWorkers=workers;
            final long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(LIFETIME_SECONDS);
            Thread udpThread=new Thread(()->serveUdp(fUdp,fReply,upstream,fWorkers,deadline),"Pilot-UDP");
            Thread tcpThread=new Thread(()->serveTcp(fTcp,upstream,fWorkers,deadline),"Pilot-TCP");
            udpThread.setDaemon(true);tcpThread.setDaemon(true);
            udpThread.start();tcpThread.start();
            log("READY euid=0 udp=1 tcp=1 bind=::1:"+PORT+" upstreams="+upstream.length+" ttl="+LIFETIME_SECONDS+"s");
            // Hard TTL prevents runaway Root app_process if the UI dies.
            while(System.nanoTime()<deadline && udpThread.isAlive() && tcpThread.isAlive())Thread.sleep(500);
        }catch(Throwable e){log("ERROR "+e.getClass().getSimpleName()+" "+String.valueOf(e.getMessage()));}
        finally{
            running=false;
            close(udp);close(tcp);close(reply);
            if(workers!=null)workers.shutdownNow();
            log("STOP received="+received.get()+" replied="+replied.get()+" failed="+failed.get());
        }
    }
}
