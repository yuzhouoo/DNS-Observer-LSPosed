package dev.yz.dnsobserver;

import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructCmsghdr;
import android.system.StructMsghdr;
import android.system.StructTimeval;
import android.system.StructPollfd;

import java.io.FileDescriptor;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/** Opt-in, user-controlled local-output IPv6 DNS53 transparent relay.
 * Requires Android 12+ Os.recvmsg/StructMsghdr and IPV6_RECVPKTINFO.
 * Different from document-target pilot: the UDP reply MUST use the received
 * packet's original IPv6 destination, not a fixed documentation IP. */
public final class DnsIpv6GlobalDaemon {
    private static final int IPV6_TRANSPARENT=75;
    private static final int PORT=15456, DNS_PORT=53, MAX_DNS=4096;
    private static final AtomicInteger received=new AtomicInteger(), replied=new AtomicInteger(), errors=new AtomicInteger();
    private static volatile boolean running=true;
    private static volatile int consecutiveFailures=0;
    private DnsIpv6GlobalDaemon(){}
    private static final class Endpoint {
        final InetAddress ip;final int port;
        Endpoint(InetAddress ip,int port){this.ip=ip;this.port=port;}
    }
    private static void log(String message){System.out.println("DNS6GLOBAL "+message);System.out.flush();}
    private static void close(FileDescriptor fd){if(fd!=null)try{Os.close(fd);}catch(Exception ignored){}}
    private static FileDescriptor createListener(int type,int proto)throws Exception {
        FileDescriptor fd=Os.socket(OsConstants.AF_INET6,type,proto);
        try{
            Os.setsockoptInt(fd,OsConstants.IPPROTO_IPV6,IPV6_TRANSPARENT,1);
            Os.setsockoptInt(fd,OsConstants.IPPROTO_IPV6,OsConstants.IPV6_V6ONLY,1);
            Os.setsockoptInt(fd,OsConstants.SOL_SOCKET,OsConstants.SO_REUSEADDR,1);
            if(type==OsConstants.SOCK_DGRAM)
                Os.setsockoptInt(fd,OsConstants.IPPROTO_IPV6,OsConstants.IPV6_RECVPKTINFO,1);
            if(type==OsConstants.SOCK_DGRAM)
                Os.setsockoptTimeval(fd,OsConstants.SOL_SOCKET,OsConstants.SO_RCVTIMEO,StructTimeval.fromMillis(950));
            else
                Os.fcntlInt(fd,OsConstants.F_SETFL,Os.fcntlInt(fd,OsConstants.F_GETFL,0)|OsConstants.O_NONBLOCK);
            Os.bind(fd,InetAddress.getByName("::1"),PORT);
            return fd;
        }catch(ErrnoException ex){
            log("BIND_ERROR protocol="+(type==OsConstants.SOCK_DGRAM?"UDP":"TCP")+
                " address=::1 port="+PORT+" errno="+ex.errno+" "+ex.getMessage());
            close(fd);throw ex;
        }catch(Exception ex){close(fd);throw ex;}
    }
    private static final class UdpMessage {
        final byte[] data;final InetSocketAddress source;final InetAddress target;
        UdpMessage(byte[] data,InetSocketAddress source,InetAddress target){this.data=data;this.source=source;this.target=target;}
    }
    /** Obtain the original IPv6 destination via IPV6_PKTINFO ancillary data. */
    private static UdpMessage receiveUdp(FileDescriptor udp)throws Exception {
        ByteBuffer payload=ByteBuffer.allocate(MAX_DNS);
        StructMsghdr msg=new StructMsghdr(new InetSocketAddress(0),new ByteBuffer[]{payload},null,0);
        int n=Os.recvmsg(udp,msg,0);
        if(n<=0||n>MAX_DNS||(msg.msg_flags&OsConstants.MSG_TRUNC)!=0)
            throw new IllegalStateException("Bad/truncated UDP packet");
        if(!(msg.msg_name instanceof InetSocketAddress))
            throw new IllegalStateException("Missing UDP source");
        InetSocketAddress client=(InetSocketAddress)msg.msg_name;
        InetAddress target=null;
        if(msg.msg_control!=null)for(StructCmsghdr c:msg.msg_control){
            if(c.cmsg_level==OsConstants.IPPROTO_IPV6 && c.cmsg_type==OsConstants.IPV6_PKTINFO &&
                    c.cmsg_data!=null && c.cmsg_data.length>=16){
                target=InetAddress.getByAddress(Arrays.copyOf(c.cmsg_data,16));break;
            }
        }
        if(!(target instanceof Inet6Address)||target.isAnyLocalAddress()||target.isLoopbackAddress())
            throw new IllegalStateException("Missing original IPv6 destination/PKTINFO");
        if(client.getAddress()==null||client.getPort()<1)
            throw new IllegalStateException("Invalid UDP peer");
        return new UdpMessage(Arrays.copyOf(payload.array(),n),client,target);
    }
    private static byte[] forward(byte[] request,String protocol,Endpoint[] targets) {
        if(!DnsPacket.validQuestion(request))return null;
        received.incrementAndGet();
        for(int i=0;i<targets.length;i++) {
            Endpoint e=targets[i];
            try{
                byte[] result=DnsUpstreamExchange.query(e.ip,e.port,protocol,request);
                consecutiveFailures=0;
                if(i>0)log("FAILOVER_OK protocol="+protocol+" index="+i);
                return result;
            }catch(Exception ex){log("UPSTREAM_FAIL protocol="+protocol+" index="+i+" error="+ex.getClass().getSimpleName());}
        }
        errors.incrementAndGet();
        if(++consecutiveFailures%6==0)log("UNHEALTHY: repeated upstream failures="+consecutiveFailures);
        return DnsPacket.servfail(request);
    }
    private static void respondUdp(UdpMessage message,byte[] reply)throws Exception {
        // Temporary per-request transparent reply socket: avoids spoofing the fixed
        // document address when intercepted clients use arbitrary DNS servers.
        FileDescriptor fd=Os.socket(OsConstants.AF_INET6,OsConstants.SOCK_DGRAM,OsConstants.IPPROTO_UDP);
        try{
            Os.setsockoptInt(fd,OsConstants.IPPROTO_IPV6,IPV6_TRANSPARENT,1);
            Os.setsockoptInt(fd,OsConstants.IPPROTO_IPV6,OsConstants.IPV6_V6ONLY,1);
            Os.setsockoptInt(fd,OsConstants.SOL_SOCKET,OsConstants.SO_REUSEADDR,1);
            Os.bind(fd,message.target,DNS_PORT);
            int sent=Os.sendto(fd,reply,0,reply.length,0,message.source.getAddress(),message.source.getPort());
            if(sent!=reply.length)throw new IllegalStateException("Short transparent UDP response");
            replied.incrementAndGet();
        }finally{close(fd);}
    }
    private static void serveUdp(FileDescriptor listen,Endpoint[] upstream,ThreadPoolExecutor workers){
        while(running){
            try{
                UdpMessage q=receiveUdp(listen);
                workers.execute(()->{
                    try{
                        byte[] ans=forward(q.data,"UDP",upstream);
                        if(ans!=null)respondUdp(q,ans);
                    }catch(Exception e){errors.incrementAndGet();log("UDP_ERROR "+e.getClass().getSimpleName()+" "+String.valueOf(e.getMessage()));}
                });
            }catch(ErrnoException ex){
                if(ex.errno!=OsConstants.EAGAIN && ex.errno!=OsConstants.EINTR){
                    errors.incrementAndGet();log("UDP_SOCKET_ERROR errno="+ex.errno);running=false;break;
                }
            }catch(java.util.concurrent.RejectedExecutionException ex){errors.incrementAndGet();log("QUEUE_FULL protocol=UDP");}
            catch(Exception ex){errors.incrementAndGet();log("UDP_RECV_ERROR "+ex.getClass().getSimpleName()+" "+String.valueOf(ex.getMessage()));
                // An unavailable original-destination API must fail closed, not proxy DNS using ::1.
                running=false;break;
            }
        }
    }
    private static int readExact(FileDescriptor fd,byte[] out,int n)throws Exception {
        int got=0;while(got<n){int r=Os.read(fd,out,got,n-got);if(r<=0)return -1;got+=r;}return got;
    }
    private static void handleTcp(FileDescriptor fd,Endpoint[] upstream){
        try{
            SocketAddress local=Os.getsockname(fd);
            if(!(local instanceof InetSocketAddress))throw new IllegalStateException("TCP destination unavailable");
            InetSocketAddress origin=(InetSocketAddress)local;
            if(!(origin.getAddress() instanceof Inet6Address)||origin.getPort()!=DNS_PORT ||
                    origin.getAddress().isAnyLocalAddress()||origin.getAddress().isLoopbackAddress())
                throw new IllegalStateException("TCP original destination lost: "+origin);
            byte[] length=new byte[2];if(readExact(fd,length,2)!=2)return;
            int count=((length[0]&255)<<8)|(length[1]&255);
            if(count<17||count>MAX_DNS){errors.incrementAndGet();return;}
            byte[] q=new byte[count];if(readExact(fd,q,count)!=count)return;
            byte[] answer=forward(q,"TCP",upstream);if(answer==null)return;
            byte[] framed=new byte[answer.length+2];
            framed[0]=(byte)(answer.length>>8);framed[1]=(byte)answer.length;
            System.arraycopy(answer,0,framed,2,answer.length);
            int sent=0;while(sent<framed.length){
                int n=Os.write(fd,framed,sent,framed.length-sent);
                if(n<=0)throw new IllegalStateException("TCP send failed");sent+=n;
            }
            replied.incrementAndGet();
        }catch(Exception ex){errors.incrementAndGet();log("TCP_QUERY_ERROR "+ex.getClass().getSimpleName()+" "+String.valueOf(ex.getMessage()));}
        finally{close(fd);}
    }
    private static FileDescriptor createTcpListener()throws Exception {
        FileDescriptor fd=createListener(OsConstants.SOCK_STREAM,OsConstants.IPPROTO_TCP);
        try{Os.listen(fd,24);return fd;}catch(Exception error){close(fd);throw error;}
    }
    private static DnsTcpAcceptLoop<FileDescriptor,FileDescriptor> tcpLoop(FileDescriptor initial,Endpoint[] upstream,ThreadPoolExecutor workers){
        return new DnsTcpAcceptLoop<>(initial,new DnsTcpAcceptLoop.Io<FileDescriptor,FileDescriptor>(){
            public boolean running(){return DnsIpv6GlobalDaemon.running;}
            public FileDescriptor accept(FileDescriptor server)throws Exception {
                StructPollfd poll=new StructPollfd();poll.fd=server;poll.events=(short)OsConstants.POLLIN;
                if(Os.poll(new StructPollfd[]{poll},950)==0)return null;
                if((poll.revents&(OsConstants.POLLERR|OsConstants.POLLHUP|OsConstants.POLLNVAL))!=0)
                    throw new java.io.IOException("TCP listener poll revents="+poll.revents+" valid="+server.valid());
                if((poll.revents&OsConstants.POLLIN)==0)return null;
                // The peer address is unused. Avoid sockaddr conversion and let getsockname
                // on the accepted socket supply the original transparent destination.
                return Os.accept(server,null);
            }
            public void configure(FileDescriptor client)throws Exception {
                Os.fcntlInt(client,OsConstants.F_SETFL,Os.fcntlInt(client,OsConstants.F_GETFL,0)&~OsConstants.O_NONBLOCK);
                Os.setsockoptTimeval(client,OsConstants.SOL_SOCKET,OsConstants.SO_RCVTIMEO,StructTimeval.fromMillis(3500));
                Os.setsockoptTimeval(client,OsConstants.SOL_SOCKET,OsConstants.SO_SNDTIMEO,StructTimeval.fromMillis(3500));
            }
            public void dispatch(FileDescriptor client){workers.execute(()->handleTcp(client,upstream));}
            public void closeClient(FileDescriptor client){close(client);}
            public void closeListener(FileDescriptor listener){close(listener);}
            public FileDescriptor openListener()throws Exception{return createTcpListener();}
            public DnsTcpAcceptLoop.Failure classify(Exception error){
                if(error instanceof ErrnoException){
                    int errno=((ErrnoException)error).errno;
                    if(errno==OsConstants.EAGAIN||errno==OsConstants.EINTR||errno==OsConstants.ECONNABORTED||
                       errno==OsConstants.EPROTO||errno==OsConstants.ENETUNREACH||errno==OsConstants.EHOSTUNREACH)
                        return DnsTcpAcceptLoop.Failure.RETRY;
                }
                return DnsTcpAcceptLoop.Failure.RECOVER;
            }
            public void event(String stage,Exception error){
                if(error!=null)errors.incrementAndGet();
                log(stage+(error==null?" port="+PORT+" listening=1":" "+error.toString()));
            }
            public void fatal(){DnsIpv6GlobalDaemon.running=false;}
            public void pause(long millis)throws InterruptedException{Thread.sleep(millis);}
            public long now(){return TimeUnit.NANOSECONDS.toMillis(System.nanoTime());}
        });
    }
    public static void main(String[] args){
        FileDescriptor udp=null,tcp=null;ThreadPoolExecutor workers=null;
        DnsTcpAcceptLoop<FileDescriptor,FileDescriptor> acceptLoop=null;
        try{
            if(Os.geteuid()!=0||args.length<3||args.length>7||args.length%2!=1||
                    !args[0].matches("[A-Za-z0-9_-]{1,64}"))throw new IllegalArgumentException("Root/token/endpoint count invalid");
            Endpoint[] upstream=new Endpoint[(args.length-1)/2];
            for(int i=0;i<upstream.length;i++){
                String ip=args[i*2+1],port=args[i*2+2];
                if(!ip.matches("[0-9a-fA-F:.]+") || !port.matches("[0-9]{1,5}"))throw new IllegalArgumentException("numeric upstream required");
                InetAddress addr=InetAddress.getByName(ip);int p=Integer.parseInt(port);
                if(p<1||p>65535||!DnsUpstreamExchange.permittedUpstream(addr))throw new IllegalArgumentException("disallowed upstream");
                upstream[i]=new Endpoint(addr,p);
            }
            udp=createListener(OsConstants.SOCK_DGRAM,OsConstants.IPPROTO_UDP);
            tcp=createTcpListener();
            workers=new ThreadPoolExecutor(2,4,10,TimeUnit.SECONDS,new ArrayBlockingQueue<>(32));
            final FileDescriptor fUdp=udp;final ThreadPoolExecutor pool=workers;
            acceptLoop=tcpLoop(tcp,upstream,pool);
            Thread thUdp=new Thread(()->serveUdp(fUdp,upstream,pool),"GlobalDns-UDP");
            Thread thTcp=new Thread(acceptLoop,"GlobalDns-TCP");
            thUdp.setDaemon(true);thTcp.setDaemon(true);thUdp.start();thTcp.start();
            log("READY euid=0 pid="+Os.getpid()+" port="+PORT+" endpoints="+upstream.length+" persistent=1 pktinfo=1");
            while(running && thUdp.isAlive() && thTcp.isAlive())Thread.sleep(350);
        }catch(Throwable ex){log("ERROR "+ex.getClass().getSimpleName()+" "+String.valueOf(ex.getMessage()));}
        finally{
            running=false;close(udp);
            if(acceptLoop!=null)acceptLoop.close();else close(tcp);
            if(workers!=null)workers.shutdownNow();
            log("STOP received="+received.get()+" replied="+replied.get()+" errors="+errors.get());
        }
    }
}
