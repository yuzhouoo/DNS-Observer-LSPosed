package dev.yz.dnsobserver;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.Arrays;

/** Real DNS request/reply latency on ONE address and ONE transport. No Android dependencies. */
public final class DnsProbe {
    private DnsProbe() { }
    private static final int TIMEOUT_MS=2000;
    private static final int MAX_REPLY=4096;

    public static final class Sample {
        public final String ip, family, transport, error;
        public final int port, responseCode;
        public final long latencyMs;
        public final boolean success;
        Sample(InetAddress addr,int port,String transport,boolean success,long latency,int rcode,String error) {
            this.ip=addr.getHostAddress();this.family=addr instanceof Inet4Address?"IPv4":"IPv6";
            this.port=port;this.transport=transport;this.success=success;
            this.latencyMs=latency;this.responseCode=rcode;this.error=error;
        }
    }

    /** Counts a matched response with a non-SERVFAIL code as a working DNS service. */
    public static Sample measure(InetAddress address,int port,String transport) {
        byte[] query=DnsPacket.probeQuestion();
        long start=System.nanoTime();
        try {
            byte[] answer="TCP".equals(transport)?queryTcp(address,port,query):queryUdp(address,port,query);
            long elapsed=Math.max(0,(System.nanoTime()-start)/1_000_000);
            if(!DnsPacket.validReply(query,answer))
                return new Sample(address,port,transport,false,elapsed,-1,"响应 ID/QR 不匹配");
            int rcode=answer[3]&15;
            if(rcode==2) return new Sample(address,port,transport,false,elapsed,rcode,"DNS SERVFAIL (RCODE=2)");
            if(rcode==5) return new Sample(address,port,transport,false,elapsed,rcode,"DNS REFUSED (RCODE=5)");
            if(rcode!=0 && rcode!=3) return new Sample(address,port,transport,false,elapsed,rcode,"DNS 返回错误 RCODE="+rcode);
            if("UDP".equals(transport) && DnsPacket.truncated(answer))
                return new Sample(address,port,transport,false,elapsed,rcode,"UDP 响应被截断，请查看 TCP 测试");
            return new Sample(address,port,transport,true,elapsed,rcode,"");
        } catch (SocketTimeoutException e) {
            return new Sample(address,port,transport,false,Math.max(0,(System.nanoTime()-start)/1_000_000),-1,"超时（2 秒）");
        } catch (Exception e) {
            String detail=e.getMessage();
            if(detail==null||detail.isEmpty())detail=e.getClass().getSimpleName();
            if(detail.length()>90)detail=detail.substring(0,90);
            return new Sample(address,port,transport,false,Math.max(0,(System.nanoTime()-start)/1_000_000),-1,detail);
        }
    }
    private static byte[] queryUdp(InetAddress address,int port,byte[] query) throws IOException {
        try(DatagramSocket socket=new DatagramSocket()) {
            socket.connect(new InetSocketAddress(address,port));socket.setSoTimeout(TIMEOUT_MS);
            socket.send(new DatagramPacket(query,query.length));
            byte[] raw=new byte[MAX_REPLY];DatagramPacket received=new DatagramPacket(raw,raw.length);
            socket.receive(received);
            return Arrays.copyOf(received.getData(),received.getLength());
        }
    }
    private static byte[] queryTcp(InetAddress address,int port,byte[] query) throws IOException {
        try(Socket socket=new Socket()) {
            socket.connect(new InetSocketAddress(address,port),TIMEOUT_MS);
            socket.setSoTimeout(TIMEOUT_MS);
            DataOutputStream out=new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));
            out.writeShort(query.length);out.write(query);out.flush();
            DataInputStream in=new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            int length=in.readUnsignedShort();
            if(length<12 || length>MAX_REPLY)throw new IOException("DNS TCP 响应长度非法: "+length);
            byte[] result=new byte[length];in.readFully(result);return result;
        }
    }
}
