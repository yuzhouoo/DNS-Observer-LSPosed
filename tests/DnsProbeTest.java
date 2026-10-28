package dev.yz.dnsobserver;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;

/** Standalone localhost real UDP+TCP DNS replies; no public DNS dependency. */
public final class DnsProbeTest {
    private static void check(boolean ok,String msg){if(!ok)throw new AssertionError(msg);}
    public static void main(String[] args) throws Exception {
        InetAddress loop=InetAddress.getByName("127.0.0.1");
        try(ServerSocket tcp=new ServerSocket(0,5,loop);
            DatagramSocket udp=new DatagramSocket(tcp.getLocalPort(),loop)) {
            final int port=tcp.getLocalPort();
            Thread udpThread=new Thread(()->{
                try {
                    byte[] bytes=new byte[2048];DatagramPacket p=new DatagramPacket(bytes,bytes.length);
                    udp.receive(p);byte[] reply=Arrays.copyOf(p.getData(),p.getLength());
                    reply[2]=(byte)0x81;reply[3]=(byte)0x80;
                    udp.send(new DatagramPacket(reply,reply.length,p.getAddress(),p.getPort()));
                } catch(Exception e){throw new RuntimeException(e);}
            });
            Thread tcpThread=new Thread(()->{
                try(Socket s=tcp.accept()) {
                    DataInputStream in=new DataInputStream(s.getInputStream());
                    int size=in.readUnsignedShort();byte[] data=new byte[size];in.readFully(data);
                    data[2]=(byte)0x81;data[3]=(byte)0x80;
                    DataOutputStream out=new DataOutputStream(s.getOutputStream());
                    out.writeShort(data.length);out.write(data);out.flush();
                } catch(Exception e){throw new RuntimeException(e);}
            });
            udpThread.start();tcpThread.start();
            DnsProbe.Sample udpSample=DnsProbe.measure(loop,port,"UDP");
            DnsProbe.Sample tcpSample=DnsProbe.measure(loop,port,"TCP");
            check(udpSample.success && udpSample.family.equals("IPv4"),"UDP response failed: "+udpSample.error);
            check(tcpSample.success && tcpSample.family.equals("IPv4"),"TCP response failed: "+tcpSample.error);
            check(udpSample.latencyMs>=0 && tcpSample.latencyMs>=0,"latency must be monotonic nonnegative");
            udpThread.join(3000);tcpThread.join(3000);
        }
        System.out.println("PASS: per-IP UDP DNS and TCP DNS framing + latency");
    }
}
