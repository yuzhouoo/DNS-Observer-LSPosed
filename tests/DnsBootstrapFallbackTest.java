package dev.yz.dnsobserver;
import java.net.*;import java.io.*;import java.util.*;
public final class DnsBootstrapFallbackTest {
    public static void main(String[] args)throws Exception{
        InetAddress loop=InetAddress.getLoopbackAddress();
        try(ServerSocket tcp=new ServerSocket(0,4,loop);DatagramSocket udp=new DatagramSocket(tcp.getLocalPort(),loop)){
            Thread u=new Thread(()->{try{byte[] b=new byte[4096];DatagramPacket p=new DatagramPacket(b,b.length);udp.receive(p);b[0]^=1;b[2]=(byte)0x81;udp.send(new DatagramPacket(b,p.getLength(),p.getSocketAddress()));}catch(Exception e){throw new RuntimeException(e);}});u.start();
            Thread t=new Thread(()->{try(Socket socket=tcp.accept()){
                DataInputStream in=new DataInputStream(socket.getInputStream());byte[] q=new byte[in.readUnsignedShort()];in.readFully(q);
                ByteArrayOutputStream b=new ByteArrayOutputStream();b.write(q);byte[] a=b.toByteArray();a[2]=(byte)0x81;a[3]=(byte)0x80;a[7]=1;
                b.reset();b.write(a);b.write(new byte[]{(byte)0xc0,12,0,1,0,1,0,0,0,60,0,4,1,2,3,4});a=b.toByteArray();
                DataOutputStream out=new DataOutputStream(socket.getOutputStream());if(!DnsObservation.answerAddresses(a)[0].equals("1.2.3.4"))throw new AssertionError();
                out.writeShort(a.length);out.write(a);out.flush();
            }catch(Exception e){throw new RuntimeException(e);}});t.start();
            List<InetAddress> found=DnsBootstrap.resolveViaIp("example.com",loop,1,tcp.getLocalPort());
            if(found.size()!=1||!found.get(0).getHostAddress().equals("1.2.3.4"))throw new AssertionError();u.join(3000);t.join(3000);
        }
        System.out.println("PASS: invalid UDP Bootstrap reply falls back to validated TCP DNS without system resolver");
    }
}
