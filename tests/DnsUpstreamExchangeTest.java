package dev.yz.dnsobserver;
import java.io.*;
import java.net.*;
import java.util.Arrays;
public final class DnsUpstreamExchangeTest {
    private static void check(boolean ok,String message){if(!ok)throw new AssertionError(message);}
    private static byte[] answer(byte[] q) {
        byte[] a=DnsPacket.servfail(q);a[3]=(byte)(a[3]&0xf0);return a;
    }
    public static void main(String[] args)throws Exception{
        check(!DnsUpstreamExchange.permittedUpstream(InetAddress.getByName("::1")),"loopback blocked");
        check(!DnsUpstreamExchange.permittedUpstream(InetAddress.getByName("2001:db8:ffff::53")),"document prefix blocked");
        check(DnsUpstreamExchange.permittedUpstream(InetAddress.getByName("223.5.5.5")),"public IPv4 DNS accepted");
        byte[] query=DnsPacket.probeQuestion();
        InetAddress local=InetAddress.getByName("127.0.0.1");
        try(DatagramSocket receiver=new DatagramSocket(0,local)){
            Thread server=new Thread(()->{
                try{
                    byte[] buf=new byte[1024];DatagramPacket packet=new DatagramPacket(buf,buf.length);
                    receiver.receive(packet);
                    byte[] reply=answer(Arrays.copyOf(buf,packet.getLength()));
                    receiver.send(new DatagramPacket(reply,reply.length,packet.getAddress(),packet.getPort()));
                }catch(Exception e){throw new RuntimeException(e);}
            });server.start();
            byte[] got=DnsUpstreamExchange.query(local,receiver.getLocalPort(),"UDP",query);
            check(DnsPacket.validReply(query,got)&& (got[3]&15)==0,"UDP DNS");
            server.join(1000);
        }
        try(ServerSocket listener=new ServerSocket(0,1,local)){
            Thread server=new Thread(()->{
                try(Socket c=listener.accept()){
                    DataInputStream in=new DataInputStream(c.getInputStream());
                    byte[] question=new byte[in.readUnsignedShort()];in.readFully(question);
                    byte[] reply=answer(question);
                    DataOutputStream out=new DataOutputStream(c.getOutputStream());
                    out.writeShort(reply.length);out.write(reply);out.flush();
                }catch(Exception e){throw new RuntimeException(e);}
            });server.start();
            byte[] got=DnsUpstreamExchange.query(local,listener.getLocalPort(),"TCP",query);
            check(DnsPacket.validReply(query,got) && (got[3]&15)==0,"TCP DNS");
            server.join(1000);
        }
        try {DnsUpstreamExchange.query(local,53,"UDP",new byte[0]);throw new AssertionError("bad question accepted");}
        catch(IOException expected){}
        System.out.println("DNS upstream UDP/TCP protocol tests: PASS");
    }
}
