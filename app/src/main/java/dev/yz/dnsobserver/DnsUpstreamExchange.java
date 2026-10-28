package dev.yz.dnsobserver;
import java.io.*;
import java.net.*;
import java.util.Arrays;

/** A single bounded standard DNS exchange for the isolated TPROXY upstream test. */
public final class DnsUpstreamExchange {
    private DnsUpstreamExchange(){}
    private static final int TIMEOUT_MS=2500, MAX_REPLY=4096;
    /** Reject loopback, multicast and RFC3849 documentation IPv6 targets, never our own fake destination. */
    public static boolean permittedUpstream(InetAddress address){
        if(address==null||address.isAnyLocalAddress()||address.isLoopbackAddress()
                ||address.isMulticastAddress()||address.isLinkLocalAddress())return false;
        if(address instanceof Inet6Address){
            byte[] b=address.getAddress();
            if((b[0]&255)==0x20 && (b[1]&255)==0x01 &&
               (b[2]&255)==0x0d && (b[3]&255)==0xb8)return false;
        }
        return address instanceof Inet4Address || address instanceof Inet6Address;
    }
    public static byte[] query(InetAddress server,int port,String protocol,byte[] question)throws IOException{
        if(server==null||port<1||port>65535||!DnsPacket.validQuestion(question)||
           (!"UDP".equals(protocol)&&!"TCP".equals(protocol)))
            throw new IOException("Invalid upstream DNS experiment arguments");
        byte[] reply;
        if("UDP".equals(protocol)){
            try(DatagramSocket s=new DatagramSocket()){
                s.connect(new InetSocketAddress(server,port));s.setSoTimeout(TIMEOUT_MS);
                s.send(new DatagramPacket(question,question.length));
                byte[] buf=new byte[MAX_REPLY];DatagramPacket p=new DatagramPacket(buf,buf.length);
                s.receive(p);reply=Arrays.copyOf(buf,p.getLength());
            }
        }else{
            try(Socket s=new Socket()){
                s.connect(new InetSocketAddress(server,port),TIMEOUT_MS);s.setSoTimeout(TIMEOUT_MS);
                DataOutputStream out=new DataOutputStream(new BufferedOutputStream(s.getOutputStream()));
                out.writeShort(question.length);out.write(question);out.flush();
                DataInputStream in=new DataInputStream(new BufferedInputStream(s.getInputStream()));
                int size=in.readUnsignedShort();
                if(size<12||size>MAX_REPLY)throw new IOException("Invalid TCP DNS response length "+size);
                reply=new byte[size];in.readFully(reply);
            }
        }
        if(!DnsPacket.validReply(question,reply))throw new IOException("Upstream DNS ID/QR mismatch");
        int rcode=reply[3]&15;
        if(rcode!=0 && rcode!=3)throw new IOException("Upstream RCODE="+rcode);
        if(DnsPacket.truncated(reply))throw new IOException("Upstream DNS truncated response");
        return reply;
    }
}
