package dev.yz.dnsobserver;
import java.util.Arrays;
public class DnsPacketTest {
    static void ok(boolean v,String s) {if(!v)throw new AssertionError(s);}
    public static void main(String[] args) throws Exception {
        byte[] q=DnsPacket.probeQuestion();
        ok(DnsPacket.validQuestion(q),"valid probe");
        byte[] bad=DnsPacket.servfail(q);
        ok(DnsPacket.validReply(q,bad),"reply id");
        ok((bad[3]&15)==2,"servfail code");
        ok(bad.length==q.length,"short reply");
        byte[] mutated=Arrays.copyOf(bad,bad.length);mutated[0]^=1;
        ok(!DnsPacket.validReply(q,mutated),"bad id detected");
        ok(!DnsPacket.validQuestion(new byte[0]),"short query");
        ok(DnsBootstrap.parseLiteral("223.5.5.5").getHostAddress().equals("223.5.5.5"),"literal ip");
        try {DnsBootstrap.parseLiteral("bootstrap.example.org");throw new AssertionError("hostname rejected");}
        catch (IllegalArgumentException expected) { }
        System.out.println("DNS wire/bootstrap core tests: PASS");
    }
}
