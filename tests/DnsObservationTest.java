package dev.yz.dnsobserver;
public final class DnsObservationTest {
    static void check(boolean b){if(!b)throw new AssertionError();}
    public static void main(String[] args){
        check(DnsObservation.http("https://example.com/news","GET",null)==null);
        DnsObservation.Http h=DnsObservation.http("https://u:secret@example.com/dns-query?token=secret&dns=AAAA#secret","GET",null);
        check(h!=null&&h.transport.equals("SUSPECTED"));check(!h.url.contains("secret")&&!h.url.contains("dns="));
        h=DnsObservation.http("https://dns.example/custom?key=secret","POST","application/dns-message; charset=binary");
        check(h.transport.equals("DoH")&&h.evidence.equals("HTTP_API_MEDIA_TYPE"));
        check(DnsObservation.http("http://dns.example/custom","POST","application/dns-message").transport.equals("HTTP_DNS"));
        check(DnsObservation.http("https://example.com/custom?dns=abc","GET",null).dnsParam);
        String encoded=java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(DnsPacket.probeQuestion());
        h=DnsObservation.http("https://dns.example/custom?token=secret&dns="+encoded,"GET",null);
        check(h.transport.equals("DoH")&&h.evidence.equals("HTTP_API_DNS_QUERY")&&h.detail.contains("example.com"));
        check(!h.url.contains("token")&&!h.url.contains(encoded));
        check(DnsObservation.http("file:///dns-query","GET",null)==null);
        byte[] q=DnsPacket.probeQuestion();check(DnsObservation.questionName(q).equals("example.com"));check(DnsObservation.questionType(q)==1);
        check(DnsObservation.questionName(new byte[3]).isEmpty());
        System.out.println("PASS: HTTP evidence classification, no false DoH from keywords, credential/query stripping and DNS question metadata");
    }
}
