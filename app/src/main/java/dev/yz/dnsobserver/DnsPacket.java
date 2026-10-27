package dev.yz.dnsobserver;

import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;

/** Small protocol helpers with no Android dependencies; can be JVM unit tested. */
public final class DnsPacket {
    private DnsPacket() { }
    public static boolean validQuestion(byte[] q) {
        return q != null && q.length >= 17 && (q[2] & 0x80) == 0
                && (((q[4]&255)<<8) | (q[5]&255)) == 1 && questionEnd(q) > 0;
    }
    private static int questionEnd(byte[] q) {
        int offset = 12;
        for (int i = 0; i < 128 && offset < q.length; i++) {
            int length = q[offset]&255;
            if (length == 0) return offset+5 <= q.length ? offset+5 : -1;
            if ((length & 0xC0) == 0xC0) return offset+6 <= q.length ? offset+6 : -1;
            if (length > 63 || offset+length+1 >= q.length) return -1;
            offset += length+1;
        }
        return -1;
    }
    public static boolean validReply(byte[] q, byte[] a) {
        return q != null && q.length >= 12 && a != null && a.length >= 12
                && q[0]==a[0] && q[1]==a[1] && (a[2]&0x80)!=0;
    }
    public static boolean truncated(byte[] a) { return a != null && a.length > 3 && (a[2]&2)!=0; }
    public static byte[] servfail(byte[] q) {
        if (!validQuestion(q)) return null;
        int end = questionEnd(q);
        byte[] result = Arrays.copyOf(q, end);
        result[2]=(byte)((q[2]&0x7D)|0x80); // QR=1, clear TC
        result[3]=(byte)((q[3]&0xF0)|2); // RCODE=SERVFAIL
        for (int i=6;i<12;i++)result[i]=0; // no answer/authority/additional
        return result;
    }
    public static byte[] probeQuestion() {
        byte[] name = new byte[]{7,'e','x','a','m','p','l','e',3,'c','o','m',0};
        int id = ThreadLocalRandom.current().nextInt(65536);
        byte[] q = new byte[12+name.length+4];
        q[0]=(byte)(id>>8);q[1]=(byte)id;q[2]=1;q[5]=1;
        System.arraycopy(name,0,q,12,name.length);
        q[q.length-3]=1; q[q.length-1]=1; // type A, class IN
        return q;
    }
}
