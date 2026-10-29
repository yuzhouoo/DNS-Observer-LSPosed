package dev.yz.dnsobserver;
public final class DnsStateEpochTest {
    private static void check(boolean b){if(!b)throw new AssertionError();}
    public static void main(String[] args)throws Exception{
        long old=DnsStateEpoch.version();check(DnsStateEpoch.valid(old));
        DnsStateEpoch.begin();check(!DnsStateEpoch.valid(old));
        DnsStateEpoch.begin();DnsStateEpoch.end();check(DnsStateEpoch.busy());
        DnsStateEpoch.end();check(!DnsStateEpoch.busy());check(!DnsStateEpoch.valid(old));
        long sample=DnsStateEpoch.version();
        Thread t=new Thread(()->{DnsStateEpoch.begin();DnsStateEpoch.end();});t.start();t.join();
        check(!DnsStateEpoch.valid(sample));check(DnsStateEpoch.valid(DnsStateEpoch.version()));
        System.out.println("PASS: samples cannot cross concurrent/nested lifecycle changes");
    }
}
