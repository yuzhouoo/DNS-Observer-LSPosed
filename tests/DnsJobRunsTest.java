package dev.yz.dnsobserver;
public final class DnsJobRunsTest {
    private static void check(boolean value){if(!value)throw new AssertionError();}
    public static void main(String[] args){
        DnsJobRuns jobs=new DnsJobRuns();DnsJobRuns.Run a=jobs.begin();
        jobs.cancel();check(a.cancelled);check(!jobs.finish(a));
        DnsJobRuns.Run b=jobs.begin();check(!b.cancelled);check(!jobs.finish(a));
        DnsJobRuns.Run c=jobs.begin();check(b.cancelled);check(!jobs.finish(b));
        check(jobs.finish(c));check(!jobs.finish(c));check(!c.cancelled);
        jobs.cancel();check(!jobs.finish(c));
        System.out.println("PASS: per-run cancellation, replacement, late completion and exactly-once finish");
    }
}
