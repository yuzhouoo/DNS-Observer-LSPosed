package dev.yz.dnsobserver;

/** One cancellation token per scheduled run; stopped runs never finish newer work. */
public final class DnsJobRuns {
    public static final class Run { public volatile boolean cancelled;public volatile Thread worker; }
    private Run active;
    public synchronized Run begin(){cancel();active=new Run();return active;}
    public synchronized void cancel(){
        if(active!=null){active.cancelled=true;if(active.worker!=null)active.worker.interrupt();active=null;}
    }
    public synchronized boolean finish(Run run){
        if(active!=run||run.cancelled)return false;
        active=null;return true;
    }
}
