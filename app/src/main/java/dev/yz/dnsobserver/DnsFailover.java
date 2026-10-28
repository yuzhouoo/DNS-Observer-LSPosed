package dev.yz.dnsobserver;

/** Three-level priority switching, without mixing one-off request fallback and global state. */
public final class DnsFailover {
    public static final String[] NAMES={"主","从","备"};
    private static final int FORWARD_FAILURES=3;
    private static final int HEALTH_FAILURES=2;
    private static final int RETURN_HEALTHY_CHECKS=3;
    private static final long RETURN_HOLD_MS=5*60*1000L;
    private volatile int active;
    private int requestFailures,healthFailures,betterChecks,betterRole=-1;
    private long lastSwitchMs;
    public DnsFailover(int initial,long now) {
        if(initial<0||initial>2)throw new IllegalArgumentException("invalid role");
        active=initial;lastSwitchMs=now;
    }
    public int current() {return active;}
    public synchronized boolean onForward(int requestedRole,int answeredRole,long now) {
        if(requestedRole!=active)return false;
        if(answeredRole==active){requestFailures=0;return false;}
        if(answeredRole<0)return false;
        if(++requestFailures<FORWARD_FAILURES)return false;
        return change(answeredRole,now);
    }
    public synchronized boolean onHealth(boolean[] configured,boolean[] healthy,long now) {
        if(configured.length!=3||healthy.length!=3)throw new IllegalArgumentException("three groups required");
        if(!healthy[active]) {
            betterChecks=0;betterRole=-1;
            if(++healthFailures<HEALTH_FAILURES)return false;
            for(int role=0;role<3;role++)if(role!=active && configured[role]&&healthy[role])
                return change(role,now); // Emergency failover, no hold-off.
            return false;
        }
        healthFailures=0;
        if(active==0)return false;
        int better=-1;
        for(int role=0;role<active;role++)if(configured[role]&&healthy[role]){better=role;break;}
        if(better<0){betterChecks=0;betterRole=-1;return false;}
        if(better!=betterRole){betterRole=better;betterChecks=0;}
        betterChecks++;
        if(betterChecks>=RETURN_HEALTHY_CHECKS && now-lastSwitchMs>=RETURN_HOLD_MS)
            return change(better,now);
        return false;
    }
    private boolean change(int next,long now) {
        if(next<0||next>2||next==active)return false;
        active=next;lastSwitchMs=now;requestFailures=0;healthFailures=0;
        betterChecks=0;betterRole=-1;return true;
    }
}
