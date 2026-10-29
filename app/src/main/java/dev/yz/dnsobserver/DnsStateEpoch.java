package dev.yz.dnsobserver;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/** Invalidates observations spanning any concurrent owned lifecycle mutation. */
public final class DnsStateEpoch {
    private static final AtomicLong version=new AtomicLong();
    private static final AtomicInteger writers=new AtomicInteger();
    public static long version(){return version.get();}
    public static boolean busy(){return writers.get()!=0;}
    public static void begin(){writers.incrementAndGet();version.incrementAndGet();}
    public static void end(){version.incrementAndGet();writers.decrementAndGet();}
    public static boolean valid(long sample){return !busy()&&sample==version();}
}
