package dev.yz.dnsobserver;

public final class DnsFeatureStateTest {
    private static void check(boolean value,String message){if(!value)throw new AssertionError(message);}
    public static void main(String[] args) {
        check(DnsFeatureState.resolve("idle",false,false,false,false,false)==DnsFeatureState.UNKNOWN,"Root failure is unknown, never off");
        check(DnsFeatureState.resolve("monitoring",true,true,true,false,false)==DnsFeatureState.ERROR,"requested is not running");
        check(DnsFeatureState.resolve("monitoring",true,true,true,true,false)==DnsFeatureState.ERROR,"rules without server is error");
        check(DnsFeatureState.resolve("monitoring",true,true,true,true,true)==DnsFeatureState.ON,"verified live proxy is on");
        check(DnsFeatureState.resolve("idle",false,false,true,true,false)==DnsFeatureState.ERROR,"orphaned rules require cleanup");
        check(DnsFeatureState.resolve("starting",true,true,false,false,false)==DnsFeatureState.STARTING,"pending action stays pending");
        check(DnsFeatureState.resolve("stopping",true,false,true,false,false)==DnsFeatureState.STOPPING,"async stop not prematurely off");
        check(DnsFeatureState.resolve("idle",false,false,true,false,false)==DnsFeatureState.OFF,"verified absent is off");
        // Exercise every feature-state combination: new installs only from verified clean state.
        for(DnsFeatureState v4:DnsFeatureState.values())for(DnsFeatureState v6:DnsFeatureState.values()) {
            boolean actual=DnsFeatureState.mayStart(false,"idle",false,true,true,false,v4,v6,"disabled");
            check(actual==(v4==DnsFeatureState.OFF && v6==DnsFeatureState.OFF),"must not start over unknown/residual rules");
        }
        DnsFeatureState off=DnsFeatureState.OFF;
        check(!DnsFeatureState.mayStart(false,"idle",false,true,false,true,off,off,"disabled"),"IPv6 conflict blocked");
        check(!DnsFeatureState.mayStart(false,"idle",false,true,false,true,off,off,"unknown"),"unknown IPv6 blocked");
        check(!DnsFeatureState.mayStart(false,"idle",false,true,false,true,off,off,"blocked"),"partial global disable blocks IPv6 takeover");
        check(DnsFeatureState.mayStart(false,"idle",false,true,false,true,off,off,"mixed"),"normal mixed interfaces may use IPv6");
        check(DnsFeatureState.mayStart(false,"idle",false,true,true,true,off,off,"enabled"),"clean dual protocol start");
        check(!DnsFeatureState.mayStart(true,"idle",false,true,true,false,off,off,"enabled"),"duplicate start blocked");
        check(!DnsFeatureState.mayStart(false,"starting",false,true,true,false,off,off,"enabled"),"start pending blocked");
        check(!DnsFeatureState.mayStart(false,"stopping",false,true,true,false,off,off,"enabled"),"stop pending blocked");
        check(!DnsFeatureState.mayStart(false,"idle",true,true,true,false,off,off,"enabled"),"busy action blocked");
        check(!DnsFeatureState.mayStart(false,"idle",false,false,true,false,off,off,"enabled"),"invalid config blocked");
        check(!DnsFeatureState.mayStart(false,"idle",false,true,false,false,off,off,"enabled"),"empty selection blocked");
        System.out.println("PASS: feature status truth, partial failures, stale/unknown state, duplicate start and IPv6 conflict gating");
    }
}
