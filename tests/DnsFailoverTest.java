package dev.yz.dnsobserver;
public final class DnsFailoverTest {
    private static void ck(boolean valid,String reason){if(!valid)throw new AssertionError(reason);}
    public static void main(String[] args){
        DnsFailover state=new DnsFailover(0,0);
        ck(!state.onForward(0,1,1),"single transient fallback must not switch");
        ck(!state.onForward(0,1,2),"two fallbacks still stable");
        ck(state.onForward(0,1,3),"third failover should switch to secondary");
        ck(state.current()==1,"now using secondary");
        ck(!state.onHealth(new boolean[]{true,true,true},new boolean[]{true,true,true},60000),"one recovery sample must not switch");
        ck(!state.onHealth(new boolean[]{true,true,true},new boolean[]{true,true,true},120000),"two recovery samples must not switch");
        ck(!state.onHealth(new boolean[]{true,true,true},new boolean[]{true,true,true},180000),"hold-down prevents bounce");
        ck(state.onHealth(new boolean[]{true,true,true},new boolean[]{true,true,true},330000),"stable recovery switches back");
        ck(state.current()==0,"primary should recover");
        ck(!state.onHealth(new boolean[]{true,true,true},new boolean[]{false,true,true},360000),"one bad health probe isn't enough");
        ck(state.onHealth(new boolean[]{true,true,true},new boolean[]{false,false,true},420000),"second failure switches to backup");
        ck(state.current()==2,"backup role selected");
        ck(!state.onHealth(new boolean[]{true,false,true},new boolean[]{false,false,true},480000),"not returning to unreachable upstream");
        System.out.println("PASS: three DNS priority levels, anti-flap and hold-down");
    }
}
