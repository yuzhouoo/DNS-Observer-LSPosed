package dev.yz.dnsobserver;

/** Debounce real process/rule snapshots, never infer STOPPED from an unreadable probe. */
public final class BoxWatchState {
    public enum Result { UNKNOWN, WAIT, BASELINE, SAME, CHANGED }
    private String candidate="", settled="";
    private int samples;
    public void reset(){candidate="";settled="";samples=0;}
    /** A pre-start read establishes identity, not authorization to repair. */
    public void seed(String state,String signature){
        reset();
        if(signature!=null&&!signature.isEmpty()&&("running".equals(state)||"stopped".equals(state)))settled=state+":"+signature;
    }
    public Result observe(String state,String signature) {
        if(signature==null||signature.isEmpty()||!("running".equals(state)||"stopped".equals(state))) {
            candidate="";samples=0;
            return "starting".equals(state)||"stopping".equals(state)?Result.WAIT:Result.UNKNOWN;
        }
        String key=state+":"+signature;
        if(!key.equals(candidate)){candidate=key;samples=1;return Result.WAIT;}
        if(samples<2)samples++;
        if(key.equals(settled))return Result.SAME;
        boolean first=settled.isEmpty();settled=key;
        return first?Result.BASELINE:Result.CHANGED;
    }
}
