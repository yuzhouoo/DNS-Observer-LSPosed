package dev.yz.dnsobserver;

public final class BoxWatchStateTest {
    private static void check(boolean value){if(!value)throw new AssertionError();}
    public static void main(String[] args){
        BoxWatchState s=new BoxWatchState();
        check(s.observe("running","pid1:rules1")==BoxWatchState.Result.WAIT);
        check(s.observe("running","pid1:rules1")==BoxWatchState.Result.BASELINE);
        check(s.observe("running","pid1:rules1")==BoxWatchState.Result.SAME);
        check(s.observe("stopped","empty")==BoxWatchState.Result.WAIT);
        // Stop/start in one debounce window produces one final restart event.
        check(s.observe("running","pid2:rules1")==BoxWatchState.Result.WAIT);
        check(s.observe("running","pid2:rules1")==BoxWatchState.Result.CHANGED);
        check(s.observe("running","pid2:rules1")==BoxWatchState.Result.SAME);
        check(s.observe("running","pid2:rules2")==BoxWatchState.Result.WAIT);
        check(s.observe("unknown","")==BoxWatchState.Result.UNKNOWN);
        check(s.observe("running","pid2:rules2")==BoxWatchState.Result.WAIT);
        check(s.observe("running","pid2:rules2")==BoxWatchState.Result.CHANGED);
        check(s.observe("stopping","residue")==BoxWatchState.Result.WAIT);
        check(s.observe("stopped","empty")==BoxWatchState.Result.WAIT);
        check(s.observe("stopped","empty")==BoxWatchState.Result.CHANGED);
        s.reset();
        check(s.observe("running","pid2:rules2")==BoxWatchState.Result.WAIT);
        check(s.observe("running","pid2:rules2")==BoxWatchState.Result.BASELINE);
        System.out.println("Box lifecycle debounce: PASS");
    }
}
