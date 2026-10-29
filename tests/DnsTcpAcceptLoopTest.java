package dev.yz.dnsobserver;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Fault injection drives the production accept loop, including resource ownership and retry bounds. */
public final class DnsTcpAcceptLoopTest {
    private static void check(boolean value,String reason){if(!value)throw new AssertionError(reason);}
    private static final class FakeIo implements DnsTcpAcceptLoop.Io<String,String> {
        final ArrayDeque<String> script=new ArrayDeque<>();
        final List<String> events=new ArrayList<>(),dispatched=new ArrayList<>(),closedClients=new ArrayList<>();
        final Set<String> closedListeners=new HashSet<>();
        boolean alive=true,cancelOnOpen;
        int opens,fatals,openFailures;
        long time;
        FakeIo(String...steps){script.addAll(Arrays.asList(steps));}
        public boolean running(){return alive;}
        public String accept(String listener)throws Exception {
            check(!closedListeners.contains(listener),"accept on closed listener");
            String next=script.isEmpty()?"stop":script.removeFirst();
            if(next.equals("stop")){alive=false;return null;}
            if(next.equals("stopWithClient")){alive=false;return "cancelledClient";}
            if(next.equals("EINVAL")||next.equals("EAGAIN")||next.equals("ECONNABORTED"))throw new Exception(next);
            return next;
        }
        public void configure(String client)throws Exception {if(client.equals("badSetup"))throw new Exception("setsockopt EINVAL");}
        public void dispatch(String client)throws Exception {
            if(client.equals("queueFull"))throw new java.util.concurrent.RejectedExecutionException("queue full");
            dispatched.add(client);closeClient(client); // Worker owns accepted client from here onward.
        }
        public void closeClient(String client){check(!closedClients.contains(client),"client closed twice: "+client);closedClients.add(client);}
        public void closeListener(String listener){check(closedListeners.add(listener),"listener closed twice: "+listener);}
        public String openListener()throws Exception {
            opens++;if(opens<=openFailures)throw new Exception("bind denied");
            if(cancelOnOpen)alive=false;
            return "L"+(opens+1);
        }
        public DnsTcpAcceptLoop.Failure classify(Exception error){
            return error.getMessage().equals("EAGAIN")||error.getMessage().equals("ECONNABORTED")?
                DnsTcpAcceptLoop.Failure.RETRY:DnsTcpAcceptLoop.Failure.RECOVER;
        }
        public void event(String stage,Exception error){events.add(stage);}
        public void fatal(){fatals++;alive=false;}
        public void pause(long millis){time+=millis;}
        public long now(){return time;}
        void run(){new DnsTcpAcceptLoop<String,String>("L1",this).run();}
    }
    public static void main(String[] args){
        FakeIo transientAccept=new FakeIo("EAGAIN","ECONNABORTED","good","stop");transientAccept.run();
        check(transientAccept.opens==0&&transientAccept.fatals==0,"transient accept failure must preserve listener");
        check(transientAccept.dispatched.equals(Arrays.asList("good")),"next client must be served");

        FakeIo setup=new FakeIo("badSetup","good","stop");setup.run();
        check(setup.events.contains("TCP_CLIENT_SETUP_ERROR")&&setup.opens==0&&setup.fatals==0,"client setup failure is isolated");
        check(setup.closedClients.equals(Arrays.asList("badSetup","good")),"both failed and successful clients are closed exactly once");

        FakeIo queue=new FakeIo("queueFull","good","stop");queue.run();
        check(queue.events.contains("TCP_QUEUE_ERROR")&&queue.fatals==0,"queue rejection must not stop UDP/TCP daemon");
        check(queue.closedClients.contains("queueFull"),"rejected client leaked");

        FakeIo invalid=new FakeIo("EINVAL","good","stop");invalid.run();
        check(invalid.opens==1&&invalid.fatals==0,"EINVAL must recover the listener rather than terminate immediately");
        check(invalid.closedListeners.equals(new HashSet<>(Arrays.asList("L1","L2"))),"listener replacement/stop ownership");
        check(invalid.events.contains("TCP_LISTENER_RECOVERED")&&invalid.dispatched.contains("good"),"connection after recovery must be served");

        FakeIo repeated=new FakeIo("EINVAL","EINVAL","EINVAL","EINVAL");repeated.run();
        check(repeated.opens==3&&repeated.fatals==1,"persistent invalid listener must fail closed within retry budget");
        check(repeated.closedListeners.size()==4,"fatal path leaked a listener");

        FakeIo reopen=new FakeIo("EINVAL","good","stop");reopen.openFailures=2;reopen.run();
        check(reopen.opens==3&&reopen.fatals==0&&reopen.dispatched.contains("good"),"bounded reopen failures can recover");

        FakeIo denied=new FakeIo("EINVAL");denied.openFailures=10;denied.run();
        check(denied.opens==3&&denied.fatals==1,"permanent bind failure may not loop indefinitely");

        FakeIo cancelled=new FakeIo("EINVAL");cancelled.cancelOnOpen=true;cancelled.run();
        check(cancelled.closedListeners.size()==2&&!cancelled.events.contains("TCP_LISTENER_RECOVERED"),"cancel during reopen must close replacement and never announce recovery");

        FakeIo acceptedAtStop=new FakeIo("stopWithClient");acceptedAtStop.run();
        check(acceptedAtStop.dispatched.isEmpty()&&acceptedAtStop.closedClients.contains("cancelledClient"),"stop must release an unsubmitted client");
        FakeIo preclosed=new FakeIo("good");
        DnsTcpAcceptLoop<String,String> closedLoop=new DnsTcpAcceptLoop<>("L1",preclosed);
        closedLoop.close();closedLoop.run();
        check(preclosed.dispatched.isEmpty()&&preclosed.closedListeners.size()==1,"closed loop may not accept or reopen");
        System.out.println("PASS: production TCP accept loop isolates client/queue failures, recovers EINVAL, bounds permanent faults, and closes resources on every path");
    }
}
