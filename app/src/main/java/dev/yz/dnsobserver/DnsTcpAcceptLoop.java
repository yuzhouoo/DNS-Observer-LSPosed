package dev.yz.dnsobserver;

import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicBoolean;

/** Single owner for a listener and accepted clients; client failures never kill the listener. */
final class DnsTcpAcceptLoop<L,C> implements Runnable,AutoCloseable {
    enum Failure { RETRY, RECOVER }
    interface Io<L,C> {
        boolean running();
        C accept(L listener)throws Exception;
        void configure(C client)throws Exception;
        void dispatch(C client)throws Exception;
        void closeClient(C client);
        void closeListener(L listener);
        L openListener()throws Exception;
        Failure classify(Exception failure);
        void event(String stage,Exception failure);
        void fatal();
        void pause(long millis)throws InterruptedException;
        long now();
    }
    private final Io<L,C> io;
    private final AtomicReference<L> listener;
    private final AtomicBoolean closed=new AtomicBoolean();
    private int recoveries;
    private long windowStart;
    DnsTcpAcceptLoop(L initial,Io<L,C> io){this.listener=new AtomicReference<>(initial);this.io=io;windowStart=io.now();}
    private boolean alive(){return !closed.get()&&io.running();}
    private void releaseListener(){L fd=listener.getAndSet(null);if(fd!=null)io.closeListener(fd);}
    @Override public void close(){closed.set(true);releaseListener();}
    private boolean recover(Exception cause)throws InterruptedException {
        io.event("TCP_LISTENER_RECOVERING",cause);
        releaseListener();
        while(alive()){
            long now=io.now();
            if(now-windowStart>=60000){windowStart=now;recoveries=0;}
            if(recoveries>=3){io.event("TCP_LISTENER_FATAL",cause);io.fatal();return false;}
            recoveries++;
            io.pause(100L*recoveries);
            if(!alive())return false;
            L replacement;
            try{replacement=io.openListener();}
            catch(Exception error){cause=error;io.event("TCP_LISTENER_REOPEN_ERROR",error);continue;}
            if(!alive()){io.closeListener(replacement);return false;}
            listener.set(replacement);
            if(!alive()){releaseListener();return false;}
            io.event("TCP_LISTENER_RECOVERED",null);
            return true;
        }
        return false;
    }
    @Override public void run(){
        try{
            while(alive()){
                L server=listener.get();if(server==null)break;
                C client;
                try{client=io.accept(server);}
                catch(Exception error){
                    if(!alive())break;
                    if(io.classify(error)==Failure.RETRY){io.pause(30);continue;}
                    if(!recover(error))break;
                    continue;
                }
                if(client==null)continue;
                boolean handedOff=false;
                String stage="TCP_CLIENT_SETUP_ERROR";
                try{
                    io.configure(client);
                    if(!alive())continue;
                    stage="TCP_QUEUE_ERROR";
                    io.dispatch(client);handedOff=true;
                }catch(Exception error){io.event(stage,error);}
                finally{if(!handedOff)io.closeClient(client);}
            }
        }catch(InterruptedException interrupted){Thread.currentThread().interrupt();if(alive()){io.event("TCP_LISTENER_FATAL",interrupted);io.fatal();}}
        finally{close();}
    }
}
