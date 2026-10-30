package engine

import("context";"encoding/binary";"errors";"fmt";"io";"net";"strconv";"strings";"sync";"syscall";"time";"encoding/json";"sync/atomic")
type endpoint struct{addr string;group int}
type DNS struct{viaCore atomic.Bool;mu sync.RWMutex;ends []endpoint;cfg Config;log *Logger;closers []io.Closer;ctx context.Context;cancel context.CancelFunc;slots chan struct{};wg sync.WaitGroup}
func socketControl(family string,transparent,bypass bool)func(string,string,syscall.RawConn)error{return func(network,address string,raw syscall.RawConn)error{var inner error;e:=raw.Control(func(fd uintptr){if bypass{inner=syscall.SetsockoptInt(int(fd),syscall.SOL_SOCKET,syscall.SO_MARK,Egress);if inner!=nil{return}};if transparent{level,opt:=syscall.SOL_IP,19;if family=="6"{level,opt=syscall.SOL_IPV6,75};inner=syscall.SetsockoptInt(int(fd),level,opt);if inner!=nil{return};if strings.HasPrefix(network,"udp"){opt=20;if family=="6"{opt=74};inner=syscall.SetsockoptInt(int(fd),level,opt);if inner!=nil{return}};inner=syscall.SetsockoptInt(int(fd),syscall.SOL_SOCKET,syscall.SO_REUSEADDR,1)}});if e!=nil{return e};return inner}}
func dial(ctx context.Context,network,addr string,bypass bool)(net.Conn,error){d:=net.Dialer{Timeout:2500*time.Millisecond,Control:socketControl("",false,bypass)};return d.DialContext(ctx,network,addr)}
func(d *DNS)Resolve(ctx context.Context)error{
 var ends []endpoint
 for i,u:=range d.cfg.Upstreams {
  var ips []net.IP
  if ip:=net.ParseIP(u.Host);ip!=nil{ips=[]net.IP{ip}}else{
   resolver:=net.Resolver{PreferGo:true,StrictErrors:true,Dial:func(ctx context.Context,network,unused string)(net.Conn,error){return dial(ctx,network,net.JoinHostPort(d.cfg.Bootstrap,"53"),true)}}
   var e error;ips,e=resolver.LookupIP(ctx,"ip",u.Host);if e!=nil{d.log.Event("BOOTSTRAP_FAILED","group=%d host=%s error=%v",i,u.Host,e);continue}
  }
  for n,ip:=range ips{if n>=6{break};if ip.IsLoopback()||ip.IsUnspecified()||ip.IsMulticast(){continue};ends=append(ends,endpoint{net.JoinHostPort(ip.String(),strconv.Itoa(u.Port)),i})}
 }
 if len(ends)==0{return errors.New("自建 DNS / Bootstrap 未返回可用 IP；未使用系统解析或公共备用")}
 // Verify UDP/TCP separately, keep only usable transports at query time (TCP can rescue UDP).
 good:=[]endpoint{};q:=queryPacket("example.com")
 for _,ep:=range ends{_,e:=exchange(ctx,"udp",ep.addr,q,true);if e!=nil{_,e=exchange(ctx,"tcp",ep.addr,q,true)};if e==nil{good=append(good,ep);d.log.Event("UPSTREAM_READY","group=%d endpoint=%s",ep.group,ep.addr)}else{d.log.Event("UPSTREAM_FAILED","group=%d endpoint=%s error=%v",ep.group,ep.addr,e)}}
 if len(good)==0{return errors.New("自建 DNS 上游全部不可达（UDP/TCP 验证失败）")}
 d.mu.Lock();d.ends=good;d.mu.Unlock();return nil
}
func queryPacket(host string)[]byte{b:=[]byte{0x59,0x54,1,0,0,1,0,0,0,0,0,0};for _,p:=range strings.Split(host,"."){b=append(b,byte(len(p)));b=append(b,[]byte(p)...)};return append(b,0,0,1,0,1)}
func validReply(q,a []byte)bool{qn,qt:=question(q);an,at:=question(a);if qn=="[invalid question]"||!strings.EqualFold(qn,an)||qt!=at{return false};return len(q)>=12&&len(a)>=12&&q[0]==a[0]&&q[1]==a[1]&&a[2]&128!=0&&a[5]>0&&a[3]&15!=2&&a[3]&15!=5}
func exchange(ctx context.Context,network,addr string,q []byte,bypass bool)([]byte,error){
 c,e:=dial(ctx,network,addr,bypass);if e!=nil{return nil,e};defer c.Close();stop:=context.AfterFunc(ctx,func(){c.Close()});defer stop();c.SetDeadline(Deadline());var a []byte
 if network=="tcp" {frame:=append([]byte{byte(len(q)>>8),byte(len(q))},q...);if _,e=c.Write(frame);e!=nil{return nil,e};h:=make([]byte,2);if _,e=io.ReadFull(c,h);e!=nil{return nil,e};n:=int(binary.BigEndian.Uint16(h));if n<12{return nil,errors.New("short TCP DNS")};a=make([]byte,n);_,e=io.ReadFull(c,a)}else{if _,e=c.Write(q);e!=nil{return nil,e};a=make([]byte,65535);var n int;n,e=c.Read(a);a=a[:n]}
 if e!=nil{return nil,e};if !validReply(q,a){return nil,errors.New("DNS reply ID/rcode/question invalid")};if network=="udp"&&a[2]&2!=0{return nil,errors.New("truncated UDP DNS")};return a,nil
}
func servfail(q []byte)[]byte{a:=append([]byte(nil),q...);if len(a)<12{return nil};a[2]=(a[2]|128)&^2;a[3]=(a[3]&240)|2;for i:=6;i<12;i++{a[i]=0};return a}
func(d *DNS)forward(q []byte,proto,client string,upstreamOnly bool)[]byte{
 if len(q)<12||q[2]&128!=0{return nil};start:=time.Now();d.mu.RLock();ends:=append([]endpoint(nil),d.ends...);d.mu.RUnlock();if d.viaCore.Load()&&!upstreamOnly{ends=[]endpoint{{addr:"127.0.0.1:1053",group:-1}}};var answer []byte;var last error;used:="";transport:=proto
 for _,ep:=range ends{ctx,cancel:=context.WithTimeout(d.ctx,6*time.Second);answer,last=exchange(ctx,proto,ep.addr,q,true);if last!=nil&&proto=="udp"{answer,last=exchange(ctx,"tcp",ep.addr,q,true);transport="tcp"};cancel();used=ep.addr;if last==nil{break}}
 if last!=nil||answer==nil{answer=servfail(q);d.log.Event("DNS_UPSTREAM_FAILURE","endpoint=%s error=%v",used,last)}
 if d.cfg.DNSLog {name,typ:=question(q);d.log.Write("dns",map[string]any{"client":client,"uid":-1,"transport":proto,"upstream_transport":transport,"upstream":used,"name":name,"qtype":typ,"rcode":int(answer[3]&15),"elapsed_ms":time.Since(start).Milliseconds(),"ips":answerIPs(answer),"stage":map[bool]string{true:"mihomo_upstream",false:"client_query"}[upstreamOnly],"evidence":"root DNS relay; upstream response, not proof of client receipt"})}
 return answer
}
func question(q []byte)(string,int){if len(q)<12{return "",0};i:=12;parts:=[]string{};for len(parts)<128&&i<len(q){n:=int(q[i]);i++;if n==0{if i+4>len(q){break};return strings.Join(parts,"."),int(binary.BigEndian.Uint16(q[i:i+2]))};if n>63||i+n>len(q){break};parts=append(parts,string(q[i:i+n]));i+=n};return "[invalid question]",0}
func originalDst(oob []byte)(*net.UDPAddr,error){msgs,e:=syscall.ParseSocketControlMessage(oob);if e!=nil{return nil,e};for _,m:=range msgs{if m.Header.Level==syscall.SOL_IP&&m.Header.Type==20&&len(m.Data)>=8{return &net.UDPAddr{IP:net.IPv4(m.Data[4],m.Data[5],m.Data[6],m.Data[7]),Port:int(binary.BigEndian.Uint16(m.Data[2:4]))},nil};if m.Header.Level==syscall.SOL_IPV6&&m.Header.Type==74&&len(m.Data)>=28{return &net.UDPAddr{IP:net.IP(append([]byte(nil),m.Data[8:24]...)),Port:int(binary.BigEndian.Uint16(m.Data[2:4]))},nil}};return nil,errors.New("original-destination cmsg missing")}
func(d *DNS)udp(c *net.UDPConn,family string,upstreamOnly bool){defer d.wg.Done();for{b,o:=make([]byte,65535),make([]byte,256);n,on,_,client,e:=c.ReadMsgUDP(b,o);if e!=nil{return};q:=b[:n];if !localSource(client.IP){continue};target,e:=originalDst(o[:on]);if e!=nil{d.log.Event("DNS_UDP_ORIGDST_FAILED","%v",e);continue};select{case d.slots<-struct{}{}:default:d.log.Event("DNS_QUEUE_FULL","udp");continue};d.wg.Add(1);go func(){defer d.wg.Done();defer func(){<-d.slots}();a:=d.forward(q,"udp",client.String(),upstreamOnly);if a==nil{return};if target.Port==DNSPort||target.Port==15354{_,e=c.WriteToUDP(a,client)}else if target.Port==53 {lc:=net.ListenConfig{Control:socketControl(family,true,true)};var pc net.PacketConn;pc,e=lc.ListenPacket(context.Background(),"udp"+family,target.String());if e==nil{pc.SetWriteDeadline(Deadline());_,e=pc.WriteTo(a,client);pc.Close()}}else{e=errors.New("unexpected original destination port")};if e!=nil{d.log.Event("DNS_CLIENT_REPLY_FAILED","%v",e)}}()}}
func(d *DNS)tcp(l net.Listener,upstreamOnly bool){defer d.wg.Done();for{c,e:=l.Accept();if e!=nil{return};host,_,_:=net.SplitHostPort(c.RemoteAddr().String());if !localSource(net.ParseIP(host)){c.Close();continue};select{case d.slots<-struct{}{}:default:c.Close();continue};d.wg.Add(1);go func(){defer d.wg.Done();defer c.Close();cancelConn:=context.AfterFunc(d.ctx,func(){c.Close()});defer cancelConn();defer func(){<-d.slots}();for{c.SetDeadline(time.Now().Add(12*time.Second));h:=make([]byte,2);if _,e:=io.ReadFull(c,h);e!=nil{return};n:=int(binary.BigEndian.Uint16(h));if n<12{return};q:=make([]byte,n);if _,e:=io.ReadFull(c,q);e!=nil{return};a:=d.forward(q,"tcp",c.RemoteAddr().String(),upstreamOnly);if len(a)<12{return};if _,e:=c.Write(append([]byte{byte(len(a)>>8),byte(len(a))},a...));e!=nil{return}}}()}}
func NewDNS(cfg Config,log *Logger)*DNS{ctx,cancel:=context.WithCancel(context.Background());return &DNS{cfg:cfg,log:log,ctx:ctx,cancel:cancel,slots:make(chan struct{},128)}}
func(d *DNS)Start()error{
 ctx,cancel:=context.WithTimeout(d.ctx,30*time.Second);defer cancel();if e:=d.Resolve(ctx);e!=nil{return e}
 // IPv4 local endpoint is always available for Mihomo; capture family choices stay independent.
 families:=[]string{"4"};if d.cfg.IPv6{families=append(families,"6")}
 for _,f:=range families{addr:="0.0.0.0:15353";if f=="6"{addr="[::]:15353"};lc:=net.ListenConfig{Control:socketControl(f,true,false)};p,e:=lc.ListenPacket(context.Background(),"udp"+f,addr);if e!=nil{d.Close();return fmt.Errorf("UDP%s listen: %w",f,e)};d.closers=append(d.closers,p);d.wg.Add(1);go d.udp(p.(*net.UDPConn),f,false);l,e:=lc.Listen(context.Background(),"tcp"+f,addr);if e!=nil{d.Close();return fmt.Errorf("TCP%s listen: %w",f,e)};d.closers=append(d.closers,l);d.wg.Add(1);go d.tcp(l,false)}
 if d.cfg.Mode=="proxy"{
  lc:=net.ListenConfig{Control:socketControl("4",true,false)}
  p,e:=lc.ListenPacket(context.Background(),"udp4","127.0.0.1:15354");if e!=nil{d.Close();return e};d.closers=append(d.closers,p);d.wg.Add(1);go d.udp(p.(*net.UDPConn),"4",true)
  l,e:=lc.Listen(context.Background(),"tcp4","127.0.0.1:15354");if e!=nil{d.Close();return e};d.closers=append(d.closers,l);d.wg.Add(1);go d.tcp(l,true)
 }
 return nil
}
func(d *DNS)Close(){d.cancel();for _,c:=range d.closers{c.Close()};d.closers=nil;d.wg.Wait()}
func ProbeDNS(addr string,bypass bool)error{q:=queryPacket("example.com");for _,p:=range []string{"udp","tcp"}{if _,e:=exchange(context.Background(),p,addr,q,bypass);e!=nil{return fmt.Errorf("%s %s: %w",p,addr,e)}};return nil}
// JSONLines is shared by the CLI and APK; no payload bodies or upstream credentials are logged.
func JSONLines(path string)[]json.RawMessage{var out []json.RawMessage;for _,s:=range strings.Split(Tail(path,50000),"\n"){if json.Valid([]byte(s)){out=append(out,json.RawMessage(s))}};return out}
func localSource(ip net.IP)bool{if ip==nil{return false};if ip.IsLoopback(){return true};a,_:=net.InterfaceAddrs();for _,v:=range a{host,_,e:=net.ParseCIDR(v.String());if e==nil&&host.Equal(ip){return true}};return false}

func answerIPs(b []byte)[]string{
 out:=[]string{};if len(b)<12{return out};off:=12
 skip:=func()bool{for k:=0;k<128&&off<len(b);k++{n:=int(b[off]);off++;if n==0{return true};if n&192==192{if off>=len(b){return false};off++;return true};if n>63||off+n>len(b){return false};off+=n};return false}
 qd:=int(binary.BigEndian.Uint16(b[4:6]));an:=int(binary.BigEndian.Uint16(b[6:8]));for i:=0;i<qd;i++{if !skip()||off+4>len(b){return out};off+=4};for i:=0;i<an&&len(out)<16;i++{if !skip()||off+10>len(b){return out};typ:=binary.BigEndian.Uint16(b[off:off+2]);n:=int(binary.BigEndian.Uint16(b[off+8:off+10]));off+=10;if off+n>len(b){return out};if typ==1&&n==4||typ==28&&n==16{out=append(out,net.IP(b[off:off+n]).String())};off+=n};return out
}
