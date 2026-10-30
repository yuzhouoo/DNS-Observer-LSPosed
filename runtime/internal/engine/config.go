package engine

import (
 "encoding/json"
 "errors"
 "fmt"
 "net"
 "os"
 "path/filepath"
 "strings"
 "time"
)
const Home = "/data/adb/yutong"
const Egress = 0x20000000
const Capture = "0x40000000/0x40000000"
const Table = "19770"
const Prefix = "YTDNS"
const DNSPort = 15353
const ProxyPort = 9898

type Upstream struct { Host string `json:"host"`; Port int `json:"port"` }
type Config struct {
 Revision string `json:"revision"`
 Mode string `json:"mode"`
 IPv4 bool `json:"ipv4"`
 IPv6 bool `json:"ipv6"`
 Boot bool `json:"boot"`
 Repair bool `json:"repair"`
 Block853 bool `json:"block853"`
 LANBypass bool `json:"lan_bypass"`
 DNSLog bool `json:"dns_log"`
 Bootstrap string `json:"bootstrap"`
 Upstreams []Upstream `json:"upstreams"`
 Core string `json:"core"`
 Profile string `json:"profile"`
 SIMMatch bool `json:"sim_match"`
 SIM1 string `json:"sim1"`
 SIM2 string `json:"sim2"`
 BypassUIDs []int `json:"bypass_uids"`
}
func DefaultConfig() Config { return Config{Mode:"off",IPv4:true,IPv6:true,Repair:true,LANBypass:true,DNSLog:true,Core:Home+"/mihomo/mihomo",Profile:Home+"/mihomo/config.yaml",SIM1:"DIRECT",SIM2:"代理"} }
func(c Config) Validate() error {
 if c.Mode!="off"&&c.Mode!="dns"&&c.Mode!="proxy" {return errors.New("mode must be off/dns/proxy")}
 if c.Mode=="off" {return nil}
 if !c.IPv4&&!c.IPv6 {return errors.New("至少选择 IPv4 或 IPv6")}
 if len(c.Upstreams)<1||len(c.Upstreams)>3 {return errors.New("需要 1 至 3 组自建 DNS")}
 if net.ParseIP(c.Bootstrap)==nil {return errors.New("Bootstrap 必须为纯 IP")}
 for _,u:=range c.Upstreams {if u.Port<1||u.Port>65535||u.Host==""||len(u.Host)>253||strings.ContainsAny(u.Host,"/\x00\r\n :")&&net.ParseIP(u.Host)==nil{return fmt.Errorf("DNS 地址或端口不合法: %q",u.Host)}}
 if len(c.BypassUIDs)>200 {return errors.New("绕过 UID 数量超过200")};for _,u:=range c.BypassUIDs {if u<0{return errors.New("UID 必须非负")}}
 if c.Mode=="proxy" {
  for _,p:=range []string{c.Core,c.Profile} {if !filepath.IsAbs(p)||!strings.HasPrefix(filepath.Clean(p),"/data/")||strings.ContainsAny(p,"\x00\n\r") {return errors.New("核心与配置路径必须为 /data 下的绝对路径")}}
  if c.SIMMatch && (c.SIM1==""||c.SIM2==""||strings.ContainsAny(c.SIM1+c.SIM2,"\r\n,")){return errors.New("SIM MATCH 目标不合法")}
 }
 return nil
}
func LoadConfig(home string)(Config,error){c:=DefaultConfig();b,e:=os.ReadFile(home+"/config.json");if os.IsNotExist(e){return c,nil};if e!=nil{return c,e};e=json.Unmarshal(b,&c);if e==nil{e=c.Validate()};return c,e}
func AtomicJSON(path string,v any)error{b,e:=json.MarshalIndent(v,"","  ");if e!=nil{return e};return Atomic(path,b,0600)}
func Atomic(path string,b []byte,mode os.FileMode)error{
 if e:=os.MkdirAll(filepath.Dir(path),0700);e!=nil{return e};f,e:=os.CreateTemp(filepath.Dir(path),".write-");if e!=nil{return e};name:=f.Name();defer os.Remove(name)
 if e=f.Chmod(mode);e==nil{_,e=f.Write(b)};if e==nil{e=f.Sync()};ce:=f.Close();if e==nil{e=ce};if e==nil{e=os.Rename(name,path)};if e==nil{if d,x:=os.Open(filepath.Dir(path));x==nil{e=d.Sync();d.Close()}};return e
}
func Deadline()time.Time{return time.Now().Add(3*time.Second)}
