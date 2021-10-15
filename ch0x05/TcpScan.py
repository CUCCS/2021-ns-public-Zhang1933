# -*- coding: utf-8 -*-
import sys
from scapy.all import *
def help():
    print("USAGE")
    print("\t"+sys.argv[0]+" [-c] [-s] [-u] [-x] [-f] [-n] <ip:port>")
    print("OPTIONS") 
    print("\t-c:TCP connect scan ")
    print("\t-s:TCP stealth scan")
    print("\t-x:TCP Xmas scan")
    print("\t-f:TCP fin scan")
    print("\t-n:TCP null scan")
    print("\t-u:UDP scan")
    print("\t<ip:port>:destination ip address and ports")
    print("\n\nEXAMPLE:\n\t"+sys.argv[0]+" -c 192.168.56.110:8080")

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

sport = random.randint(1024,65535)

def TCPConnect(ip,port):
    """
        目标端口是开放的：返回1.
        目标端口关闭，返回0
        目标端口没有任何响应，返回-1
    """
    print("TCP connect scan start...")
    pkt=IP(dst=ip)/TCP(sport=sport,dport=port,flags="S")
    ans=sr1(pkt,retry=2,timeout=0.2)
    if not ans:
        return -1
    F=ans['TCP'].flags
    if F & ACK and F & SYN :
        pkt=IP(dst=ip)/TCP(sport=sport,dport=port,seq=ans.ack,ack=ans.seq+1,flags="AR")
        send(pkt)
        return 1
    elif F & RST and F & ACK:
        return 0
    else:
        return -1

def TcpStealthy(ip,port):
    """
        目标端口是开放的：返回1.
        目标端口关闭，返回0
        目标端口没有任何响应，返回-1
    """
    print("####TCP stealth scan start...###")
    pkt=IP(dst=ip)/TCP(sport=sport,dport=port,flags="S") # 不成功尝试2次
    ans=sr1(pkt,retry=2,timeout=0.2)    
    if not ans :
        return -1
    F=ans['TCP'].flags
    if F & ACK and F & SYN:
        send(IP(dst=ip)/TCP(sport=sport,dport=port,seq=ans.ack,ack=ans.seq+1,flags="R"))
        return 1
    elif F & ACK and F & RST:
        return 0

def TCPXmas(ip,port):
    """
        目标端口是关闭：返回1.
        目标端口开放或者过滤状态，返回0
        其他情况返回-2
    """
    print("TCP Xmas scan start...")
    pkt=IP(dst=ip)/TCP(sport=sport,dport=port,flags="FPU")
    ans=sr1(pkt,retry=2,timeout=0.2)
    if not ans :
        return 0
    F=ans['TCP'].flags
    if F & RST :
        return 1
    return -2

def TCPFin(ip,port):
    """
       端口关闭状态，返回1
       端口开放或者过滤状态，返回0
       其他情况，返回-2
    """
    print("TCP fin scan start...")
    pkt=IP(dst=ip)/TCP(sport=sport,dport=port,flags="F")
    ans=sr1(pkt,retry=2,timeout=0.2)
    if not ans:
        return 0
    F=ans['TCP'].flags
    if F & RST:
        return 1
    return -2 

def TCPNull(ip,port):
    """
       端口关闭状态，返回1
       端口开放或者过滤状态，返回0
       其他情况，返回-2
    """
    print("TCP null scan start...")
    pkt=IP(dst=ip)/TCP(sport=sport,dport=port,flags="")
    ans=sr1(pkt,retry=2,timeout=0.2)
    if not ans:
        return 0
    F=ans['TCP'].flags
    if F & RST:
        return 1
    return -2 

def UDPScan(ip,port):
    """
        端口关闭，返回1
        端口开放状态:返回0
        端口过滤状态：返回-1
        端口过滤或者开放状态，返回-2
    """
    print("UDP scan start ...")
    pkt=IP(dst=ip)/UDP(sport=sport,dport=port)
    ans=sr1(pkt,retry=2,timeout=0.2)
    if not ans:
        return -2
    if ans.haslayer(UDP):
        return 0
    if ans.haslayer(ICMP):
        if int(ans.getlayer(ICMP).type)==3 and  int(ans.getlayer(ICMP).code)==3:
            return 1
        if int(ans.getlayer(ICMP).type)==3 and  int(ans.getlayer(ICMP).code) in [1,2,9,10,13]:
            return  -1
    return -3

if __name__=="__main__":
    opts=[opt for opt in sys.argv[1:] if opt.startswith("-")]
    args=[arg for arg in sys.argv[1:] if not arg.startswith("-")]
    if len(args)>1 or len(args) ==0:
        help()
        exit(1)
    dividPos=args[0].find(":")
    if(dividPos==-1):
        print("没有指定端口号")
        sys.exit(1)
    ip=args[0][:dividPos]
    port=int(args[0][dividPos+1:])
    if "-c" in opts :
        res=TCPConnect(ip,port)
        if res == 1:
            print("目标端口为开放状态")
        elif res== 0:
            print("目标端口为关闭状态")
        else :
            print("目标端口为过滤状态")
    elif "-s" in opts:
        res=TcpStealthy(ip,port)
        if res == 1:
            print("目标端口为开放状态")
        elif res== 0:
            print("目标端口为关闭状态")
        else :
            print("目标端口为过滤状态")

    elif  "-x" in opts:
        res=TCPXmas(ip,port) 
        if res == 1:
            print("目标端口为关闭状态")
        elif res==0:
            print("目标端口为开放或者过滤状态")
        else:
            print("xmax异常")
    elif "-f" in opts:
        res=TCPFin(ip,port)
        if res==1:
            print("目标端口为关闭状态")
        elif res==0:
            print("目标端口为开放或者过滤状态")
        else:
            print("未处理的其他情况")
    elif "-n" in opts:
        res=TCPNull(ip,port)
        if res==1:
            print("目标端口为关闭状态")
        elif res==0:
            print("目标端口为开放或者过滤状态")
        else:
            print("未考虑的其他情况")
    elif "-u" in opts:
        res=UDPScan(ip,port)
        if res==1:
            print("端口关闭")
        elif res==0:
            print("端口开放")
        elif res==-1:
            print("端口为过滤状态")
        elif res==-2:
            print("端口过滤或者开放")
        else:
            print("未考虑的情况")
    else:
        help()
        sys.exit(1)

