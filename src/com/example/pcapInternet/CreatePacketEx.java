package com.example.pcapInternet;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.*;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

import java.io.PrintWriter;
import java.util.*;

/**
 * @program: JnetPcapEx
 * @description:
 * @author: Mr.Wang
 * @create: 2018-03-06 19:36
 **/
public class CreatePacketEx {
    List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs
    StringBuilder errbuf = new StringBuilder(); // For any error msgs
    StringBuffer buffer = null;
    int snaplen = 4 * 1024; // 指定捕获的最大byte数
    int flags = Pcap.MODE_PROMISCUOUS; // 混杂模式
    int timeout = 10 * 1000; // 捕获数据包后等待的时间
    List<String> PacketInfo;
    String source = null;
    String destination = null;
    String macSource = null;
    String macDestion = null;
    Pcap pcap;
    Udp udp = new Udp();
    Icmp icmp = new Icmp();
    Ip4 ip = new Ip4();
    Ethernet eth = new Ethernet();
    Tcp tcp = new Tcp();
    Http http = new Http();
    Arp arp = new Arp();
    volatile int PacketNum = 1;
    // 创建一些loop中会使用和重用的对象
    List<String> NetList;
    static int NetCount = 1;//网路接口
    // 创建表格的输出
    List<Object> tablelist;
    public static volatile boolean flag = true;

    Map<Integer,String> InfoMap=new HashMap<Integer,String>();
    public static void main(String[] args) throws InterruptedException {
        PrintWriter p = new PrintWriter(System.out);
        CreatePacketEx example = new CreatePacketEx();
        CatchpacketThread t = example.new CatchpacketThread(p);
        t.start();
        Thread.sleep(10 * 1000);
        flag = false;
    }
    public String getProtocol(int type) {

        switch (type) {
            case 1:
                return "ICMP";
            case 2:
                return "IGMP";
            case 4:
                return "IP in IP";
            case 6:
                return "TCP";
            case 8:
                return "EGP";
            case 17:
                return "UDP";
            case 41:
                return "IPV6";
            case 89:
                return "OSPF";
            default:
                return "UNKOW";

        }

    }
    class CatchpacketThread extends Thread {
        // eth Header
        private long time;
        private int Length;
        private int captureLen;
        private String SoureMac;
        private String DestionMac;
        private int ethType;

        // IP header
        private int IpVersion;
        private int IpHeaderLength;
        private int ServiceType;
        private int TotalLenth;
        private int Identification;
        private int Flages;
        private int Ttl;
        private String Protocol;
        private int Checksum;
        private String IpSource;
        private String IpDestion;

        // tcp header
        private int tcpSrcPort;
        private int tcpDesPort;
        private long SequenceNum;
        private long TcpAck;
        private int TcpLen;
        private int Reserved;
        private int TcpFlages;
        private int TcpSize;
        private int TcpChecksum;
        private int TcpUrgent;

        // udpHeader
        private int UdpScrPort;
        private int UdpDesPort;
        private int UdpLen;
        private int UdpChecksum;

        // Icmp Header
        private int IcmpType;
        private int IcmpCode;
        private int IcmpChecksum;
        private int IcmpId;
        private int IcmpSize;
        private String httpType;
        private int ContentLen;
        // Arp Header
        private int ArpHardType;
        private int ArpProType;
        private int ArpPlen;
        public CatchpacketThread(PrintWriter p) {
            this.printWriter = p;
        }
        private PrintWriter printWriter;
        private FeaturesBean features;
        public void run() {
            int r = Pcap.findAllDevs(alldevs, errbuf);
            if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
                System.err.printf("Can't read list of devices, error is %s", errbuf
                        .toString());
                return;
            }
            System.out.println(NetCount);
            if (NetCount > alldevs.size()) {
                System.out.println("NetCount is out of alldevs's size");
            }
            PcapIf device = alldevs.get(NetCount); // 得到网络接口

            pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
            PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

                @Override
                public void nextPacket(PcapPacket packet, String user) {
                    buffer = new StringBuffer();
                    tablelist = new LinkedList<Object>();
                    features = new FeaturesBean();
//                    packet.scan(JRegistry.mapDLTToId(pcap.datalink()));
                    // 对数据包进行解析
                    /************************* Frame **************************************/
//                    time = packet.getCaptureHeader().timestampInMillis(); // 数据包捕获时间
//                    Length = packet.getCaptureHeader().wirelen(); // 数据包原本长度
//                    captureLen = packet.getCaptureHeader().caplen()
                    /****************************Ethernet************************/

                    if (packet.hasHeader(eth)) {
                        SoureMac = FormatUtils.asString(packet.getHeader(eth).source());
                        DestionMac = FormatUtils.asString(packet.getHeader(eth).destination());
                        ethType = packet.getHeader(eth).type();
                        Ethernet header = packet.getHeader(eth);

                        //表格显示
                        tablelist.add(SoureMac);
                        tablelist.add(DestionMac);

                    }

                    /*************************** IPV4只抓取IP数据包的UDP TCP ICMP*************************/
                    if (packet.hasHeader(ip)) {
                        IpVersion = ip.version(); // 得到版本号
                        IpHeaderLength = packet.getHeader(ip).length();// 得到ip头长度
                        ServiceType = ip.tos(); // 服务类型
                        TotalLenth = packet.getHeader(ip).size(); // 得到总长度
                        Identification = ip.id();
                        Flages = ip.flags();
                        Ttl = ip.ttl(); // 存活时间
                        Protocol = getProtocol(ip.type()); // ip数据报类型
                        Checksum = packet.getHeader(ip).checksum();
                        IpSource = FormatUtils.ip(ip.source());
                        IpDestion = FormatUtils.ip(ip.destination());

                        if(Protocol !="TCP"&&Protocol !="UDP"&&Protocol !="ICMP"){
                            //不知道协议的后面全为空
                            for(int i=0;i<7;i++) {
                                tablelist.add("----");
                            }
                        }else {
                            tablelist.add("IP");
                            tablelist.add(Protocol);
                            tablelist.add(IpSource);
                            tablelist.add(IpDestion);
                        }

                        /*********TCP*******************/
                        if (packet.hasHeader(tcp)) {

                            tcpSrcPort = tcp.source(); // tcp源端口
                            tcpDesPort = tcp.destination();// 目的端口
                            SequenceNum = tcp.seq();
                            TcpAck = tcp.ack();
                            TcpLen = packet.getHeader(tcp).getLength(); // header长度
                            Reserved = tcp.reserved(); // 是否接收到
                            TcpFlages = tcp.flags();
                            TcpSize = packet.getHeader(tcp).size(); // 数据包大小
                            TcpChecksum = tcp.checksum();
                            TcpUrgent = tcp.urgent();

                            tablelist.add(tcpSrcPort);
                            tablelist.add(tcpDesPort);
                            tablelist.add(SequenceNum);
                            tablelist.add(TcpAck);



                        }
                        /*****************UDP*********************/
                        if (packet.hasHeader(udp)) {
                            UdpScrPort = udp.source();
                            UdpDesPort = udp.destination();
                            UdpLen = udp.length();
                            UdpChecksum = udp.checksum();

                            tablelist.add(UdpScrPort);
                            tablelist.add(UdpDesPort);
                            tablelist.add("----");
                            tablelist.add("----");

                        }




                        /****************************ICMP*****************/
                        if (packet.hasHeader(icmp)) {
                            IcmpType = icmp.type();
                            IcmpCode = icmp.code();
                            IcmpChecksum = icmp.checksum();
                            IcmpId = icmp.getId();
                            IcmpSize = packet.getHeader(icmp).size();


                            //存入tableList 用于表格输出显示
                            tablelist.add("----");
                            tablelist.add("----");
                            tablelist.add("----");
                            tablelist.add("----");
                            tablelist.add(packet.getPacketWirelen());



                            //存入TreeList

                        }
                    }else if(packet.hasHeader(arp)) {
                        /**************************** ARP ************************/
                        tablelist.add("ARP");
                        tablelist.add("arp");
                        tablelist.add(IpSource);
                        tablelist.add(IpDestion);
                        for(int i=0;i<4;i++) {
                            tablelist.add("----");
                        }

                    }else{
                        tablelist.add("unknow");
                        for(int i=0;i<7;i++) {
                            tablelist.add("----");
                        }

					/*	ArpHardType = arp.hardwareType(); // 硬件类型
						ArpProType = arp.protocolType();
						ArpPlen = arp.plen();
						*/
                    }

                    tablelist.add(packet.size());

                    InfoMap.put(PacketNum, packet.toHexdump());
                    PacketNum++;
                    /**************************** HTTP*****************************/
                    if (packet.hasHeader(http)) {
                        httpType = http.contentType();
                        ContentLen = http.getLength();
                    }
                    printWriter.println(tablelist);
                    tablelist.clear();
                    printWriter.flush();
                }
            };
            pcap.loop(-1, jpacketHandler, "NakaiNetWork!");

        }

    }
}
