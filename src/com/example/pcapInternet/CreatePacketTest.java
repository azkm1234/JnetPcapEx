package com.example.pcapInternet;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

import java.io.PrintWriter;
import java.util.*;

public class CreatePacketTest {
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
    Ip6 ip6 = new Ip6();
    Ethernet eth = new Ethernet();
    Tcp tcp = new Tcp();
    Http http = new Http();
    Arp arp = new Arp();

    // 创建一些loop中会使用和重用的对象
    List<String> NetList;
    static int NetCount = 0;//网路接口
    // 创建表格的输出
    public static volatile boolean flag = true;

    Map<Integer,String> InfoMap=new HashMap<Integer,String>();
    public static void main(String[] args) throws InterruptedException {
        PrintWriter p = new PrintWriter(System.out);
        CreatePacketTest example = new CreatePacketTest();
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
                    features = new FeaturesBean();
                    /************************* Frame **************************************/
//                    time = packet.getCaptureHeader().timestampInMillis(); // 数据包捕获时间
//                    Length = packet.getCaptureHeader().wirelen(); // 数据包原本长度
//                    captureLen = packet.getCaptureHeader().caplen()


                    if (packet.hasHeader(ip)) {
                        features.setTime(packet.getCaptureHeader().timestampInMillis());; // 数据包捕获时间
                        features.setLength(packet.getCaptureHeader().wirelen()); //数据包的原本长度
                        /************************* Ip包中的字段 **************************************/
                        features.setCaptureLen(packet.getCaptureHeader().caplen());
                        features.setIpVersion(ip.version()); // 得到版本号
                        features.setIpHeaderLength( packet.getHeader(ip).length());// 得到ip头长度
                        features.setServiceType(ip.tos()); // 服务类型
                        features.setTotalLenth(packet.getHeader(ip).size());// ip包得到总长度
                        features.setIdentification(ip.id()); // 标志 ip包的
                        features.setTtl(ip.ttl()); // 存活时间
                        String Protocol = getProtocol(ip.type());
                        features.setProtocol(Protocol);// ip数据报类型
                        features.setIpSource(FormatUtils.ip(ip.source()));
                        features.setIpDestion(FormatUtils.ip(ip.destination()));
                        if (packet.hasHeader(tcp)) {
                            /************************* TCP包中的字段 **************************************/
                            features.setTcpSrcPort(tcp.source());// tcp源端口
                            features.setTcpDesPort(tcp.destination());// 目的端口
                            features.setTcpLen(packet.getHeader(tcp).getLength());// header长度
                            features.setSequenceNum(tcp.seq());
                            features.setTcpAck(tcp.ack());
                            features.setReserved(tcp.reserved()); // 是否接收到
                            features.setTcpFlages(ip.flags());
                            features.setTcpSize(packet.getHeader(tcp).size());
                            if (packet.hasHeader(http)) {
                                features.setHttpType(http.contentType());
                                features.setContentLen(http.getLength());
                            }
                        } else if (packet.hasHeader(udp)) {
                            /************************* UDP包中的字段 **************************************/
                            features.setUdpScrPort(udp.source());
                            features.setUdpDesPort(udp.destination());
                            features.setUdpLen(packet.getHeader(udp).size());
                        } else if (packet.hasHeader(icmp)) {

                        }
                    }
                    printWriter.println(features.toString());
                    printWriter.println("**************************************************************");
                    printWriter.flush();
                }
            };
            pcap.loop(-1, jpacketHandler,new String("message"));
        }

    }
}
