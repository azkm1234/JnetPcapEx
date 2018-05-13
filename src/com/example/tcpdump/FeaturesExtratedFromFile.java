package com.example.tcpdump;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

import java.io.File;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.BlockingQueue;

/**
 * @program: JnetPcapEx
 * @description:
 * @author: Mr.Zhou
 * @create: 2018-03-11 15:08
 **/
public class FeaturesExtratedFromFile implements Runnable {
    public final static String TAG = "FeaturesExtratedFromFile";
    private final static String filename = "data" + File.separator + "snort.log.1425823194.pcap";
    public final static String csvFile = "data"+ File.separator + "connection.csv";

    //    private ArrayList<JPacket> packets = null;
    private Set<DataFromLog> connSet = null;
    private BlockingQueue<String> messagesToSend;

    public FeaturesExtratedFromFile(BlockingQueue<String> messagesToSend) {
        this.messagesToSend = messagesToSend;
        this.connSet = new HashSet<>();
    }
    @Override
    public void run() {
        File file = new File(csvFile);
        try {
            file.createNewFile();
        } catch (Exception e) {
            e.printStackTrace();
        }
        getPackets();
    }

    private void getPackets() {

        System.out.println(TAG +  "in getPackets()");
        StringBuilder errbuff = new StringBuilder();

        // Open parser in offline mode
        final Pcap parser = Pcap.openOffline(filename, errbuff);
        if (parser == null) {
            System.out.println(TAG +  errbuff.toString());
        } else {
            System.out.println(TAG +  "Opened pcap file");

            JPacketHandler<String> handler = new JPacketHandler<String>() {
                DataFromLog dataFromLog;

                @Override
                public void nextPacket(JPacket packet, String user) {
                    // Add packet to displayArray and extract packet data
                    if (packet != null) {
//                        System.out.println(TAG +  "Time started: " + new Date(System.nanoTime()));
//                        packets.add(packet);

                        dataFromLog = getPacketData(packet, new DataFromLog());

                        addToConnSet(dataFromLog, connSet);
                        try {
                            Thread.sleep(200);
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                    }
                }
            };

            parser.loop(-1, handler, null);
            parser.close();
        }
    }

    private void addToConnSet(DataFromLog data, Set<DataFromLog> connSet) {
        if (data.PROTOCOL != null && data.SERVICE != null && data.DEST_IP != null && data.SRC_IP != null) {
            if (connSet.size() == 0) {
                GlobalVariables.connProtocol = data.PROTOCOL;
                GlobalVariables.connService = data.SERVICE;
                GlobalVariables.connSourceIP = data.SRC_IP;
                GlobalVariables.connDestIP = data.DEST_IP;
                GlobalVariables.connSourcePort = data.SRC_PORT;
                GlobalVariables.connDestPort = data.DEST_PORT;
                GlobalVariables.startTime = data.TIMESTAMP;
                GlobalVariables.findStateHistory(data.FLAGS, data.SRC_IP);
                connSet.add(data);
            } else {
                if (GlobalVariables.connProtocol.equals(data.PROTOCOL)
                        && GlobalVariables.connService.equals(data.SERVICE)
                        && ((GlobalVariables.connDestIP.equals(data.DEST_IP) && GlobalVariables.connSourceIP.equals(data.SRC_IP)) || (GlobalVariables.connDestIP.equals(data.SRC_IP) && GlobalVariables.connSourceIP.equals(data.DEST_IP)))) {
                    // The packet is from the same connection
                    GlobalVariables.findStateHistory(data.FLAGS, data.SRC_IP);
                    connSet.add(data);
                } else {
                    GlobalVariables.endTime = data.TIMESTAMP;
                    KDDConnection.createConnectionRecord(connSet, this.messagesToSend, data);
                    connSet.clear();
                    GlobalVariables.clearVar();
                    GlobalVariables.startTime = data.TIMESTAMP;
                    GlobalVariables.connProtocol = data.PROTOCOL;
                    GlobalVariables.connService = data.SERVICE;
                    GlobalVariables.connSourceIP = data.SRC_IP;
                    GlobalVariables.connDestIP = data.DEST_IP;
                    GlobalVariables.connSourcePort = data.SRC_PORT;
                    GlobalVariables.connDestPort = data.DEST_PORT;
                    GlobalVariables.findStateHistory(data.FLAGS, data.SRC_IP);
                    connSet.add(data);
                }
            }
        }
    }
    private DataFromLog getPacketData(JPacket packet, DataFromLog data) {

        // Types of packets that can be detected
        Ip4 ip4 = new Ip4();
        Ip6 ip6 = new Ip6();
        Tcp tcp = new Tcp();
        Udp udp = new Udp();
        Icmp icmp = new Icmp();

        if (packet != null) {
            data.TIMESTAMP = new Date(packet.getCaptureHeader().timestampInMillis()).getTime();
            data.catchTime = packet.getCaptureHeader().timestampInMillis();
            if (packet.hasHeader(ip4.ID)) {
                packet.getHeader(ip4);
                data.SRC_IP = FormatUtils.ip(ip4.source());
                data.DEST_IP = FormatUtils.ip(ip4.destination());
                data.FLAGS = getFlags(packet);

                // Check which protocol is being used
                if (packet.hasHeader(tcp.ID)) {
                    packet.getHeader(tcp);
                    data.PROTOCOL = "tcp";
                    data.SRC_PORT = tcp.source();
                    data.DEST_PORT = tcp.destination();
                    data.SERVICE = data.assignService();
                    data.LENGTH = tcp.getPayloadLength() + tcp.getHeaderLength();
                    data.CHECKSUM = tcp.checksum();
                    data.CHECKSUM_DESC = tcp.checksumDescription();
                } else if (packet.hasHeader(udp.ID)) {
                    packet.getHeader(udp);
                    data.PROTOCOL = "udp";
                    data.SRC_PORT = udp.source();
                    data.DEST_PORT = udp.destination();
                    data.SERVICE = data.assignService();
                    data.LENGTH = udp.getPayloadLength() + udp.getHeaderLength();
                    data.CHECKSUM = udp.checksum();
                    data.CHECKSUM_DESC = udp.checksumDescription();
                }
            } else if (packet.hasHeader(icmp.ID)) {
                packet.getHeader(icmp);
                data.PROTOCOL = "icmp";
                data.SRC_IP = "unknown";
                data.DEST_IP = "unknown";

                // Further, ICMP "ports" are to be interpreted as the source port meaning the ICMP message type and
                // the destination port being the ICMP message code.
                // Source: https://www.bro.org/sphinx/_downloads/main20.bro
                data.SRC_PORT = icmp.type();
                data.DEST_PORT = icmp.code();
                data.SERVICE = data.assignIcmpService(data.PROTOCOL, data.SRC_PORT, data.DEST_PORT);
                data.LENGTH = icmp.getPayloadLength() + icmp.getHeaderLength();
                data.FLAGS = getFlags(packet);
                data.CHECKSUM = icmp.checksum();
                data.CHECKSUM_DESC = icmp.checksumDescription();
            } else if (packet.hasHeader(ip6.ID)) {
                packet.getHeader(ip6);
                data.SRC_IP = FormatUtils.asStringIp6(ip6.source(), true);
                data.DEST_IP = FormatUtils.asStringIp6(ip6.destination(), true);
                data.FLAGS = getFlags(packet);

                // Check which protocol is being used
                if (packet.hasHeader(tcp.ID)) {
                    packet.getHeader(tcp);
                    data.PROTOCOL = "tcp";
                    data.SRC_PORT = tcp.source();
                    data.DEST_PORT = tcp.destination();
                    data.SERVICE = data.assignService();
                    data.LENGTH = tcp.getPayloadLength() + tcp.getHeaderLength();
                    data.CHECKSUM = tcp.checksum();
                    data.CHECKSUM_DESC = tcp.checksumDescription();
                } else if (packet.hasHeader(udp.ID)) {
                    packet.getHeader(udp);
                    data.PROTOCOL = "udp";
                    data.SRC_PORT = udp.source();
                    data.DEST_PORT = udp.destination();
                    data.SERVICE = data.assignService();
                    data.LENGTH = udp.getPayloadLength() + udp.getHeaderLength();
                    data.CHECKSUM = udp.checksum();
                    data.CHECKSUM_DESC = udp.checksumDescription();
                }
            }
        }
        return data;
    }

    private Flags getFlags(JPacket packet) {
        Tcp tcp = new Tcp();
        Udp udp = new Udp();
        Icmp icmp = new Icmp();
        Flags flags = new Flags();

        if (packet.hasHeader(tcp.ID)) {
            packet.getHeader(tcp);
            flags.ACK = tcp.flags_ACK();
            flags.CWR = tcp.flags_CWR();
            flags.ECE = tcp.flags_ECE();
            flags.FIN = tcp.flags_FIN();
            flags.PSH = tcp.flags_PSH();
            flags.RST = tcp.flags_RST();
            flags.SYN = tcp.flags_SYN();
            flags.URG = tcp.flags_URG();
            flags.ORIGINATOR = (tcp.source() == GlobalVariables.connSourcePort);
        } else if (packet.hasHeader(udp.ID)) {
            packet.getHeader(udp);
            flags.none = true;
            flags.ORIGINATOR = (udp.source() == GlobalVariables.connSourcePort);
        }
        else if (packet.hasHeader(icmp.ID)) {
            flags.none = true;
        }
        return flags;
    }
}
