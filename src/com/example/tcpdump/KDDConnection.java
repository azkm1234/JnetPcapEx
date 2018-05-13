package com.example.tcpdump;

/*
 * Creates an object for the connection record with the KDD Cup '99 data set features.
 * Of the 41 features in the KDD Cup '99 data set, features 10 to 22 have been removed as they
 * are not related to smartphones. Hence, this object will contain 28 features.
 */

import javax.swing.text.html.HTML;
import java.util.ArrayList;
import java.util.Date;
import java.util.Set;
import java.util.concurrent.BlockingQueue;

public class KDDConnection {

    // Features as described in the KDD Cup '99 Documentation
    // List of features and descriptions at: http://www.sc.ehu.es/acwaldap/gureKddcup/README.pdf

    // Intrinsic features
    long catchTime = 0;//数据包抓取的时间，timeStamp表示
    String srcIp = null;
    String desIp = null;
    int duration = 0;
    String protocol = null;
    String service = null;
    String flag = null;
    int src_bytes = 0;
    int dst_bytes = 0;
    byte land = 0;
    int wrong_fragment = 0;
    int urgent = 0;

    // Time traffic features
    int count = 0;
    int srv_count = 0;
    double serror_rate = 0.00;
    double srv_serror_rate = 0.00;
    double rerror_rate = 0.00;
    double srv_error_rate = 0.00;
    double same_srv_rate = 0.00;
    double diff_srv_rate = 0.00;
    double srv_diff_host_rate = 0.00;

    // Machine traffic features
    int dst_host_count = 0;
    int dst_host_srv_count = 0;
    double dst_host_same_srv_rate = 0.00;
    double dst_host_diff_srv_rate = 0.00;
    double dst_host_same_src_port_rate = 0.00;
    double dst_host_srv_diff_host_rate = 0.00;
    double dst_host_serror_rate = 0.00;
    double dst_host_srv_serror_rate = 0.00;
    double dst_host_rerror_rate = 0.00;
    double dst_host_srv_error_rate = 0.00;
    public static ThreadLocal<Integer> counter = new ThreadLocal<>();
    static {
        counter.set(0);
    }
    public static ArrayList<String> listToSend = new ArrayList<>(); //缓存到一定数量然后，再传输
    private String convertRecord() {
        return ("" + this.catchTime
                + "," + this.srcIp
                + "," + this.desIp
                + "," + this.duration
                + "," + this.protocol
                + ',' + this.service
                + ',' + this.flag
                + ',' + this.src_bytes
                + ',' + this.dst_bytes
                + ',' + this.land
                + ',' + this.wrong_fragment
                + ',' + this.urgent
                + ',' + this.count
                + ',' + this.srv_count
                + ',' + String.format("%.2f", this.serror_rate)
                + ',' + String.format("%.2f", this.srv_serror_rate)
                + ',' + String.format("%.2f", this.rerror_rate)
                + ',' + String.format("%.2f", this.srv_error_rate)
                + ',' + String.format("%.2f", this.same_srv_rate)
                + ',' + String.format("%.2f", this.diff_srv_rate)
                + ',' + String.format("%.2f", this.srv_diff_host_rate)
                + ',' + this.dst_host_count
                + ',' + this.dst_host_srv_count
                + ',' + String.format("%.2f", this.dst_host_same_srv_rate)
                + ',' + String.format("%.2f", this.dst_host_diff_srv_rate)
                + ',' + String.format("%.2f", this.dst_host_same_src_port_rate)
                + ',' + String.format("%.2f", this.dst_host_srv_diff_host_rate)
                + ',' + String.format("%.2f", this.dst_host_serror_rate)
                + ',' + String.format("%.2f", this.dst_host_srv_serror_rate)
                + ',' + String.format("%.2f", this.dst_host_rerror_rate)
                + ',' + String.format("%.2f", this.dst_host_srv_error_rate));
    }

    public static void writeToARFF(KDDConnection object, BlockingQueue<String> messagesToSend) {
        // Filename is the name of the ARFF file to which the connection record is to be appended.
        try {
            int tmp = counter.get();
            listToSend.add(object.convertRecord());
            if (tmp < 5) {
                counter.set(tmp + 1);
                return;
            } else {
                System.out.println(FeaturesExtratedFromFile.TAG + "start time: " + new Date(System.nanoTime()));
                messagesToSend.put(convertListToString(listToSend));
                counter.set(0);
                listToSend.clear();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    public static String convertListToString(ArrayList<String> list) {
        StringBuffer buffer = new StringBuffer();
        buffer.append(list.get(0));
        for (int i = 1; i < list.size(); i++) {
            buffer.append("\n" + list.get(i));
        }
        return buffer.toString();
    }
    // Creates a connection
    public static void createConnectionRecord(Set<DataFromLog> logData, BlockingQueue<String> messagesToSend, DataFromLog data) {
        KDDConnection newConn = new KDDConnection();

        // TIMESTAMP is in milliseconds
        newConn.duration = (int) (GlobalVariables.endTime - GlobalVariables.startTime);

        newConn.protocol = GlobalVariables.connProtocol;
        newConn.service = GlobalVariables.connService;
        newConn.flag = getFlag(newConn.protocol);

        if (GlobalVariables.connSourceIP.equals(GlobalVariables.connDestIP) && GlobalVariables.connSourcePort == GlobalVariables.connDestPort) {
            newConn.land = 1;
        } else {
            newConn.land = 0;
        }

        for (DataFromLog temp1: logData) {
            newConn.src_bytes += (temp1.SRC_IP.equals(GlobalVariables.connSourceIP)) ? temp1.LENGTH : 0;
            newConn.dst_bytes += (temp1.DEST_IP.equals(GlobalVariables.connSourceIP)) ? temp1.LENGTH : 0;
            newConn.wrong_fragment += (temp1.CHECKSUM_DESC != null && temp1.CHECKSUM_DESC.equals("correct")) ? 0 : 1;
            newConn.urgent += (temp1.FLAGS.URG) ? 1 : 0;
        }

        // Create ReducedKDDConnection object and pass & add to last100Conn and lastTwoSec
        ReducedKDDConnection tempConn = new ReducedKDDConnection();
        tempConn.TIMESTAMP = GlobalVariables.endTime;
        tempConn.PROTOCOL = newConn.protocol;
        tempConn.SERVICE = newConn.service;
        tempConn.FLAG = newConn.flag;
        tempConn.DEST_IP = GlobalVariables.connDestIP;
        tempConn.SRC_PORT = GlobalVariables.connSourcePort;
        tempConn.DEST_PORT = GlobalVariables.connDestPort;
        newConn = PastConnQueue.calculateTrafficFeatures(tempConn, newConn, GlobalVariables.last100Conn);
        newConn = LastTwoSecQueue.calculateTrafficFeatures(tempConn, newConn, GlobalVariables.lastTwoSec);
        newConn.srcIp = GlobalVariables.connSourceIP;
        newConn.desIp = GlobalVariables.connDestIP;
        newConn.catchTime = data.catchTime;
        writeToARFF(newConn, messagesToSend);
        GlobalVariables.last100Conn.addConn(tempConn);
        GlobalVariables.lastTwoSec.addConn(tempConn);
    }

    private static String getFlag (String protocol) {
        // The flag is the state of the flag when the summary was written, ie when the connection terminated
        // 1. http://www.takakura.com/Kyoto_data/BenchmarkData-Description-v3.pdf
        // 2. https://www.bro.org/sphinx/_downloads/main20.bro
        if (protocol.equals("tcp")) {
            if (GlobalVariables.stateHistory.contains("r")) {
                // Responder = TCP_RESET
                int pos = GlobalVariables.stateHistory.indexOf('r');
                String temp = GlobalVariables.stateHistory.substring(0, pos);
                if (temp.contains("S") // Originator = TCP_SYN_SENT
                    || temp.contains("H") // Originator = TCP_SYN_ACK_SENT
                    || temp.contains("R")) { // Originator = TCP_RESET
                    return "REJ";
                }
                else if (!GlobalVariables.stateHistory.contains("S") || !GlobalVariables.stateHistory.contains("H") || !GlobalVariables.stateHistory.contains("I")
                            || !GlobalVariables.stateHistory.contains("A") || !GlobalVariables.stateHistory.contains("F") || !GlobalVariables.stateHistory.contains("R")) {
                        // Originator inactive
                        return "RSTRH";
                }
                else return "RSTR";
            }
            else if (GlobalVariables.stateHistory.contains("R")) {
                int pos = GlobalVariables.stateHistory.indexOf('R');
                String temp = GlobalVariables.stateHistory.substring(pos);
                if (!temp.contains("S") || !temp.contains("H") || !temp.contains("I")
                        || !temp.contains("A") || !temp.contains("F") || !temp.contains("R")) {
                    // Originator sent a SYN followed by a RST, we never saw a SYN-ACK from the responder
                    return "RSTOS0";
                }
                else return "RSTO";
            }
            else if (GlobalVariables.stateHistory.contains("F") && GlobalVariables.stateHistory.contains("f")) {
                // Originator = TCP_CLOSED and Responder = TCP_CLOSED
                return "SF";
            }
            else if (GlobalVariables.stateHistory.contains("F")) {
                // Originator = TCP_CLOSED (with finish bit)
                int pos = GlobalVariables.stateHistory.indexOf('F');
                String temp = GlobalVariables.stateHistory.substring(pos);
                if (!temp.contains("s") || !temp.contains("h") || !temp.contains("i")
                        || !temp.contains("a") || !temp.contains("f") || !temp.contains("r")) {
                    // Responder didn't send reply after Originator sends FIN (half open connection)
                    return "SH";
                }
                else return "S2";
            }
            else if (GlobalVariables.stateHistory.contains("f")) {
                // Responder = TCP_CLOSED
                int pos = GlobalVariables.stateHistory.indexOf('f');
                String temp = GlobalVariables.stateHistory.substring(pos);
                if (!temp.contains("S") || !temp.contains("H") || !temp.contains("I")
                        || !temp.contains("A") || !temp.contains("F") || !temp.contains("R")) {
                    // Originator doesn't respond
                    return "SHR";
                }
                else return "S3";
            }
            else if (GlobalVariables.stateHistory.contains("S")) {
                int pos = GlobalVariables.stateHistory.indexOf('S');
                String temp = GlobalVariables.stateHistory.substring(pos);
                if (!temp.contains("s") || !temp.contains("h") || !temp.contains("i")
                        || !temp.contains("a") || !temp.contains("f") || !temp.contains("r")) {
                    // Originator = SYN_SENT and responder = TCP_INACTIVE
                    return "S0";
                }
            }
            else if (GlobalVariables.stateHistory.contains("H") && GlobalVariables.stateHistory.contains("h")) {
                // Originator = TCP_ESTABLISHED and responder = TCP_ESTABLISHED
                return "S1";
            }
            else return "OTH";
        }
        else if (protocol.equals("udp") || protocol.equals("icmp")) {
            // As these do not have flags, etc set, and every connection is considered established and terminated,
            return "SF";
        }
        return "OTH";
    }

    //private static boolean isOriginatorActive() {
        // Returns if originator is active or not.

    //}
}