package com.example.tcpdump;

import java.util.Iterator;
import java.util.LinkedList;

/**
 * Created by muktichowkwale on 13/01/15.
 */

public class PastConnQueue {
    /*
     * Queue for storing the past 100 connections.
     * Until 100 connections are stored, each packet is added;
     * after this, every time a packet is added, the front packet is removed.
     */

    private static LinkedList<ReducedKDDConnection> pastConn;
    private static int maxConn = 100;

    public PastConnQueue() {
        pastConn = new LinkedList<ReducedKDDConnection>();
    }

    public void clear() {
        pastConn.clear();
    }

    public static void addConn (ReducedKDDConnection newConn) {
        if (pastConn.size() == maxConn) {
            pastConn.removeFirst();
            pastConn.addLast(newConn);
        }
        else {
            pastConn.addLast(newConn);
        }
    }

    public static KDDConnection calculateTrafficFeatures(ReducedKDDConnection presentDataLog, KDDConnection presentConn, PastConnQueue last100Conn) {
        // Calculates the traffic features of the KDDCup '99 data set based on 100 previous connections
        Iterator iterator = last100Conn.pastConn.iterator();
        ReducedKDDConnection temp;

        int numSameDestIP = 0, numSameDestPort = 0;
        int dst_host_count = 0, dst_host_same_srv = 0, dst_host_diff_srv = 0, dst_host_serror = 0, dst_host_rerror = 0;
        int dst_host_srv_count = 0, dst_host_same_src_port = 0, dst_host_srv_diff_host = 0, dst_host_srv_serror = 0, dst_host_srv_error = 0;

        while (iterator.hasNext()) {
            temp = (ReducedKDDConnection) iterator.next();
            if (temp.DEST_IP.equals(presentDataLog.DEST_IP)) {
                numSameDestIP += 1;
                dst_host_count += 1;

                // Same service
                dst_host_same_srv += (DataFromLog.getService(temp.PROTOCOL, temp.DEST_PORT).equals(presentConn.service))?1:0;
                // Different service
                dst_host_diff_srv += (!DataFromLog.getService(temp.PROTOCOL, temp.DEST_PORT).equals(presentConn.service))?1:0;

                dst_host_serror += (temp.FLAG.equals("S0") || temp.FLAG.equals("S1") || temp.FLAG.equals("S2") || temp.FLAG.equals("S3"))?1:0;
                dst_host_rerror += (temp.FLAG.equals("REJ"))?1:0;
            }

            if (temp.DEST_PORT == presentDataLog.DEST_PORT) {
                numSameDestPort += 1;
                dst_host_srv_count += 1;

                dst_host_same_src_port += (temp.SRC_PORT == presentDataLog.SRC_PORT)?1:0;
                dst_host_srv_diff_host += (!temp.DEST_IP.equals(presentDataLog.DEST_IP))?1:0;
                dst_host_srv_serror += (temp.FLAG.equals("S0") || temp.FLAG.equals("S1") || temp.FLAG.equals("S2") || temp.FLAG.equals("S3"))?1:0;
                dst_host_srv_error += (temp.FLAG.equals("REJ"))?1:0;
            }
        }

        presentConn.dst_host_count = dst_host_count;
        presentConn.dst_host_srv_count = dst_host_srv_count;

        if (numSameDestIP != 0) {
            presentConn.dst_host_same_srv_rate = (dst_host_same_srv/numSameDestIP)*100;
            presentConn.dst_host_diff_srv_rate = (dst_host_diff_srv/numSameDestIP)*100;
            presentConn.dst_host_serror_rate = (dst_host_serror/numSameDestIP)*100;
            presentConn.dst_host_rerror_rate = (dst_host_rerror/numSameDestIP)*100;
        }
        else {
            presentConn.dst_host_same_srv_rate = 0.00;
            presentConn.dst_host_diff_srv_rate = 0.00;
            presentConn.dst_host_serror_rate = 0.00;
            presentConn.dst_host_rerror_rate = 0.00;
        }

        if (numSameDestPort != 0) {
            presentConn.dst_host_same_src_port_rate = (dst_host_same_src_port / numSameDestPort) * 100;
            presentConn.dst_host_srv_diff_host_rate = (dst_host_srv_diff_host / numSameDestPort) * 100;
            presentConn.dst_host_srv_serror_rate = (dst_host_srv_serror / numSameDestPort) * 100;
            presentConn.dst_host_srv_error_rate = (dst_host_srv_error / numSameDestPort) * 100;
        }
        else {
            presentConn.dst_host_same_src_port_rate = 0.00;
            presentConn.dst_host_srv_diff_host_rate = 0.00;
            presentConn.dst_host_srv_serror_rate = 0.00;
            presentConn.dst_host_srv_error_rate = 0.00;
        }
        return presentConn;
    }
}