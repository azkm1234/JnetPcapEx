package com.example.tcpdump;

import java.util.Iterator;
import java.util.LinkedList;

/**
 * Created by muktichowkwale on 13/01/15.
 */

public class LastTwoSecQueue {

    /*
     * Queue for storing connections received in the last two seconds.
     * While adding packets to the queue, the time difference is checked.
     * If the time difference is less than/equal to 2, the packet is added.
     * If greater than 2, the queue is updated and then the packet is added.
     */

    private static LinkedList<ReducedKDDConnection> pastTwoSecConn;

    public LastTwoSecQueue() {
        pastTwoSecConn = new LinkedList<ReducedKDDConnection>();
    }

    public static void addConn(ReducedKDDConnection newConn) {
        if (pastTwoSecConn.size() == 0) {
            pastTwoSecConn.add(newConn);
        }
        else if ((int) (pastTwoSecConn.get(0).TIMESTAMP - newConn.TIMESTAMP) * 1000 <= 2) {
            pastTwoSecConn.addLast(newConn);
        }
        else {
            // The queue needs to be updated.
            while ((pastTwoSecConn.size() != 0) && (((pastTwoSecConn.get(0).TIMESTAMP - newConn.TIMESTAMP) * 1000) > 2)) {
                pastTwoSecConn.removeFirst();
            }
            pastTwoSecConn.addLast(newConn);
        }
    }

    public static void clear() {
        pastTwoSecConn.clear();
    }

    public static KDDConnection calculateTrafficFeatures(ReducedKDDConnection presentDataLog, KDDConnection presentConn, LastTwoSecQueue lastTwoSec) {
        // Calculates the traffic features of KDDCup '99 data set based on two seconds connection
        Iterator iterator = lastTwoSec.pastTwoSecConn.iterator();
        ReducedKDDConnection temp;

        int numSameDestIP = 0, numSameDestPort = 0;
        int count = 0, serror = 0, rerror = 0, same_srv = 0, diff_srv = 0;
        int srv_count = 0, srv_serror = 0, srv_error = 0, srv_diff_host = 0;

        while (iterator.hasNext()) {
            temp = (ReducedKDDConnection) iterator.next();
            if (temp.DEST_IP.equals(presentDataLog.DEST_IP)) {
                numSameDestIP += 1;
                count += 1;

                serror += (temp.FLAG.equals("S0") || temp.FLAG.equals("S1") || temp.FLAG.equals("S2") || temp.FLAG.equals("S3"))?1:0;
                rerror += (temp.FLAG.equals("REJ"))?1:0;
                same_srv += (DataFromLog.getService(temp.PROTOCOL, temp.DEST_PORT).equals(presentConn.service))?1:0;
                diff_srv += (!DataFromLog.getService(temp.PROTOCOL, temp.DEST_PORT).equals(presentConn.service))?1:0;
            }

            if (temp.DEST_PORT == presentDataLog.DEST_PORT) {
                numSameDestPort += 1;
                srv_count += 1;

                srv_serror += (temp.FLAG.equals("S0") || temp.FLAG.equals("S1") || temp.FLAG.equals("S2") || temp.FLAG.equals("S3"))?1:0;
                srv_error += (temp.FLAG.equals("REJ"))?1:0;
                srv_diff_host += (!temp.DEST_IP.equals(presentDataLog.DEST_IP))?1:0;
            }

            presentConn.count = count;
            presentConn.srv_count = srv_count;

            if (numSameDestIP != 0) {
                presentConn.serror_rate = (serror/numSameDestIP)*100;
                presentConn.rerror_rate = (rerror/numSameDestIP)*100;
                presentConn.same_srv_rate = (same_srv/numSameDestIP)*100;
                presentConn.diff_srv_rate = (diff_srv/numSameDestIP)*100;
            }
            else {
                presentConn.serror_rate = 0.00;
                presentConn.rerror_rate = 0.00;
                presentConn.same_srv_rate = 0.00;
                presentConn.diff_srv_rate = 0.00;
            }

            if (numSameDestPort != 0) {
                presentConn.srv_serror_rate = (srv_serror / numSameDestPort) * 100;
                presentConn.srv_error_rate = (srv_error / numSameDestPort) * 100;
                presentConn.srv_diff_host_rate = (srv_diff_host / numSameDestPort) * 100;
            }
            else {
                presentConn.srv_serror_rate = 0.00;
                presentConn.srv_error_rate = 0.00;
                presentConn.srv_diff_host_rate = 0.00;
            }
        }

        return presentConn;
    }
}
