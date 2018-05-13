package com.example.tcpdump;

/**
 * To store the connection information that is needed for future connections.
 */

public class ReducedKDDConnection {
    long TIMESTAMP;
    String PROTOCOL = null;
    String SERVICE = null;
    String FLAG = null;
    String DEST_IP = null;
    int DEST_PORT = 0;
    int SRC_PORT = 0;
}
