package com.example.tcpdump;

/*
 * Creates an object that contains data from the log.
 */

public class DataFromLog {

    final static String TAG = "DataFromLog";
    long catchTime;
    // Timestamp
    long TIMESTAMP;
    // Source IP Address
    String SRC_IP;
    // Source Port Number; if port is -1, then unknown port
    int SRC_PORT;
    // Destination IP Address
    String DEST_IP;
    // Destination Port Number
    int DEST_PORT;
    // Length of the IP Packet
    int LENGTH;
    // Protocol used; Complete list of protocols at http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
    String PROTOCOL;
    // Service
    String SERVICE;
    // Flags
    Flags FLAGS;
    // Checksum
    int CHECKSUM;
    // CheckedChecksum
    String CHECKSUM_DESC;
    // Final Flag for KDD: Added here as it is needed in PastConnQueue.
    String FLAG;

    public String assignService () {
        String temp, temp1;
        temp = getService(this.PROTOCOL, this.SRC_PORT);
        temp1 = getService(this.PROTOCOL, this.DEST_PORT);
        return ((temp.equals("other"))?temp1:temp);
    }

    public static String assignIcmpService (String protocol, int type, int code) {
        if (protocol != null) {
            switch (type) {
                case (0):
                    return "ecr_i";
                case (3):
                    if (code == 1) { return ("urh_i"); } // Host Unreachable
                    else if (code == 3) {return ("urp_i"); } // Port Unreachable
                    else {return "other"; }
                case (5):
                    return "red_i";
                case (8):
                    return "eco_i";
                case (11):
                    return "tim_i";
            }
        }
        return "other";
    }
    public static String getService (String protocol, int port) {
        // List of ports: http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xml
        // Call only if the protocol is TCP or UDP.
        // Didn't find: 'harvest',  'pm_dump', 'private'
        if (protocol != null) {
            if (protocol.equals("tcp") && (port == 53 || port == 512 || port == 513 || port == 514 || port == 520)) {
                switch (port) {
                    case (53):
                        return "domain"; // TCP DNS Port
                    case (512):
                        return "exec"; // TCP only
                    case (513):
                        return "login"; // TCP only
                    case (514):
                        return "shell"; // TCP only
                    case (520):
                        return "efs"; // TCP only
                }
            }
            else {
                switch (port) {
                    case (5):
                        return "rje";
                    case (7):
                        return "echo";
                    case (9):
                        return "discard";
                    case (11):
                        return "systat";
                    case (13):
                        return "daytime";
                    case (15):
                        return "netstat";
                    case (20):
                        return "ftp_data";
                    case (21):
                        return "ftp";
                    case (22):
                        return "ssh";
                    case (23):
                        return "telnet";
                    case (25):
                        return "smtp";
                    case (37):
                        return "time";
                    case (42):
                        return "name";
                    case (43):
                        return "whois";
                    case (53):
                        return "domain_u"; // UDP DNS port
                    case (66):
                        return "sql_net";
                    case (69):
                        return "tftp_u";
                    case (70):
                        return "gopher";
                    case (71 - 74):
                        return "remote_job";
                    case (79):
                        return "finger";
                    case (80):
                        return "http";
                    case (84):
                        return "ctf";
                    case (95):
                        return "supdup";
                    case (101):
                        return "hostnames";
                    case (102):
                        return "iso_tsap";
                    case (105):
                        return "csnet_ns";
                    case (109):
                        return "pop_2";
                    case (110):
                        return "pop_3";
                    case (111):
                        return "sunrpc";
                    case (113):
                        return "auth";
                    case (117):
                        return "uucp_path";
                    case (119):
                        return "nntp";
                    case (123):
                        return "ntp_u";
                    case (137):
                        return "netbios_ns";
                    case (138):
                        return "netbios_dgm";
                    case (139):
                        return "netbios_ssn";
                    case (143):
                        return "imap4";
                    case (175):
                        return "vmnet";
                    case (179):
                        return "bgp";
                    case (210):
                        return "Z39_50";
                    case (245):
                        return "link";
                    case (389):
                        return "ldap";
                    case (433):
                        return "nnsp";
                    case (443):
                        return "http_443";
                    case (515):
                        return "printer";
                    case (530):
                        return "courier";
                    case (540):
                        return "uucp";
                    case (543):
                        return "klogin";
                    case (544):
                        return "kshell";
                    case (1911):
                        return "mtp";
                    case (2784):
                        return "http_2784";
                    case (5190):
                        return "aol";
                    case (6000 - 6063):
                        return "X11";
                    case (6665 - 6669):
                        return "IRC";
                    case (8001):
                        return "http_8001";
                }
            }
        }
        return "other";
    }
}
