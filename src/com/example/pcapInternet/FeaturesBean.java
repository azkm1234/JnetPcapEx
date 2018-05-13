package com.example.pcapInternet;

/**
 * @program: JnetPcapEx
 * @description: KDD99 Data Features
 * @author: Mr.Wang
 * @create: 2018-03-07 15:37
 **/
public class FeaturesBean {
    // eth Header
    private long time;
    private int Length;
    private int captureLen;


    // IP header
    private int IpVersion;
    private int IpHeaderLength;
    private int ServiceType;
    private int TotalLenth;
    private int Identification;
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


    // udpHeader
    private int UdpScrPort;
    private int UdpDesPort;
    private int UdpLen;

    // Icmp Header
//    private int IcmpType;
//    private int IcmpCode;
//
//    private int IcmpId;
//    private int IcmpSize;

    private String httpType;
    private int ContentLen;

    public long getTime() {
        return time;
    }

    public void setTime(long time) {
        this.time = time;
    }

    public int getLength() {
        return Length;
    }

    public void setLength(int length) {
        Length = length;
    }

    public int getCaptureLen() {
        return captureLen;
    }

    public void setCaptureLen(int captureLen) {
        this.captureLen = captureLen;
    }

    public int getIpVersion() {
        return IpVersion;
    }

    public void setIpVersion(int ipVersion) {
        IpVersion = ipVersion;
    }

    public int getIpHeaderLength() {
        return IpHeaderLength;
    }

    public void setIpHeaderLength(int ipHeaderLength) {
        IpHeaderLength = ipHeaderLength;
    }

    public int getServiceType() {
        return ServiceType;
    }

    public void setServiceType(int serviceType) {
        ServiceType = serviceType;
    }

    public int getTotalLenth() {
        return TotalLenth;
    }

    public void setTotalLenth(int totalLenth) {
        TotalLenth = totalLenth;
    }

    public int getIdentification() {
        return Identification;
    }

    public void setIdentification(int identification) {
        Identification = identification;
    }


    public int getTtl() {
        return Ttl;
    }

    public void setTtl(int ttl) {
        Ttl = ttl;
    }

    public String getProtocol() {
        return Protocol;
    }

    public void setProtocol(String protocol) {
        Protocol = protocol;
    }

    public int getChecksum() {
        return Checksum;
    }

    public void setChecksum(int checksum) {
        Checksum = checksum;
    }

    public String getIpSource() {
        return IpSource;
    }

    public void setIpSource(String ipSource) {
        IpSource = ipSource;
    }

    public String getIpDestion() {
        return IpDestion;
    }

    public void setIpDestion(String ipDestion) {
        IpDestion = ipDestion;
    }

    public int getTcpSrcPort() {
        return tcpSrcPort;
    }

    public void setTcpSrcPort(int tcpSrcPort) {
        this.tcpSrcPort = tcpSrcPort;
    }

    public int getTcpDesPort() {
        return tcpDesPort;
    }

    public void setTcpDesPort(int tcpDesPort) {
        this.tcpDesPort = tcpDesPort;
    }

    public long getSequenceNum() {
        return SequenceNum;
    }

    public void setSequenceNum(long sequenceNum) {
        SequenceNum = sequenceNum;
    }

    public long getTcpAck() {
        return TcpAck;
    }

    public void setTcpAck(long tcpAck) {
        TcpAck = tcpAck;
    }

    public int getTcpLen() {
        return TcpLen;
    }

    public void setTcpLen(int tcpLen) {
        TcpLen = tcpLen;
    }

    public int getReserved() {
        return Reserved;
    }

    public void setReserved(int reserved) {
        Reserved = reserved;
    }

    public int getTcpFlages() {
        return TcpFlages;
    }

    public void setTcpFlages(int tcpFlages) {
        TcpFlages = tcpFlages;
    }

    public int getTcpSize() {
        return TcpSize;
    }

    public void setTcpSize(int tcpSize) {
        TcpSize = tcpSize;
    }

    public int getUdpScrPort() {
        return UdpScrPort;
    }

    public void setUdpScrPort(int udpScrPort) {
        UdpScrPort = udpScrPort;
    }

    public int getUdpDesPort() {
        return UdpDesPort;
    }

    public void setUdpDesPort(int udpDesPort) {
        UdpDesPort = udpDesPort;
    }

    public int getUdpLen() {
        return UdpLen;
    }

    public void setUdpLen(int udpLen) {
        UdpLen = udpLen;
    }

    public String getHttpType() {
        return httpType;
    }

    public void setHttpType(String httpType) {
        this.httpType = httpType;
    }

    public int getContentLen() {
        return ContentLen;
    }

    public void setContentLen(int contentLen) {
        ContentLen = contentLen;
    }

    @Override
    public String toString() {
        return "{" +
                "time=" + time +
                ", Length=" + Length +
                ", captureLen=" + captureLen +
                ", IpVersion=" + IpVersion +
                ", IpHeaderLength=" + IpHeaderLength +
                ", ServiceType=" + ServiceType +
                ", TotalLenth=" + TotalLenth +
                ", Identification=" + Identification +
                ", Ttl=" + Ttl +
                ", Protocol='" + Protocol + '\'' +
                ", Checksum=" + Checksum +
                ", IpSource='" + IpSource + '\'' +
                ", IpDestion='" + IpDestion + '\'' +
                ", tcpSrcPort=" + tcpSrcPort +
                ", tcpDesPort=" + tcpDesPort +
                ", SequenceNum=" + SequenceNum +
                ", TcpAck=" + TcpAck +
                ", TcpLen=" + TcpLen +
                ", Reserved=" + Reserved +
                ", TcpFlages=" + TcpFlages +
                ", TcpSize=" + TcpSize +
                ", UdpScrPort=" + UdpScrPort +
                ", UdpDesPort=" + UdpDesPort +
                ", UdpLen=" + UdpLen +
                ", httpType='" + httpType + '\'' +
                ", ContentLen=" + ContentLen +
                '}';
    }
}
/*

 */
