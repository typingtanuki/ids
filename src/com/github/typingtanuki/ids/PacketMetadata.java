package com.github.typingtanuki.ids;

import com.github.typingtanuki.ids.snort.flow.SnortFlow;
import com.github.typingtanuki.ids.snort.flow.SnortFlowManager;

import java.net.InetAddress;
import java.util.Arrays;

public class PacketMetadata {
    private InetAddress srcAddr;
    private InetAddress dstAddr;
    private String protocol;
    private int srcPort = Integer.MIN_VALUE;
    private int dstPort = Integer.MIN_VALUE;
    private byte[] data;
    private long tcpFlagSequenceNumber;
    private long tcpFlagAcknowledgmentNumber;
    private int tcpFlagDataOffset;
    private byte tcpFlagReserved;
    private boolean tcpFlagUrg;
    private boolean tcpFlagAck;
    private boolean tcpFlagPsh;
    private boolean tcpFlagRst;
    private boolean tcpFlagSyn;
    private boolean tcpFlagFin;
    private int tcpFlagWindow;
    private short tcpFlagChecksum;
    private int tcpFlagUrgentPointer;
    private int pointerPos = 0;
    private SnortFlow flow;
    private Boolean fromServer = null;
    private SnortFlowManager flowManager;

    public InetAddress getSrcAddr() {
        return srcAddr;
    }

    public void setSrcAddr(InetAddress srcAddr) {
        this.srcAddr = srcAddr;
    }

    public InetAddress getDstAddr() {
        return dstAddr;
    }

    public void setDstAddr(InetAddress dstAddr) {
        this.dstAddr = dstAddr;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public int getSrcPort() {
        return srcPort;
    }

    public void setSrcPort(int srcPort) {
        this.srcPort = srcPort;
    }

    public int getDstPort() {
        return dstPort;
    }

    public void setDstPort(int dstPort) {
        this.dstPort = dstPort;
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    @Override
    public String toString() {
        return "PacketMetadata{" +
                "srcAddr=" + srcAddr +
                ", dstAddr=" + dstAddr +
                ", protocol='" + protocol + '\'' +
                ", srcPort=" + srcPort +
                ", dstPort=" + dstPort +
                ", data=" + Arrays.toString(data) +
                '}';
    }

    public boolean isEmpty() {
        return srcAddr == null &&
                dstAddr == null &&
                protocol == null &&
                srcPort != Integer.MIN_VALUE &&
                dstPort != Integer.MIN_VALUE;
    }

    public long getTcpFlagSequenceNumber() {
        return tcpFlagSequenceNumber;
    }

    public void setTcpFlagSequenceNumber(long tcpFlagSequenceNumber) {
        this.tcpFlagSequenceNumber = tcpFlagSequenceNumber;
    }

    public long getTcpFlagAcknowledgmentNumber() {
        return tcpFlagAcknowledgmentNumber;
    }

    public void setTcpFlagAcknowledgmentNumber(long tcpFlagAcknowledgmentNumber) {
        this.tcpFlagAcknowledgmentNumber = tcpFlagAcknowledgmentNumber;
    }

    public int getTcpFlagDataOffset() {
        return tcpFlagDataOffset;
    }

    public void setTcpFlagDataOffset(int tcpFlagDataOffset) {
        this.tcpFlagDataOffset = tcpFlagDataOffset;
    }

    public byte getTcpFlagReserved() {
        return tcpFlagReserved;
    }

    public void setTcpFlagReserved(byte tcpFlagReserved) {
        this.tcpFlagReserved = tcpFlagReserved;
    }

    public boolean getTcpFlagUrg() {
        return tcpFlagUrg;
    }

    public void setTcpFlagUrg(boolean tcpFlagUrg) {
        this.tcpFlagUrg = tcpFlagUrg;
    }

    public boolean getTcpFlagAck() {
        return tcpFlagAck;
    }

    public void setTcpFlagAck(boolean tcpFlagAck) {
        this.tcpFlagAck = tcpFlagAck;
    }

    public boolean getTcpFlagPsh() {
        return tcpFlagPsh;
    }

    public void setTcpFlagPsh(boolean tcpFlagPsh) {
        this.tcpFlagPsh = tcpFlagPsh;
    }

    public boolean getTcpFlagRst() {
        return tcpFlagRst;
    }

    public void setTcpFlagRst(boolean tcpFlagRst) {
        this.tcpFlagRst = tcpFlagRst;
    }

    public boolean getTcpFlagSyn() {
        return tcpFlagSyn;
    }

    public void setTcpFlagSyn(boolean tcpFlagSyn) {
        this.tcpFlagSyn = tcpFlagSyn;
    }

    public boolean getTcpFlagFin() {
        return tcpFlagFin;
    }

    public void setTcpFlagFin(boolean tcpFlagFin) {
        this.tcpFlagFin = tcpFlagFin;
    }

    public int getTcpFlagWindow() {
        return tcpFlagWindow;
    }

    public void setTcpFlagWindow(int tcpFlagWindow) {
        this.tcpFlagWindow = tcpFlagWindow;
    }

    public short getTcpFlagChecksum() {
        return tcpFlagChecksum;
    }

    public void setTcpFlagChecksum(short tcpFlagChecksum) {
        this.tcpFlagChecksum = tcpFlagChecksum;
    }

    public int getTcpFlagUrgentPointer() {
        return tcpFlagUrgentPointer;
    }

    public void setTcpFlagUrgentPointer(int tcpFlagUrgentPointer) {
        this.tcpFlagUrgentPointer = tcpFlagUrgentPointer;
    }

    public int getPointerPos() {
        return pointerPos;
    }

    public void setPointerPos(int pointerPos) {
        this.pointerPos = pointerPos;
    }

    public void setFlow(SnortFlow flow) {
        this.flow = flow;
    }

    public SnortFlow getFlow() {
        return flow;
    }

    public void defineServer(InetAddress serverIdentity) {
        if (serverIdentity == null) {
            return;
        }
        if (serverIdentity.equals(srcAddr)) {
            setFromServer(true);
        } else if (serverIdentity.equals(dstAddr)) {
            setFromServer(false);
        } else {
            setFromServer(null);
        }
    }

    public void setFromServer(Boolean fromServer) {
        this.fromServer = fromServer;
    }

    public Boolean getFromServer() {
        return fromServer;
    }

    public void setFlowManager(SnortFlowManager flowManager) {
        this.flowManager = flowManager;
    }

    public SnortFlowManager getFlowManager() {
        return flowManager;
    }
}
