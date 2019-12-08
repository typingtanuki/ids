package com.github.typingtanuki.ids;

import com.github.typingtanuki.ids.snort.SnortException;
import com.github.typingtanuki.ids.snort.SnortProtocol;
import com.github.typingtanuki.ids.snort.flow.SnortFlow;
import com.github.typingtanuki.ids.snort.flow.SnortFlowManager;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

import java.net.InetAddress;

public class PacketMetadata {
    private Packet packet;
    private int pointerPos = 0;
    private PacketHandler handler;
    private SnortFlowManager flowManager;
    private SnortFlow flow;
    private InetAddress server;

    public void setPacket(Packet packet) throws SnortException {
        this.packet = packet;
        this.handler = PacketHandler.from(packet);
    }

    public Packet getPacket() {
        return packet;
    }

    public SnortProtocol protocol() throws SnortException {
        return handler.getProtocol();
    }

    public byte[] payload() {
        return packet.getPayload().getRawData();
    }

    public int getPointerPos() {
        return pointerPos;
    }

    public void setPointerPos(int pointerPos) {
        this.pointerPos = pointerPos;
    }

    public InetAddress getSrcAddr() {
        return handler.sourceAddress();
    }

    public int getSrcPort() {
        return handler.sourcePort();
    }

    public InetAddress getDstAddr() {
        return handler.destinationAddress();
    }

    public int getDstPort() {
        return handler.destinationPort();
    }

    public SnortFlowManager getFlowManager() {
        return flowManager;
    }

    public void setFlowManager(SnortFlowManager flowManager) {
        this.flowManager = flowManager;
    }

    public void setFlow(SnortFlow flow) {
        this.flow = flow;
    }

    public SnortFlow getFlow() {
        return flow;
    }

    public void setServer(InetAddress server) {
        this.server = server;
    }

    public InetAddress getServer() {
        return server;
    }

    public TcpPacket.TcpHeader getTcpHeader() throws SnortException {
        if (handler.getProtocol() != SnortProtocol.tcp) {
            throw new SnortException("Only available for TCP");
        }
        return handler.getTcpHeader();
    }

    public <T extends Packet> T fetchPacket(Class<T> clazz) {
        return fetchThisOrPacket(clazz, packet);
    }

    private <T extends Packet> T fetchThisOrPacket(Class<T> clazz, Packet p) {
        if (p == null) {
            return null;
        }
        if (clazz.isInstance(p)) {
            return (T) p;
        }
        return fetchThisOrPacket(clazz, p.getPayload());
    }
}
