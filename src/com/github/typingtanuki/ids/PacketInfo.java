package com.github.typingtanuki.ids;

import com.github.typingtanuki.ids.handler.PacketHandler;
import com.github.typingtanuki.ids.handler.PacketHandlers;
import com.github.typingtanuki.ids.snort.SnortProtocol;
import com.github.typingtanuki.ids.snort.flow.SnortFlow;
import com.github.typingtanuki.ids.snort.flow.SnortFlowManager;
import com.github.typingtanuki.ids.utils.Connection;
import org.pcap4j.packet.Packet;

import java.net.InetAddress;
import java.util.Map;

public class PacketInfo {
    private final Packet packet;
    private final PacketHandler handler;

    private int pointerPos = 0;
    private SnortFlowManager flowManager;
    private SnortFlow flow;
    private InetAddress server;
    private Map<String, Boolean> flowbits;

    public PacketInfo(Packet packet) {
        this.packet = packet;
        this.handler = PacketHandlers.from(packet);
    }

    public Packet getPacket() {
        return packet;
    }

    public SnortProtocol protocol() {
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

    public <T extends Packet> T fetchPacket(Class<T> clazz) {
        return fetchThisOrPacket(clazz, packet);
    }

    @SuppressWarnings("unchecked")
    private <T extends Packet> T fetchThisOrPacket(Class<T> clazz, Packet p) {
        if (p == null) {
            return null;
        }
        if (clazz.isInstance(p)) {
            return (T) p;
        }
        return fetchThisOrPacket(clazz, p.getPayload());
    }

    public void setFlowbits(Map<String, Boolean> flowbits) {
        this.flowbits = flowbits;
    }

    public void putFlowbit(String variable) {
        this.flowbits.put(variable, true);
    }

    public boolean readFlowbit(String variable) {
        Boolean b = this.flowbits.get(variable);
        if (b == null) {
            return false;
        }
        return b;
    }

    public void dropFlowbit(String variable) {
        this.flowbits.remove(variable);
    }

    public Connection connectionInfo() {
        return new Connection(getSrcAddr(), getSrcPort(), getDstAddr(), getDstPort());
    }

    public int getIcmpType() {
        return handler.getIcmpType();
    }

    @Override
    public String toString() {
        return "PacketInfo{" +
                "packet=" + packet +
                ", flow=" + flow +
                ", server=" + server +
                ", flowbits=" + flowbits +
                '}';
    }
}
