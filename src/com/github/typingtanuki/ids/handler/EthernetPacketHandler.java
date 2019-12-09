package com.github.typingtanuki.ids.handler;

import com.github.typingtanuki.ids.snort.SnortException;
import com.github.typingtanuki.ids.snort.SnortProtocol;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.TcpPacket;

import java.net.InetAddress;

public class EthernetPacketHandler extends PacketHandler {
    private final PacketHandler subHandler;
    private EthernetPacket packet;

    public EthernetPacketHandler(EthernetPacket packet) throws SnortException {
        super();
        this.packet = packet;
        this.subHandler = PacketHandler.from(packet.getPayload());
    }

    @Override
    public SnortProtocol getProtocol() {
        return subHandler.getProtocol();
    }

    @Override
    public InetAddress sourceAddress() {
        return subHandler.sourceAddress();
    }

    @Override
    public int sourcePort() {
        return subHandler.sourcePort();
    }

    @Override
    public InetAddress destinationAddress() {
        return subHandler.destinationAddress();
    }

    @Override
    public int destinationPort() {
        return subHandler.destinationPort();
    }

    @Override
    public TcpPacket.TcpHeader getTcpHeader() {
        return subHandler.getTcpHeader();
    }
}
