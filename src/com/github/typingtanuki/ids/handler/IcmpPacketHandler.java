package com.github.typingtanuki.ids.handler;

import com.github.typingtanuki.ids.snort.SnortException;
import com.github.typingtanuki.ids.snort.SnortProtocol;
import org.pcap4j.packet.IcmpV6CommonPacket;
import org.pcap4j.packet.IcmpV6NeighborSolicitationPacket;
import org.pcap4j.packet.TcpPacket;

import java.net.InetAddress;

public class IcmpPacketHandler extends PacketHandler {
    private final PacketHandler subHandler;
    private final IcmpV6NeighborSolicitationPacket solicitation;
    private IcmpV6CommonPacket packet;

    public IcmpPacketHandler(IcmpV6CommonPacket packet) throws SnortException {
        super();
        this.packet = packet;
        this.solicitation = null;
        if (packet.getPayload() != null) {
            this.subHandler = PacketHandler.from(packet.getPayload());
        } else {
            this.subHandler = null;
        }
    }

    public IcmpPacketHandler(IcmpV6NeighborSolicitationPacket packet) throws SnortException {
        this.solicitation = packet;
        this.packet = null;
        if (packet.getPayload() != null) {
            this.subHandler = PacketHandler.from(packet.getPayload());
        } else {
            this.subHandler = null;
        }
    }

    @Override
    public SnortProtocol getProtocol() {
        return SnortProtocol.icmp;
    }

    @Override
    public InetAddress sourceAddress() {
        return subHandler.sourceAddress();
    }

    @Override
    public int sourcePort() {
        return -1;
    }

    @Override
    public InetAddress destinationAddress() {
        if (solicitation != null) {
            return solicitation.getHeader().getTargetAddress();
        }
        return subHandler.destinationAddress();
    }

    @Override
    public int destinationPort() {
        return -1;
    }

    @Override
    public TcpPacket.TcpHeader getTcpHeader() {
        throw new RuntimeException("Wrong protocol");
    }
}
