package com.github.typingtanuki.ids.handler;

import com.github.typingtanuki.ids.snort.SnortProtocol;
import org.pcap4j.packet.*;

import java.net.InetAddress;

public class IcmpPacketHandler extends PacketHandler {
    private final IcmpV6NeighborSolicitationPacket solicitation;
    private final int icmpType;

    public IcmpPacketHandler(IcmpV6CommonPacket packet) {
        super(packet.getPayload());
        this.solicitation = null;
        icmpType = packet.getHeader().getType().value();
    }

    public IcmpPacketHandler(IcmpV6NeighborSolicitationPacket packet) {
        super(packet.getPayload());
        this.solicitation = packet;
        icmpType = -1;
    }

    public IcmpPacketHandler(IcmpV4CommonPacket packet) {
        super(packet.getPayload());
        this.solicitation = null;
        icmpType = packet.getHeader().getType().value();
    }

    public IcmpPacketHandler(IcmpV4EchoPacket packet) {
        super(packet.getPayload());
        this.solicitation = null;
        icmpType = packet.getHeader().getIdentifierAsInt();
    }

    public IcmpPacketHandler(IcmpV4EchoReplyPacket packet) {
        super(packet.getPayload());
        this.solicitation = null;
        icmpType = packet.getHeader().getIdentifierAsInt();
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
    public int getIcmpType() {
        return icmpType;
    }
}
