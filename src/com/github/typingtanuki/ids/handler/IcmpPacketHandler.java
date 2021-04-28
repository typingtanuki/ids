package com.github.typingtanuki.ids.handler;

import com.github.typingtanuki.ids.IcmpPacket;
import com.github.typingtanuki.ids.exceptions.OperationNotSupportedException;
import com.github.typingtanuki.ids.snort.SnortProtocol;
import org.pcap4j.packet.IcmpV4EchoReplyPacket;
import org.pcap4j.packet.IcmpV6NeighborSolicitationPacket;

import java.net.InetAddress;

public class IcmpPacketHandler extends PacketHandler<IcmpPacket> {
    private final IcmpV6NeighborSolicitationPacket solicitation;
    private final Integer icmpType;
    private final Integer icmpCode;

    public IcmpPacketHandler(IcmpPacket packet) {
        super(packet, SnortProtocol.icmp);
        this.solicitation = null;
        icmpType = packet.getType();
        icmpCode = packet.getCode();
    }

    private static IcmpPacket wrap(IcmpV4EchoReplyPacket packet) {
        return new IcmpPacket(packet);
    }

    @Override
    public InetAddress sourceAddress() throws OperationNotSupportedException {
        return getSubHandler(IcmpPacket.class).sourceAddress();
    }

    @Override
    public int sourcePort() throws OperationNotSupportedException {
        throw OperationNotSupportedException.noSourcePort(getProtocol());
    }

    @Override
    public InetAddress destinationAddress() throws OperationNotSupportedException {
        if (solicitation != null) {
            return solicitation.getHeader().getTargetAddress();
        }
        return getSubHandler(IcmpPacket.class).destinationAddress();
    }

    @Override
    public int destinationPort() throws OperationNotSupportedException {
        throw OperationNotSupportedException.noDestinationPort(getProtocol());
    }

    @Override
    public int getIcmpType() throws OperationNotSupportedException {
        if (icmpType != null) {
            return icmpType;
        }
        return getSubHandler(IcmpPacket.class).getIcmpType();
    }

    @Override
    public int getIcmpCode() throws OperationNotSupportedException {
        if (icmpCode != null) {
            return icmpCode;
        }
        return getSubHandler(IcmpPacket.class).getIcmpCode();
    }
}
