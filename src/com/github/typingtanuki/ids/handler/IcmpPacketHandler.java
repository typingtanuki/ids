package com.github.typingtanuki.ids.handler;

import com.github.typingtanuki.ids.snort.SnortProtocol;
import org.pcap4j.packet.*;

import java.net.InetAddress;

public class IcmpPacketHandler extends PacketHandler {
    private final IcmpV6NeighborSolicitationPacket solicitation;
    private final Integer icmpType;
    private final Integer icmpCode;

    public IcmpPacketHandler(IcmpV6CommonPacket packet) {
        super(packet.getPayload());
        this.solicitation = null;
        icmpType = (int)packet.getHeader().getType().value();
        icmpCode = (int)packet.getHeader().getCode().value();
    }

    public IcmpPacketHandler(IcmpV6NeighborSolicitationPacket packet) {
        super(packet.getPayload());
        this.solicitation = packet;
        icmpType = null;
        icmpCode = null;
    }

    public IcmpPacketHandler(IcmpV4CommonPacket packet) {
        super(packet.getPayload());
        this.solicitation = null;
        icmpType = (int)packet.getHeader().getType().value();
        icmpCode = (int)packet.getHeader().getCode().value();
    }

    public IcmpPacketHandler(IcmpV4EchoPacket packet) {
        super(packet.getPayload());
        this.solicitation = null;
        icmpType = null;
        icmpCode = null;
    }

    public IcmpPacketHandler(IcmpV4EchoReplyPacket packet) {
        super(packet.getPayload());
        this.solicitation = null;
        icmpType = null;
        icmpCode = null;
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
        if(icmpType!=null){
            return icmpType;
        }
        return subHandler.getIcmpType();
    }
    @Override
    public int getIcmpCode() {
        if(icmpCode!=null){
            return icmpCode;
        }
        return subHandler.getIcmpCode();
    }
}
