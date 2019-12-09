package com.github.typingtanuki.ids.handler;

import com.github.typingtanuki.ids.snort.SnortException;
import com.github.typingtanuki.ids.snort.SnortProtocol;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.TcpPacket;

import java.net.InetAddress;

public class ArpPacketHandler extends PacketHandler {
    private final PacketHandler subHandler;
    private ArpPacket packet;

    public ArpPacketHandler(ArpPacket packet) throws SnortException {
        super();
        this.packet = packet;
        if (packet.getPayload() != null) {
            this.subHandler = PacketHandler.from(packet.getPayload());
        } else {
            this.subHandler = null;
        }
    }

    @Override
    public SnortProtocol getProtocol() {
        return SnortProtocol.arp;
    }

    @Override
    public InetAddress sourceAddress() {
        return packet.getHeader().getSrcProtocolAddr();
    }

    @Override
    public int sourcePort() {
        if(subHandler==null){
            return -1;
        }
        return subHandler.sourcePort();
    }

    @Override
    public InetAddress destinationAddress() {
        return packet.getHeader().getDstProtocolAddr();
    }

    @Override
    public int destinationPort() {
        if(subHandler==null){
            return -1;
        }
        return subHandler.destinationPort();
    }

    @Override
    public TcpPacket.TcpHeader getTcpHeader() {
        return subHandler.getTcpHeader();
    }
}
