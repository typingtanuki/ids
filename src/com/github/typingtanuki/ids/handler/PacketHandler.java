package com.github.typingtanuki.ids.handler;

import com.github.typingtanuki.ids.exceptions.NotImplementedException;
import com.github.typingtanuki.ids.snort.SnortProtocol;
import org.pcap4j.packet.Packet;

import java.net.InetAddress;

public abstract class PacketHandler {
    protected final PacketHandler subHandler;

    public PacketHandler(Packet payload) {
        if (payload != null) {
            this.subHandler = PacketHandlers.from(payload);
        } else {
            this.subHandler = null;
        }
    }

    public abstract SnortProtocol getProtocol();

    public abstract InetAddress sourceAddress();

    public abstract int sourcePort();

    public abstract InetAddress destinationAddress();

    public abstract int destinationPort();

    public int getIcmpType() {
        if (subHandler != null) {
            return subHandler.getIcmpType();
        }
        throw new NotImplementedException("Unknown ICMP type for " + this.getClass().getSimpleName());
    }

    public int getIcmpCode() {
        if (subHandler != null) {
            return subHandler.getIcmpCode();
        }
        throw new NotImplementedException("Unknown ICMP code for " + this.getClass().getSimpleName());
    }
}
