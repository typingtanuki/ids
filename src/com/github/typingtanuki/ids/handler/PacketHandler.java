package com.github.typingtanuki.ids.handler;

import com.github.typingtanuki.ids.exceptions.NotImplementedException;
import com.github.typingtanuki.ids.exceptions.OperationNotSupportedException;
import com.github.typingtanuki.ids.snort.SnortProtocol;
import org.pcap4j.packet.Packet;

import java.net.InetAddress;

public abstract class PacketHandler<T extends Packet> {
    private final PacketHandler<? extends Packet> subHandler;
    protected final T packet;
    protected final SnortProtocol protocol;

    public PacketHandler(T root, SnortProtocol protocol) {
        this.packet = root;
        this.protocol = protocol;

        Packet payload = root.getPayload();

        if (payload != null) {
            this.subHandler = PacketHandlers.from(payload);
        } else {
            this.subHandler = null;
        }
    }

    public final SnortProtocol getProtocol() {
        return protocol;
    }

    public abstract InetAddress sourceAddress() throws OperationNotSupportedException;

    public abstract int sourcePort() throws OperationNotSupportedException;

    public abstract InetAddress destinationAddress() throws OperationNotSupportedException;

    public abstract int destinationPort() throws OperationNotSupportedException;

    public int getIcmpType() throws OperationNotSupportedException {
        if (subHandler != null) {
            return subHandler.getIcmpType();
        }
        throw new NotImplementedException("Unknown ICMP type for " + this.getClass().getSimpleName());
    }

    public int getIcmpCode() throws OperationNotSupportedException {
        if (subHandler != null) {
            return subHandler.getIcmpCode();
        }
        throw new NotImplementedException("Unknown ICMP code for " + this.getClass().getSimpleName());
    }

    @SuppressWarnings("unchecked")
    public <U extends Packet> PacketHandler<U> getSubHandler(Class<U> classOfSub) throws OperationNotSupportedException {
        if (subHandler == null) {
            throw OperationNotSupportedException.noSubHandler(protocol);
        }
        if (!(subHandler.packet.getClass().isAssignableFrom(classOfSub))) {
            throw OperationNotSupportedException.wrongSubHandlerType(protocol, classOfSub, subHandler.packet.getClass());
        }
        return (PacketHandler<U>) subHandler;
    }
}
