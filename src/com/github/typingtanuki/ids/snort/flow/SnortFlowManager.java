package com.github.typingtanuki.ids.snort.flow;

import com.github.typingtanuki.ids.PacketMetadata;
import com.github.typingtanuki.ids.utils.Tuple;

import java.net.InetAddress;
import java.util.LinkedHashMap;
import java.util.Map;

public class SnortFlowManager {
    private final Map<Tuple<InetAddress, InetAddress>, SnortFlow> stateMap = new LinkedHashMap<>();
    private final Map<Tuple<InetAddress, InetAddress>, InetAddress> serverIdentity = new LinkedHashMap<>();

    public void handle(PacketMetadata metadata) {
        Tuple<InetAddress, InetAddress> connection = new Tuple<>(metadata.getSrcAddr(), metadata.getDstAddr());
        SnortFlow currentFlow = stateMap.getOrDefault(connection, SnortFlow.UNKNOWN);
        InetAddress identity = serverIdentity.getOrDefault(connection, null);
        metadata.setFlow(currentFlow);
        metadata.defineServer(identity);
        metadata.setFlowManager(this);

        if (metadata.getTcpFlagSyn() && !metadata.getTcpFlagAck()) {
            metadata.setFlow(SnortFlow.SYN_RECEIVED);
            serverIdentity.put(connection, metadata.getDstAddr());
        } else if (metadata.getTcpFlagSyn() && metadata.getTcpFlagAck()) {
            metadata.setFlow(SnortFlow.SYN_ACKED);
            serverIdentity.put(connection, metadata.getSrcAddr());
        } else if ((currentFlow == SnortFlow.SYN_ACKED || currentFlow == SnortFlow.SYN_RECEIVED) && metadata.getTcpFlagAck()) {
            metadata.setFlow(SnortFlow.ESTABLISHED);
            serverIdentity.put(connection, metadata.getDstAddr());
        }
        stateMap.put(connection, metadata.getFlow());
    }

    @Override
    public String toString() {
        return "SnortFlowManager{" +
                "stateMap=" + stateMap +
                '}';
    }

    public boolean isEstablished(PacketMetadata metadata) {
        Tuple<InetAddress, InetAddress> connection = new Tuple<>(metadata.getSrcAddr(), metadata.getDstAddr());
        return stateMap.getOrDefault(connection, SnortFlow.UNKNOWN).equals(SnortFlow.ESTABLISHED);
    }

    public boolean isFromServer(PacketMetadata metadata) {
        Tuple<InetAddress, InetAddress> connection = new Tuple<>(metadata.getSrcAddr(), metadata.getDstAddr());
        return metadata.getSrcAddr().equals(serverIdentity.getOrDefault(connection, null));
    }
}
