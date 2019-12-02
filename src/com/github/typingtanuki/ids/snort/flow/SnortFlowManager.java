package com.github.typingtanuki.ids.snort.flow;

import com.github.typingtanuki.ids.PacketMetadata;
import com.github.typingtanuki.ids.utils.Tuple;

import java.net.InetAddress;
import java.util.LinkedHashMap;
import java.util.Map;

public class SnortFlowManager {
    private final Map<Tuple<InetAddress, InetAddress>, SnortFlow> stateMap = new LinkedHashMap<>();

    public void handle(PacketMetadata metadata) {
        Tuple<InetAddress, InetAddress> connection = new Tuple<>(metadata.getSrcAddr(), metadata.getDstAddr());
        SnortFlow currentFlow = stateMap.getOrDefault(connection, SnortFlow.UNKNOWN);
        metadata.setFlow(currentFlow);

        if (metadata.getTcpFlagSyn() && !metadata.getTcpFlagAck()) {
            metadata.setFlow(SnortFlow.SYN_RECEIVED);
        } else if (metadata.getTcpFlagSyn() && metadata.getTcpFlagAck()) {
            metadata.setFlow(SnortFlow.SYN_ACKED);
        } else if ((currentFlow == SnortFlow.SYN_ACKED || currentFlow == SnortFlow.SYN_RECEIVED) && metadata.getTcpFlagAck()) {
            metadata.setFlow(SnortFlow.ESTABLISHED);
        }
        stateMap.put(connection, metadata.getFlow());
    }
}
