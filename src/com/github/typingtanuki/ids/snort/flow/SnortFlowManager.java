package com.github.typingtanuki.ids.snort.flow;

import com.github.typingtanuki.ids.PacketMetadata;
import com.github.typingtanuki.ids.snort.SnortException;
import com.github.typingtanuki.ids.utils.Tuple;
import org.pcap4j.packet.TcpPacket;

import java.net.InetAddress;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

public class SnortFlowManager {
    private final Map<Tuple<InetAddress, InetAddress>, SnortFlow> stateMap = new LinkedHashMap<>();
    private final Map<Tuple<InetAddress, InetAddress>, Map<String, Boolean>> flowbits = new LinkedHashMap<>();
    private final Map<Tuple<InetAddress, InetAddress>, InetAddress> serverIdentity = new LinkedHashMap<>();

    public void handle(PacketMetadata metadata) throws SnortException {
        Tuple<InetAddress, InetAddress> connection = new Tuple<>(metadata.getSrcAddr(), metadata.getDstAddr());
        SnortFlow currentFlow = stateMap.getOrDefault(connection, SnortFlow.UNKNOWN);
        InetAddress identity = serverIdentity.getOrDefault(connection, null);
        metadata.setFlow(currentFlow);
        metadata.setServer(identity);
        metadata.setFlowManager(this);

        switch (metadata.protocol()) {
            case tcp:

                TcpPacket.TcpHeader tcpHeader = metadata.getTcpHeader();
                if (tcpHeader.getSyn() && !tcpHeader.getAck()) {
                    metadata.setFlow(SnortFlow.SYN_RECEIVED);
                    serverIdentity.put(connection, metadata.getDstAddr());
                    flowbits.put(connection, new HashMap<>());
                } else if (tcpHeader.getSyn()) {
                    metadata.setFlow(SnortFlow.SYN_ACKED);
                    serverIdentity.put(connection, metadata.getSrcAddr());
                    if (!flowbits.containsKey(connection)) {
                        flowbits.put(connection, new HashMap<>());
                    }
                } else if ((currentFlow == SnortFlow.SYN_ACKED || currentFlow == SnortFlow.SYN_RECEIVED) && tcpHeader.getAck()) {
                    metadata.setFlow(SnortFlow.ESTABLISHED);
                    serverIdentity.put(connection, metadata.getDstAddr());
                    if (!flowbits.containsKey(connection)) {
                        flowbits.put(connection, new HashMap<>());
                    }
                } else if (tcpHeader.getFin()) {
                    metadata.setFlow(SnortFlow.FINISHED);
                    flowbits.remove(connection);
                }
                break;
        }
        stateMap.put(connection, metadata.getFlow());
        metadata.setFlowbits(flowbits.get(connection));
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
