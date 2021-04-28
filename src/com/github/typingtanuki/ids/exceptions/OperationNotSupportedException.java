package com.github.typingtanuki.ids.exceptions;

import com.github.typingtanuki.ids.snort.SnortProtocol;
import org.pcap4j.packet.Packet;

/**
 * @author clerc
 * @since 2020/04/13
 */
public class OperationNotSupportedException extends Exception {
    private OperationNotSupportedException(String message, Throwable cause) {
        super(message, cause);
    }

    private OperationNotSupportedException(String message) {
        this(message, null);
    }


    public static OperationNotSupportedException noSourceAddress(SnortProtocol protocol) {
        return new OperationNotSupportedException("No source address for " + protocol);
    }

    public static OperationNotSupportedException noSourcePort(SnortProtocol protocol) {
        return new OperationNotSupportedException("No source port for " + protocol);
    }

    public static OperationNotSupportedException noDestinationAddress(SnortProtocol protocol) {
        return new OperationNotSupportedException("No destination address for " + protocol);
    }

    public static OperationNotSupportedException noDestinationPort(SnortProtocol protocol) {
        return new OperationNotSupportedException("No destination port for " + protocol);
    }

    public static OperationNotSupportedException noSubHandler(SnortProtocol protocol) {
        return new OperationNotSupportedException("No sub handler in " + protocol);
    }

    public static <T extends Packet> OperationNotSupportedException wrongSubHandlerType(SnortProtocol protocol,
                                                                                        Class<T> expect,
                                                                                        Class<?> current) {
        return new OperationNotSupportedException(
                "Wrong sub handler type in " + protocol +
                        " expected " + expect.getSimpleName() +
                        " got " + current.getSimpleName());
    }

}
