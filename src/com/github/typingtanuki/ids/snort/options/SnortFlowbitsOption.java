package com.github.typingtanuki.ids.snort.options;

import com.github.typingtanuki.ids.exceptions.NotImplementedException;
import com.github.typingtanuki.ids.PacketInfo;
import com.github.typingtanuki.ids.exceptions.SnortException;
import com.github.typingtanuki.ids.utils.PeakableIterator;

/**
 * http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node33.html#SECTION004610000000000000000
 * <p>
 * The flowbits keyword is used in conjunction with conversation tracking from the Session preprocessor (see Section[*]).
 * It allows rules to track states during a transport protocol session. The flowbits option is most useful for TCP
 * sessions, as it allows rules to generically track the state of an application protocol.
 */
public class SnortFlowbitsOption extends SnortOption {
    private final FlowbitAction action;
    private final String variable;

    public SnortFlowbitsOption(String value) throws SnortException {
        super(SnortOptionType.flowbits, value);

        String[] parts = value.split(",");
        try {
            action = FlowbitAction.valueOf(parts[0]);
        } catch (IllegalArgumentException e) {
            throw new SnortException("Unknown flowbit type for " + value, e);
        }
        if (parts.length > 1) {
            variable = parts[1];
        } else {
            variable = null;
        }
        if (parts.length > 2) {
            throw new SnortException("Unsupport flowbit format " + value);
        }

        if (action != FlowbitAction.noalert && variable == null) {
            throw new SnortException("Missing variable for " + value);
        }
    }

    @Override
    public boolean match(PacketInfo packetInfo) throws SnortException {
        switch (action) {
            case set:
                packetInfo.putFlowbit(variable);
                return true;
            case isset:
                return packetInfo.readFlowbit(variable);
            case unset:
                packetInfo.dropFlowbit(variable);
                return true;
            case toggle:
                if (packetInfo.readFlowbit(variable)) {
                    packetInfo.dropFlowbit(variable);
                } else {
                    packetInfo.putFlowbit(variable);
                }
                return true;
            case noalert:
                throw new NotImplementedException("Alerting is not implemented");
            case isnotset:
                return !packetInfo.readFlowbit(variable);
        }
        throw new SnortException("Unknown flowbit action " + action);
    }

    @Override
    public void finalize(PeakableIterator<SnortOption> iter) {
        // Nothing to do
    }
}
