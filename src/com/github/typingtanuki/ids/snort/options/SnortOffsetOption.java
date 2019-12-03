package com.github.typingtanuki.ids.snort.options;

import com.github.typingtanuki.ids.snort.SnortException;

/**
 * http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node32.html#SECTION00458000000000000000
 * <p>
 * <p>
 * The offset keyword allows the rule writer to specify where to start searching for a pattern within a packet.
 * offset modifies the previous 'content' keyword in the rule.
 */
public class SnortOffsetOption extends SwallowedSnortOption {
    private final int offset;

    public SnortOffsetOption(String value) throws SnortException {
        super(SnortOptionType.offset, value);
        this.offset = parseOffset(value);
    }

    private static int parseOffset(String value) throws SnortException {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new SnortException("Illegal offset " + value, e);
        }
    }

    public int getOffset() {
        return offset;
    }
}
