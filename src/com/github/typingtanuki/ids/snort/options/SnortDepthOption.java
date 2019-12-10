package com.github.typingtanuki.ids.snort.options;

import com.github.typingtanuki.ids.exceptions.SnortException;

/**
 * http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node32.html#SECTION00457000000000000000
 * <p>
 * The depth keyword allows the rule writer to specify how far into a packet Snort should search for the specified
 * pattern. depth modifies the previous `content' keyword in the rule.
 */
public class SnortDepthOption extends SwallowedSnortOption {
    private final int depth;

    public SnortDepthOption(String value) throws SnortException {
        super(SnortOptionType.depth, value);
        this.depth = parseDepth(value);
    }

    private static int parseDepth(String value) throws SnortException {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new SnortException("Illegal depth " + value, e);
        }
    }

    public int getDepth() {
        return depth;
    }
}
