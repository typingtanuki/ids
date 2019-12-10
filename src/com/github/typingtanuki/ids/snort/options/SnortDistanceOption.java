package com.github.typingtanuki.ids.snort.options;

import com.github.typingtanuki.ids.exceptions.SnortException;

/**
 * http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node32.html#SECTION00459000000000000000
 * <p>
 * The distance keyword allows the rule writer to specify how far into a packet Snort should ignore before starting to
 * search for the specified pattern relative to the end of the previous pattern match.
 */
public class SnortDistanceOption extends SwallowedSnortOption {
    private final int distance;

    public SnortDistanceOption(String value) throws SnortException {
        super(SnortOptionType.distance, value);
        this.distance = parseDistance(value);
    }

    private static int parseDistance(String value) throws SnortException {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new SnortException("Illegal distance " + value, e);
        }
    }

    public int getDistance() {
        return distance;
    }
}
