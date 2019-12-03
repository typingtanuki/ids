package com.github.typingtanuki.ids.snort.options;

import com.github.typingtanuki.ids.snort.SnortException;

/**
 * http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node32.html#SECTION004510000000000000000
 * <p>
 * The within keyword is a content modifier that makes sure that at most N bytes are between pattern matches using the
 * content keyword ( See Section [*] ). It's designed to be used in conjunction with the distance (Section [*])
 * rule option.
 */
public class SnortWithinOption extends SwallowedSnortOption {
    private final int within;

    public SnortWithinOption(String value) throws SnortException {
        super(SnortOptionType.within, value);
        this.within = parseWithin(value);
    }

    private static int parseWithin(String value) throws SnortException {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new SnortException("Illegal distance " + value, e);
        }
    }

    public int getWithin() {
        return within;
    }
}
