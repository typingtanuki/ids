package com.github.typingtanuki.ids.snort.options;

/**
 * http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node32.html#SECTION00459000000000000000
 * <p>
 * The distance keyword allows the rule writer to specify how far into a packet Snort should ignore before starting to
 * search for the specified pattern relative to the end of the previous pattern match.
 */
public class SnortDistanceOption extends NotImplementedSnortOption {
    public SnortDistanceOption(String value) {
        super(SnortOptionType.distance, value);
    }
}
