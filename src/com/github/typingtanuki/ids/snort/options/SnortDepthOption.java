package com.github.typingtanuki.ids.snort.options;

/**
 * http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node32.html#SECTION00457000000000000000
 * <p>
 * The depth keyword allows the rule writer to specify how far into a packet Snort should search for the specified
 * pattern. depth modifies the previous `content' keyword in the rule.
 */
public class SnortDepthOption extends NotImplementedSnortOption {
    public SnortDepthOption(String value) {
        super(SnortOptionType.depth, value);
    }
}
