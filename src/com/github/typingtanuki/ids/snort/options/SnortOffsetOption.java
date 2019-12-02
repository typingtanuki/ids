package com.github.typingtanuki.ids.snort.options;

/**
 * http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node32.html#SECTION00458000000000000000
 * <p>
 * <p>
 * The offset keyword allows the rule writer to specify where to start searching for a pattern within a packet.
 * offset modifies the previous 'content' keyword in the rule.
 */
public class SnortOffsetOption extends NotImplementedSnortOption {
    public SnortOffsetOption(String value) {
        super(SnortOptionType.offset, value);
    }
}
