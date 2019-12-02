package com.github.typingtanuki.ids.snort.options;

/**
 * http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node32.html#SECTION004524000000000000000
 * <p>
 * The urilen keyword in the Snort rule language specifies the exact length, the minimum length, the maximum length,
 * or range of URI lengths to match. By default the raw uri buffer will be used. With the optional <uribuf> argument,
 * you can specify whether the raw or normalized buffer are used.
 */
public class SnortUriLenOption extends NotImplementedSnortOption {
    public SnortUriLenOption(String value) {
        super(SnortOptionType.urilen, value);
    }
}
