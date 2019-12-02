package com.github.typingtanuki.ids.snort.options;

/**
 * http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node32.html#SECTION004526000000000000000
 * <p>
 * <p>
 * The pcre keyword allows rules to be written using perl compatible regular expressions.
 * For more detail on what can be done via a pcre regular expression, check out the PCRE web site http://www.pcre.org
 */
public class SnortPcreOption extends NotImplementedSnortOption {
    public SnortPcreOption(String value) {
        super(SnortOptionType.pcre, value);
    }
}
