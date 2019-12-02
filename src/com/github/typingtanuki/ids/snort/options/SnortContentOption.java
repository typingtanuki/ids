package com.github.typingtanuki.ids.snort.options;

import com.github.typingtanuki.ids.PacketMetadata;
import com.github.typingtanuki.ids.utils.PeakableIterator;

import java.nio.charset.Charset;
import java.util.Locale;

/**
 * http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node32.html#SECTION00451000000000000000
 * <p>
 * The content keyword is one of the more important features of Snort. It allows the user to set rules that search for
 * specific content in the packet payload and trigger response based on that data. Whenever a content option pattern
 * match is performed, the Boyer-Moore pattern match function is called and the (rather computationally expensive) test
 * is performed against the packet contents. If data exactly matching the argument data string is contained anywhere
 * within the packet's payload, the test is successful and the remainder of the rule option tests are performed.
 * <p>
 * Be aware that this test is case sensitive.
 */
public class SnortContentOption extends SnortOption {
    private boolean caseSensitive = true;

    public SnortContentOption(String value) {
        super(SnortOptionType.content, value);
    }

    @Override
    public boolean match(PacketMetadata metadata, PeakableIterator<SnortOption> iter) {
        System.out.println("Partial implementation " + this);
        boolean hexa = false;
        byte[] data = metadata.getData();
        String hexaFirst = null;

        configure(iter);

        for (char c : value.toCharArray()) {
            if (c == '|') {
                hexa = !hexa;
            } else {
                if (!hexa) {
                    byte b = data[metadata.getPointerPos()];
                    metadata.setPointerPos(metadata.getPointerPos() + 1);

                    String varA = String.valueOf(c);
                    String varB = varA;

                    if (!caseSensitive) {
                        varA = varA.toLowerCase(Locale.ENGLISH);
                        varB = varB.toUpperCase(Locale.ENGLISH);
                    }

                    if (b != varA.getBytes(Charset.defaultCharset())[0] &&
                            b != varB.getBytes(Charset.defaultCharset())[0]) {
                        return false;
                    }
                } else {
                    if (hexaFirst == null) {
                        hexaFirst = String.valueOf(c);
                    } else {
                        String pair = hexaFirst + c;
                        hexaFirst = null;
                        int parsed = Integer.parseInt(pair, 16);
                        byte p = (byte) parsed;
                        byte b = data[metadata.getPointerPos()];
                        metadata.setPointerPos(metadata.getPointerPos() + 1);
                        if (b != p) {
                            return false;
                        }
                    }
                }
            }
        }
        return true;
    }

    private void configure(PeakableIterator<SnortOption> iter) {
        while (iter.hasNext()) {
            SnortOption candidate = iter.peak();
            switch (candidate.type) {
                case nocase:
                    iter.swallow();
                    this.caseSensitive = false;
                    break;
                default:
                    return;
            }
        }
    }
}
