package com.github.typingtanuki.ids.snort.options;

import com.github.typingtanuki.ids.PacketInfo;
import com.github.typingtanuki.ids.snort.ParserUtils;
import com.github.typingtanuki.ids.exceptions.SnortException;
import com.github.typingtanuki.ids.utils.PeakableIterator;
import org.pcap4j.packet.TransportPacket;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

import static com.github.typingtanuki.ids.snort.ParserUtils.minMaxParser;

/**
 * http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node32.html#SECTION004524000000000000000
 * <p>
 * The urilen keyword in the Snort rule language specifies the exact length, the minimum length, the maximum length,
 * or range of URI lengths to match. By default the raw uri buffer will be used. With the optional <uribuf> argument,
 * you can specify whether the raw or normalized buffer are used.
 */
public class SnortUriLenOption extends SnortOption {
    private final ParserUtils.MinMaxValue minMax;
    private boolean normalized = false;

    public SnortUriLenOption(String value) throws SnortException {
        super(SnortOptionType.urilen, value);

        String v = value;
        if (value.contains(",")) {
            String[] parts = v.split(",");
            if (parts.length != 2) {
                throw new SnortException("Too many commas in " + value);
            }
            v = parts[0];
            if ("norm".equalsIgnoreCase(parts[1])) {
                normalized = true;
            } else {
                throw new SnortException("Unknown type " + parts[1]);
            }
        }

        minMax = minMaxParser(v);
    }

    @Override
    public boolean match(PacketInfo packetInfo) throws SnortException {
        return tryMatch(packetInfo.fetchPacket(TransportPacket.class));
    }

    private boolean tryMatch(TransportPacket packet) throws SnortException {
        if (packet != null) {
            if (packet.getPayload() == null) {
                return false;
            }
            byte[] rawData = packet.getPayload().getRawData();
            CharsetDecoder decoder = StandardCharsets.US_ASCII.newDecoder();
            decoder.onUnmappableCharacter(CodingErrorAction.REPLACE);
            decoder.onMalformedInput(CodingErrorAction.IGNORE);
            try {
                CharBuffer chars = decoder.decode(ByteBuffer.wrap(rawData));
                System.out.println("###################");
                System.out.println(packet.getClass().getSimpleName());
                System.out.println(chars.toString());
                System.out.println("###################");
            } catch (CharacterCodingException e) {
                throw new SnortException("Could not read char", e);
            }
        }
        return false;
    }

    @Override
    public void finalize(PeakableIterator<SnortOption> iter) {
        // Nothing to do
    }
}
