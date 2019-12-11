package com.github.typingtanuki.ids.snort.port;

import com.github.typingtanuki.ids.exceptions.SnortException;
import com.github.typingtanuki.ids.snort.ParserUtils;

import static com.github.typingtanuki.ids.snort.ParserUtils.minMaxParser;

public class SnortPortMinMax extends SnortPort {
    private final ParserUtils.MinMaxValue minMax;

    public SnortPortMinMax(String s) throws SnortException {
        super();
        minMax = minMaxParser(s);
    }

    @Override
    public boolean matches(int packetPort) {
        return minMax.match(packetPort);
    }
}
