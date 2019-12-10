package com.github.typingtanuki.ids.snort.options;

import com.github.typingtanuki.ids.PacketInfo;
import com.github.typingtanuki.ids.utils.PeakableIterator;

public class SwallowedSnortOption extends SnortOption {
    protected SwallowedSnortOption(SnortOptionType type, String value) {
        super(type, value);
    }

    @Override
    public final boolean match(PacketInfo packetInfo) {
        throw new IllegalStateException("Must have been already handled");
    }

    @Override
    public final void finalize(PeakableIterator<SnortOption> iter) {
        throw new IllegalStateException("Must have been already handled");
    }
}
