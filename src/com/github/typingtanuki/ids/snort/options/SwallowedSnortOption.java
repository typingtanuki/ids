package com.github.typingtanuki.ids.snort.options;

import com.github.typingtanuki.ids.PacketMetadata;
import com.github.typingtanuki.ids.utils.PeakableIterator;

public class SwallowedSnortOption extends SnortOption {
    protected SwallowedSnortOption(SnortOptionType type, String value) {
        super(type, value);
    }

    @Override
    public final boolean match(PacketMetadata metadata) {
        throw new IllegalStateException("Must have been already handled");
    }

    @Override
    public final void finalize(PeakableIterator<SnortOption> iter) {
        throw new IllegalStateException("Must have been already handled");
    }
}
