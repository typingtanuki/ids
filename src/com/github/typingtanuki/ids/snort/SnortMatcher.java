package com.github.typingtanuki.ids.snort;

import com.github.typingtanuki.ids.PacketMetadata;
import com.github.typingtanuki.ids.snort.flow.SnortFlowManager;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class SnortMatcher {
    private final Map<SnortProtocol, List<SnortRule>> rules;
    private final SnortFlowManager flowManager = new SnortFlowManager();

    public SnortMatcher(SnortParser parser) {
        rules = parser.getRules();
    }

    public List<SnortRule> match(PacketMetadata metadata) throws SnortException {
        flowManager.handle(metadata);

        SnortProtocol protocol = SnortProtocol.from(metadata.getProtocol());
        List<SnortRule> ruleList = rules.get(protocol);
        if (ruleList == null) {
            ruleList = rules.getOrDefault(SnortProtocol.all, new LinkedList<>());
        } else {
            ruleList.addAll(rules.getOrDefault(SnortProtocol.all, Collections.emptyList()));
        }
        if (ruleList == null) {
            return Collections.emptyList();
        }

        List<SnortRule> matched = new LinkedList<>();
        for (SnortRule rule : ruleList) {
            if (rule.match(metadata)) {
                matched.add(rule);
            }
        }
        return matched;
    }
}
