package com.github.typingtanuki.ids;

import com.github.typingtanuki.ids.snort.SnortException;
import com.github.typingtanuki.ids.snort.SnortMatcher;
import com.github.typingtanuki.ids.snort.SnortParser;

import java.nio.file.Paths;

public class Main {

    public static void main(String[] args) {
        SnortParser snort = new SnortParser();
        try {
            snort.parse(Paths.get("snort.txt"));
        } catch (SnortException e) {
            e.printStackTrace();
            System.exit(12);
        }

        Ids ids = new Ids(new SnortMatcher(snort));
        ids.start();
        try {
            ids.join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
