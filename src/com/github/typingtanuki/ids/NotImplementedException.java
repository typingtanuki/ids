package com.github.typingtanuki.ids;

public class NotImplementedException extends RuntimeException {
    public NotImplementedException() {
        super("Feature or method is not implemented");
    }
}
