package com.github.typingtanuki.ids.utils;

public class Tuple<T, U> {
    private T t;
    private U u;

    public Tuple(T t, U u) {
        this.t = t;
        this.u = u;
    }

    public T getT() {
        return t;
    }

    public U getU() {
        return u;
    }

    public void setT(T t) {
        this.t = t;
    }

    public void setU(U u) {
        this.u = u;
    }
}
