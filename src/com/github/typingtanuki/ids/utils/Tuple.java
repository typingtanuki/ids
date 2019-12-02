package com.github.typingtanuki.ids.utils;

import java.util.Objects;

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

    @Override
    public String toString() {
        return "Tuple{" +
                "t=" + t +
                ", u=" + u +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Tuple<?, ?> tuple = (Tuple<?, ?>) o;
        return (Objects.equals(t, tuple.t) &&
                Objects.equals(u, tuple.u)) || (Objects.equals(u, tuple.t) &&
                Objects.equals(t, tuple.u));
    }

    @Override
    public int hashCode() {
        int a = Objects.hash(t);
        int b = Objects.hash(u);
        if (a < b) {
            return Objects.hash(t, u);
        } else {
            return Objects.hash(u, t);
        }
    }
}
