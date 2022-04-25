package com.datapipe.jenkins.vault.credentials;

import java.io.Serializable;
import java.util.function.Supplier;

public class Snapshot<T> implements Supplier<T>, Serializable {

    private static final long serialVersionUID = 1L;

    private final T value;

    public Snapshot(T value) {
        this.value = value;
    }

    @Override
    public T get() {
        return value;
    }
}

