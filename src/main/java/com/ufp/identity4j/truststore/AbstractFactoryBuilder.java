package com.ufp.identity4j.truststore;

import java.io.File;

public abstract class AbstractFactoryBuilder {
    protected File store;
    protected String passphrase;

    public void setStore(File store) {
        this.store = store;
    }

    public void setPassphrase(String passphrase) {
        this.passphrase = passphrase;
    }
}
