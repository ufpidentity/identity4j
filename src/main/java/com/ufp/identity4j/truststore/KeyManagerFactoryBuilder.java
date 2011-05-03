package com.ufp.identity4j.truststore;

import java.security.KeyStore;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;

import java.io.InputStream;
import java.io.FileInputStream;

public class KeyManagerFactoryBuilder extends AbstractFactoryBuilder {
    public KeyManagerFactory getKeyManagerFactory() throws Exception {
        char[] pass = passphrase.toCharArray();
 
	// First initialize the key material.
	KeyStore ksKeys = KeyStore.getInstance("PKCS12");
        InputStream inputStream = new FileInputStream(store);
	ksKeys.load(inputStream, pass);
 
	// KeyManager's decide which key material to use.
	KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
	kmf.init(ksKeys, pass);
        inputStream.close();
	return kmf;
    }
}