package com.ufp.identity4j.truststore;

import java.security.KeyStore;

import javax.net.ssl.TrustManagerFactory;

import java.io.InputStream;
import java.io.FileInputStream;

public class TrustManagerFactoryBuilder extends AbstractFactoryBuilder {
    public TrustManagerFactory getTrustManagerFactory() throws Exception {
	char[] pass = passphrase.toCharArray();

	// First initialize the trust material.
	KeyStore ksTrust = KeyStore.getInstance("JKS");
        InputStream inputStream = new FileInputStream(store);
	ksTrust.load(inputStream, pass);
 
	// TrustManager's decide whether to allow connections.
	TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
	tmf.init(ksTrust);
        inputStream.close();
	return tmf;
    }
}
