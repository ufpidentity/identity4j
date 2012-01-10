package com.ufp.identity4j.truststore;

import java.security.KeyStore;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;

import java.io.InputStream;
import java.io.FileInputStream;

/** 
 * Builder to return Key Manager factory encapsulating the private key and certificate for client-authenticated TLS communication with the ufpIdentity service.
 */
public class KeyManagerFactoryBuilder extends AbstractFactoryBuilder {
    /**
     * Factory encapsulating the private key and certificate. Requires a PKCS12 file.
     */
    public KeyManagerFactory getKeyManagerFactory() throws Exception {
        char[] pass = passphrase.toCharArray();
 
        // First initialize the key material
        KeyStore ksKeys = KeyStore.getInstance("PKCS12");
        InputStream inputStream = new FileInputStream(store);
        ksKeys.load(inputStream, pass);
 
        // KeyManager's decide which key material to use
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ksKeys, pass);
        inputStream.close();
        return kmf;
    }
}