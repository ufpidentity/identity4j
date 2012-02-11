package com.ufp.identity4j.truststore;

import java.security.KeyStore;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;

import java.io.InputStream;
import java.io.FileInputStream;

/** 
 * Builder to return Key Manager factory encapsulating the private key
 * and certificate for client-authenticated TLS communication with the
 * ufpIdentity service.  The KeyManagerFactoryBuilder requires a
 * PKCS12 file. The PKCS12 file contains the certificate returned from
 * ufpIdentity along with your private key. The PKCS12 export password
 * must be the same as the password for your private key.
 * <h4>Creating a PKCS12 file with your ufpIdentity certificate and private key</h4>
 *
 * <pre>
 * openssl pkcs12 -export -in magrathea.com.crt.pem -inkey magrathea.com.key.pem -out magrathea.com.p12 -name magrathea.com 
 * </pre>
 */
public class KeyManagerFactoryBuilder extends AbstractFactoryBuilder {
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