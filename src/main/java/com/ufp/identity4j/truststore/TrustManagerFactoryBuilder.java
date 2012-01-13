package com.ufp.identity4j.truststore;

import java.security.KeyStore;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManager;

import java.io.InputStream;
import java.io.FileInputStream;

import org.apache.log4j.Logger;

/** 
 * Builder to return Trust Manager factory encapsulating the trust store. ufpIdentity requires a closed truststore. Make absolutely sure you
 * are only using ufpIdentity public certificates. It is highly
 * recommended that you acquire the ufpIdentity certificates, verify them against published fingerprints and create your own secure truststore.
 * <h4>Creating a keystore with ufpIdentity certificates</h4>
 * <p>Due to the way keytool works, the procedure for creating a truststore consists of generating a new keystore, containing a dummy keychain, deleting the dummy keychain and then adding the certificates.<p>
 * <ol>
 * <li>Create the new keystore with dummy keychain</li>
 * <pre>
 * keytool -genkey -alias dummy -keyalg RSA -keystore truststore.jks
 * </pre>
 * <li>Delete the alias dummy, to have an empty trust-store</li>
 * <pre>
 * keytool -delete -alias dummy -keystore truststore.jks
 * </pre>
 * <li>Import ufpIdentity certificates that you have verified by fingerprint</li>
 * <pre>
 * keytool -import -v -trustcacerts -alias my_ca -file public/ca.crt -keystore truststore.jks
 * </pre>
 * <li>Check your truststore</li>
 * <pre>
 * keytool -v -list -keystore truststore.jks
 * </pre>
 *</ol>
 */
public class TrustManagerFactoryBuilder extends AbstractFactoryBuilder {
    private static Logger logger = Logger.getLogger(TrustManagerFactoryBuilder.class);

    /**
     * Factory encapsulating the trust store in use. Requires a java keystore file containing only ufpIdentity public certificates.
     */
    public TrustManagerFactory getTrustManagerFactory() throws Exception {
        char[] pass = passphrase.toCharArray();

        // First initialize the trust material
        KeyStore ksTrust = KeyStore.getInstance("JKS");
        InputStream inputStream = new FileInputStream(store);
        logger.debug("loading KeyStore");
        ksTrust.load(inputStream, pass);
 
        // TrustManager's decide whether to allow connections
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
        logger.debug("TrustManangerFactory init " + tmf.toString());
        tmf.init(ksTrust);

        TrustManager tms [] = tmf.getTrustManagers();  
        logger.debug("found " + tms.length + " trustManager(s)");
        /* 
         * Iterate over the returned trustmanagers, look 
         * for an instance of X509TrustManager.  If found, 
         * use that as our "default" trust manager. 
         */  
        for (int i = 0; i < tms.length; i++) {  
            logger.debug("[" + i + "] " + tms[i].toString());
        }  
        inputStream.close();
        return tmf;
    }
}