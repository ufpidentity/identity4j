package com.ufp.identity4j.truststore;

import java.security.KeyStore;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManager;

import java.io.InputStream;
import java.io.FileInputStream;

import org.apache.log4j.Logger;

/** 
 * Builder to return Trust Manager factory encapsulating the trust store. ufpIdentity requires a closed truststore. Make absolutely sure you
 * are only using ufpIdentity public certificates. 
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