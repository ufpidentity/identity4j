package com.ufp.identity4j.truststore;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

import org.apache.log4j.Logger;

/**
 * Custom hostname verifier to allow for any ufp.com services host to validate.
 */
public class IdentityHostnameVerifier implements HostnameVerifier {
    private static Logger logger = Logger.getLogger(IdentityHostnameVerifier.class);
    private static String DEFAULT_HOSTNAME = "ufp.com";

    private String hostnameToVerify;

    public IdentityHostnameVerifier() {
        this(DEFAULT_HOSTNAME);
    }

    public IdentityHostnameVerifier(String hostnameToVerify) {
        logger.debug("instantiating verifier with " + hostnameToVerify);
        this.hostnameToVerify = hostnameToVerify;
    }

    public boolean verify(String hostname, SSLSession session) {
        logger.debug("verifying hostname " + hostname + " peer hostname " + session.getPeerHost() + " against " + hostnameToVerify);
        return hostname.endsWith(hostnameToVerify);
    }

    public void setHostnameToVerify(String hostnameToVerify) {
        this.hostnameToVerify = hostnameToVerify;
    }
}