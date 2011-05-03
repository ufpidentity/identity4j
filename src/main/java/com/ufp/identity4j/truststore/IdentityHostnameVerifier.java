package com.ufp.identity4j.truststore;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

import org.apache.log4j.Logger;

public class IdentityHostnameVerifier implements HostnameVerifier {
    private static Logger logger = Logger.getLogger(IdentityHostnameVerifier.class);

    public boolean verify(String hostname, SSLSession session) {
	logger.debug("verifying hostname " + hostname + " peer hostname " + session.getPeerHost());
        return hostname.endsWith("ufp.com");
    }
}
