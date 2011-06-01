package com.ufp.identity4j.truststore;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

import org.apache.log4j.Logger;

/**
 * A {@link HostnameVerifier} that verifies host {@link String#startsWith(String)} &quot;localhost.&quot; For development/testing only
 * 
 * @pad.exclude
 */
public class LocalHostnameVerifier implements HostnameVerifier {
    private static Logger logger = Logger.getLogger(LocalHostnameVerifier.class);

    public boolean verify(String hostname, SSLSession session) {
	logger.debug("verifying hostname " + hostname + " peer hostname " + session.getPeerHost());
        return hostname.startsWith("localhost");
    }
}
