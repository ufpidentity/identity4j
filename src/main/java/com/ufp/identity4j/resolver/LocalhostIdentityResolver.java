package com.ufp.identity4j.resolver;

import java.net.URI;
import java.net.URISyntaxException;

import org.apache.log4j.Logger;

/**
 * An {@link IdentityResolver} that returns the service running locally (localhost). For development/testing only
 * @pad.exclude
 */
public class  LocalhostIdentityResolver implements IdentityResolver {
    private static Logger logger = Logger.getLogger(LocalhostIdentityResolver.class);

    public URI getNext() {
        URI uri = null;
        try  {
            uri = new URI("https://localhost:8443/identity-services/services/");
        } catch (URISyntaxException use) {
            logger.error(use.getMessage(), use);
        }
        return uri;
    }
}