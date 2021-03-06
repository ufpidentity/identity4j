package com.ufp.identity4j.resolver;

import java.net.URI;
import java.net.URISyntaxException;

import org.apache.log4j.Logger;

/**
 * An {@link IdentityResolver} that does no load balancing.
 */
public class  StaticIdentityResolver implements IdentityResolver {
    private static Logger logger = Logger.getLogger(StaticIdentityResolver.class);
    private URI uri = null;
    private String uriString;

    public StaticIdentityResolver() {
        this(null);
    }

    public StaticIdentityResolver(String uriString) {
        logger.debug("instantiating resolver with " + uriString);
        this.uriString = uriString;
    }

    public URI getNext() {
        if (uri == null) {
            try  {
                if (uriString == null)
                    uriString = "https://identity.ufp.com/identity-services/services/";
                uri = new URI(uriString);
            } catch (URISyntaxException use) {
                logger.error(use.getMessage(), use);
            }
        }
        return uri;
    }

    public void setUriString(String uriString) {
        this.uriString = uriString;
    }
}