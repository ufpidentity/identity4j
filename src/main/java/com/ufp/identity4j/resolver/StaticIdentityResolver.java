package com.ufp.identity4j.resolver;

import java.net.URI;
import java.net.URISyntaxException;

import org.apache.log4j.Logger;

/**
 * An {@link IdentityResolver} that does no load balancing. Suitable for low-volume authentication requirements
 */
public class  StaticIdentityResolver implements IdentityResolver {
    private static Logger logger = Logger.getLogger(StaticIdentityResolver.class);
    private URI uri = null;

    public URI getNext() {
        if (uri == null) {
            try  {
                uri = new URI("https://identity.ufp.com:8443/identity-services/");
            } catch (URISyntaxException use) {
                logger.error(use.getMessage(), use);
            }
        }
        return uri;
    }
}