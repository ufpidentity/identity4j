package com.ufp.identity4j.resolver;

import java.net.URI;

/** 
 * A resolver gets a {@link URI} which SHOULD NOT be cached. The {@link URI} is used to make a connection to the Identity service
 */
public interface IdentityResolver {
    public URI getNext();
}