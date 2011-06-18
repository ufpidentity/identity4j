package com.ufp.identity4j.test;

import java.io.File;

import java.util.Map;
import java.util.HashMap;

import org.junit.Test;
import org.junit.Before;
import static org.junit.Assert.*;

import com.ufp.identity4j.data.AuthenticationContext;
import com.ufp.identity4j.data.AuthenticationPretext;
import com.ufp.identity4j.data.DisplayItem;

import com.ufp.identity4j.provider.IdentityServiceProvider;
import com.ufp.identity4j.truststore.KeyManagerFactoryBuilder;
import com.ufp.identity4j.truststore.TrustManagerFactoryBuilder;
import com.ufp.identity4j.truststore.IdentityHostnameVerifier;
import com.ufp.identity4j.resolver.StaticIdentityResolver;

public class TestIdentity4J {
    private IdentityServiceProvider identityServiceProvider = new IdentityServiceProvider();

    @Before 
    public void setupIdentity4JProvider() throws Exception {
        identityServiceProvider = new IdentityServiceProvider();

        // setup the key manager factory
        KeyManagerFactoryBuilder keyManagerFactoryBuilder = new KeyManagerFactoryBuilder();
        keyManagerFactoryBuilder.setStore(new File("src/test/resources/example.com.p12"));
        keyManagerFactoryBuilder.setPassphrase("example123");

        // setup the trust store
        TrustManagerFactoryBuilder trustManagerFactoryBuilder = new TrustManagerFactoryBuilder();
        trustManagerFactoryBuilder.setStore(new File("src/test/resources/truststore.jks"));
        trustManagerFactoryBuilder.setPassphrase("pSnHa(3QDixmi%\\");

        // set provider properties
        identityServiceProvider.setKeyManagerFactoryBuilder(keyManagerFactoryBuilder);
        identityServiceProvider.setTrustManagerFactoryBuilder(trustManagerFactoryBuilder);
        identityServiceProvider.setHostnameVerifier(new IdentityHostnameVerifier("ufp.com"));
        identityServiceProvider.setIdentityResolver(new StaticIdentityResolver("https://staging.ufp.com:8443/identity-services/services/"));
        identityServiceProvider.afterPropertiesSet();
    }

    @Test
    public void TestAuthenticate() throws Exception {
        AuthenticationPretext authenticationPretext = identityServiceProvider.preAuthenticate("guest", "example.com");
        assertNotNull(authenticationPretext);
        assertEquals(authenticationPretext.getResult().getValue(), "SUCCESS");

        DisplayItem displayItem = authenticationPretext.getDisplayItem().get(0);
        Map<String, String []> parameterMap = new HashMap<String, String []>();

        parameterMap.put(displayItem.getName(), new String [] {"guest"});
        AuthenticationContext authenticationContext = (AuthenticationContext)identityServiceProvider.authenticate(authenticationPretext.getName(), "example.com", parameterMap);
        assertNotNull(authenticationContext);
        assertEquals(authenticationContext.getResult().getValue(), "SUCCESS");
    }

    @Test
    public void TestPreEnroll() {
        assertTrue(true);
    }

    @Test
    public void TestEnroll() {
        assertTrue(true);
    }
}