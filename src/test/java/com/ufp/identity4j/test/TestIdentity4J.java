package com.ufp.identity4j.test;

import java.io.File;

import java.net.InetAddress;

import java.util.Enumeration;
import java.util.Map;
import java.util.HashMap;

import org.junit.Test;
import org.junit.BeforeClass;
import static org.junit.Assert.*;

import org.springframework.mock.web.MockHttpServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.servlet.http.Cookie;

import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.ClientResponse.Status;

import com.ufp.identity4j.data.AuthenticationContext;
import com.ufp.identity4j.data.AuthenticationPretext;
import com.ufp.identity4j.data.DisplayItem;

import com.ufp.identity4j.provider.IdentityServiceProvider;
import com.ufp.identity4j.truststore.KeyManagerFactoryBuilder;
import com.ufp.identity4j.truststore.TrustManagerFactoryBuilder;
import com.ufp.identity4j.truststore.IdentityHostnameVerifier;
import com.ufp.identity4j.resolver.StaticIdentityResolver;

import org.apache.log4j.Logger;

public class TestIdentity4J {
    private static IdentityServiceProvider identityServiceProvider;
    private static Logger logger = Logger.getLogger(TestIdentity4J.class);

    @BeforeClass
    public static void setupIdentity4JProvider() throws Exception {
        identityServiceProvider = new IdentityServiceProvider();
        // setup the key manager factory
        KeyManagerFactoryBuilder keyManagerFactoryBuilder = new KeyManagerFactoryBuilder();
        keyManagerFactoryBuilder.setStore(new File("src/test/resources/example.com.p12"));
        keyManagerFactoryBuilder.setPassphrase("test");

        // setup the trust store
        TrustManagerFactoryBuilder trustManagerFactoryBuilder = new TrustManagerFactoryBuilder();
        trustManagerFactoryBuilder.setStore(new File("src/test/resources/truststore.jks"));
        trustManagerFactoryBuilder.setPassphrase("pSnHa(3QDixmi%\\");

        // set provider properties
        identityServiceProvider.setKeyManagerFactoryBuilder(keyManagerFactoryBuilder);
        identityServiceProvider.setTrustManagerFactoryBuilder(trustManagerFactoryBuilder);

        identityServiceProvider.setHostnameVerifier(new IdentityHostnameVerifier("ufp.com"));
        identityServiceProvider.setIdentityResolver(new StaticIdentityResolver("https://identity.ufp.com/identity-services/services/"));
        // must call this
        identityServiceProvider.afterPropertiesSet();
    }

    @Test
    public void TestAuthenticate() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest();
        AuthenticationPretext authenticationPretext = identityServiceProvider.preAuthenticate("guest", mockHttpServletRequest);
        assertNotNull(authenticationPretext);
        assertEquals("SUCCESS", authenticationPretext.getResult().getValue());
        HttpSession httpSession = mockHttpServletRequest.getSession(false);
        assertNotNull(httpSession);
        String sessionId = null;

        if (httpSession != null) {
            logger.debug("session has id " + httpSession.getId());
            for (Enumeration<String> e = httpSession.getAttributeNames(); e.hasMoreElements();) {
                String attribute = e.nextElement();
                logger.debug("attribute " + attribute + " has value " + httpSession.getAttribute(attribute).toString());
            }
            sessionId = (String)httpSession.getAttribute(IdentityServiceProvider.IDENTITY_SESSION);
            assertNotNull(sessionId);
        }
        mockHttpServletRequest = new MockHttpServletRequest();
        mockHttpServletRequest.getSession().setAttribute(IdentityServiceProvider.IDENTITY_SESSION, sessionId);
        assertEquals(1, authenticationPretext.getDisplayItem().size());
        DisplayItem displayItem = authenticationPretext.getDisplayItem().get(0);
        Map<String, String []> parameterMap = new HashMap<String, String []>();

        parameterMap.put(displayItem.getName(), new String [] {"guest"});
        AuthenticationContext authenticationContext = (AuthenticationContext)identityServiceProvider.authenticate(authenticationPretext.getName(), mockHttpServletRequest, parameterMap);
        assertNotNull(authenticationContext);
        assertEquals("SUCCESS", authenticationContext.getResult().getValue());
        logger.debug("found confidence of " + authenticationContext.getResult().getConfidence());
        assertEquals(0.00d, authenticationContext.getResult().getConfidence(), 0.10d);
    }

    @Test
    public void TestAuthenticateNoSession() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest();
        AuthenticationPretext authenticationPretext = identityServiceProvider.preAuthenticate("guest", mockHttpServletRequest);
        assertNotNull(authenticationPretext);
        assertEquals("SUCCESS", authenticationPretext.getResult().getValue());

        mockHttpServletRequest = new MockHttpServletRequest();
        assertEquals(1, authenticationPretext.getDisplayItem().size());
        DisplayItem displayItem = authenticationPretext.getDisplayItem().get(0);
        Map<String, String []> parameterMap = new HashMap<String, String []>();

        parameterMap.put(displayItem.getName(), new String [] {"guest"});
        AuthenticationContext authenticationContext = (AuthenticationContext)identityServiceProvider.authenticate(authenticationPretext.getName(), mockHttpServletRequest, parameterMap);
        assertNotNull(authenticationContext);
        assertNotNull(mockHttpServletRequest.getSession(false));
        assertNotNull(mockHttpServletRequest.getSession(false).getAttribute(IdentityServiceProvider.IDENTITY_SESSION));
        assertEquals("SUCCESS", authenticationContext.getResult().getValue());
        logger.debug("found confidence of " + authenticationContext.getResult().getConfidence());
        assertEquals(0.00d, authenticationContext.getResult().getConfidence(), 0.10d);
    }
}