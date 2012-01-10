package com.ufp.identity4j.provider;

import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;

import java.util.List;
import java.util.Map;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;

import javax.net.ssl.SSLContext;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.HttpsURLConnection;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.MediaType;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.config.ClientConfig;
import com.sun.jersey.api.client.config.DefaultClientConfig;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.client.urlconnection.HTTPSProperties;
import com.sun.jersey.core.util.MultivaluedMapImpl;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.ClientResponse.Status;
import com.sun.jersey.api.client.UniformInterfaceException;

import com.ufp.identity4j.data.AuthenticationPretext;
import com.ufp.identity4j.data.AuthenticationContext;
import com.ufp.identity4j.data.EnrollmentContext;
import com.ufp.identity4j.data.EnrollmentPretext;

import com.ufp.identity4j.resolver.IdentityResolver;
import com.ufp.identity4j.resolver.StaticIdentityResolver;

import com.ufp.identity4j.service.IdentityServiceException;

import com.ufp.identity4j.truststore.IdentityHostnameVerifier;
import com.ufp.identity4j.truststore.KeyManagerFactoryBuilder;
import com.ufp.identity4j.truststore.TrustManagerFactoryBuilder;

import org.apache.log4j.Logger;

/**
 * The Identity service provider does a direct interaction with the
 * Identity service. Data objects specific to the service are returned
 * in a generic way to allow for a wide variety of integrations.
 * <p>
 * Enroll is typically very specific to an integration. We will provide a custom enrollment to address your needs.
 * The enrollment methods below are generic enough to handle most any type of custom needs. Generally {@link #enroll} handles situations where
 * the user does not exist (create and import). {@link #reEnroll} handles situations where the user already exists (update, delete).
 * <p>
 * The specific elements of the parameters argument(s) are determined by your custom enrollment needs.
 */
public class IdentityServiceProvider {
    private static Logger logger = Logger.getLogger(IdentityServiceProvider.class);

    private static Client client;
    private IdentityResolver identityResolver;
    private HostnameVerifier hostnameVerifier;
    private TrustManagerFactoryBuilder trustManagerFactoryBuilder;
    private KeyManagerFactoryBuilder keyManagerFactoryBuilder;

    /**
     * Handle setup and default injection(s) if nothing was explicitly set. This method must be called after setting the necessary properties and
     * before using any further methods.
     * <p>
     * Will set a default {@link IdentityResolver} and a default {@link HostnameVerifier} suitable for most integrations.
     * <p>
     * Methods are available to explicitly set (or have dependencies
     * injected) the {@link IdentityResolver} and {@link HostnameVerifier}.
     * <p>
     * n. b. No {@link TrustManagerFactoryBuilder} or {@link  KeyManagerFactoryBuilder} are set by default. These objects are
     * specific to integrations and must be either explicitly
     * dependency injected or set using {@link #setTrustManagerFactoryBuilder(TrustManagerFactoryBuilder)} and
     * {@link #setKeyManagerFactoryBuilder(KeyManagerFactoryBuilder)}.
     * <p>
     * An example of how the IdentityServiceProvider would be setup:
     * <pre>
     *  IdentityServiceProvider identityServiceProvider = new IdentityServiceProvider();
     *
     *  // setup the key manager factory
     *  KeyManagerFactoryBuilder keyManagerFactoryBuilder = new KeyManagerFactoryBuilder();
     *  keyManagerFactoryBuilder.setStore(new File("example.com.p12"));
     *  keyManagerFactoryBuilder.setPassphrase("super_secret_password");
     *
     *  // setup the trust store
     *  TrustManagerFactoryBuilder trustManagerFactoryBuilder = new TrustManagerFactoryBuilder();
     *  trustManagerFactoryBuilder.setStore(new File("truststore.jks"));
     *  trustManagerFactoryBuilder.setPassphrase("truststore_password");

     *  // set provider properties
     *  identityServiceProvider.setKeyManagerFactoryBuilder(keyManagerFactoryBuilder);
     *  identityServiceProvider.setTrustManagerFactoryBuilder(trustManagerFactoryBuilder);
     *  identityServiceProvider.afterPropertiesSet();
     * </pre>
     */
    public void afterPropertiesSet() {
        if (identityResolver == null)
            identityResolver = new StaticIdentityResolver();
        if (hostnameVerifier == null) 
            hostnameVerifier = new IdentityHostnameVerifier();
        try {
            ClientConfig clientConfig = new DefaultClientConfig();
            SSLContext sslContext = SSLContext.getInstance("TLSv1");
            logger.debug("getting trustManagerFactory");
            TrustManagerFactory trustManagerFactory = trustManagerFactoryBuilder.getTrustManagerFactory();
            TrustManager tms [] = trustManagerFactory.getTrustManagers();  
   
            logger.debug("found " + tms.length + " trustManager(s)");
            /* 
             * Iterate over the returned trustmanagers, look 
             * for an instance of X509TrustManager.  If found, 
             * use that as our "default" trust manager. 
             */  
            for (int i = 0; i < tms.length; i++) {  
                logger.debug("[" + i + "] " + tms[i].toString());
            }  

            sslContext.init(keyManagerFactoryBuilder.getKeyManagerFactory().getKeyManagers(), tms, null);
            HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
            clientConfig.getProperties().put(HTTPSProperties.PROPERTY_HTTPS_PROPERTIES, new HTTPSProperties(hostnameVerifier, sslContext));
            client = Client.create(clientConfig);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        }
    }

    private MultivaluedMap getQueryParams(String name, String clientIp, Map<String, String[]> additionalParams) {
        MultivaluedMap queryParams = new MultivaluedMapImpl();
        queryParams.add("name", name);
        queryParams.add("client_ip", clientIp);
        if (additionalParams != null) {
            for (String key : additionalParams.keySet()) {
                String [] values = additionalParams.get(key);
                for (String value : values) {
                    if (!key.equals("submit")) {
                        logger.debug("adding key " + key + ", with value " + value);
                        queryParams.add(key, value);
                    }
                }
            }
        }
        return queryParams;
    }

    /**
     * Authenticating with ufpIdentity is a two or more pass process that ALWAYS starts with preAuthenticate.
     * An {@link AuthenticationPretext} object is returned indicating SUCCESS or FAILURE. In the SUCCESS case, one or more {@link com.ufp.identity4j.data.DisplayItem}s
     * are included which must be presented to the user. In the FAILURE case, the {@link com.ufp.identity4j.data.Result} contains information about the failure
     * which may be used to adjust the user experience e.g. start a registration of the user, in the case of a NOT_FOUND. In the case of other errors, it is usually
     * not a good idea to indicate the error to the user, but rather some generic error or just resetting for a new user id.
     *
     * @param name the user id to be authenticated
     * @param clientIp the client ip of the user authenticating, usually from {@link javax.servlet.ServletRequest#getRemoteAddr()}
     * @return {@link AuthenticationPretext} or null if some error occurs
     */
    public AuthenticationPretext preAuthenticate(String name, String clientIp) {
        WebResource webResource = client.resource(identityResolver.getNext().resolve("preauthenticate"));
        MultivaluedMap queryParams = getQueryParams(name, clientIp, null);
        AuthenticationPretext authenticationPretext = null;
        try {
            authenticationPretext = webResource.queryParams(queryParams).get(AuthenticationPretext.class);
            logger.debug("got result of " + authenticationPretext.getResult().getValue() + ", with message " + authenticationPretext.getResult().getMessage());
        } catch (UniformInterfaceException uie) {
            logger.error(uie.getMessage(), uie);
        }
        return authenticationPretext;
    }

    /**
     * After a successful preAuthenticate, additional parameters are collected and passed to authenticate. In the case of a successful authentication,
     * either an {@link AuthenticationContext} indicating SUCCESS OR an additional {@link AuthenticationPretext} may be returned with a result of CONTINUE
     * indicating that further authentication is required. In the case of FAILURE, an {@link AuthenticationContext} is returned with
     * a {@link com.ufp.identity4j.data.Result} indicating
     * the nature of the failure. In the special case of a RESET failure, contextual information about the user information has been cleaned up (perhaps due to timeout)
     * and the entire process must be reset. In the general case of FAILURE, care must be taken not to indicate the nature of the failure to the user.
     *
     * @param name the user id to be authenticated
     * @param clientIp the client ip of the user authenticating, usually from {@link javax.servlet.ServletRequest#getRemoteAddr()}
     * @param parameters additional parameters collected from the user
     * @return {@link AuthenticationContext}, {@link AuthenticationPretext} or null in the case of error
     */
    public Object authenticate(String name, String clientIp, Map<String, String[]> parameters) {
        Object r = null;
        WebResource webResource = client.resource(identityResolver.getNext().resolve("authenticate"));
        MultivaluedMap queryParams = getQueryParams(name, clientIp, parameters);
        ClientResponse clientResponse = webResource.queryParams(queryParams).get(ClientResponse.class);
        if (clientResponse.getClientResponseStatus().equals(ClientResponse.Status.OK)) {
            try {
                r = handleClientResponse(clientResponse);
            } catch (Exception e) {
                logger.error(e.getMessage(), e);
            }
        } else
            logger.error("got response of " + clientResponse.getClientResponseStatus());
        return r;
    }

    /**
     * A helper function to see if enrollment for the specified user will succeed (user does not already exist) and get a list of
     * {@link com.ufp.identity4j.data.FormElement} needed to enroll a new user.
     * <p>
     * If the {@link com.ufp.identity4j.data.Result} contained in the EnrollmentPretext indicates an error, an enrollment will not
     * succeed with the named user.
     *
     * @param name the user id to be authenticated
     * @param clientIp the client ip of the user authenticating, usually from {@link javax.servlet.ServletRequest#getRemoteAddr()}
     * @return {@link EnrollmentPretext} or null in the case of error
     */
    public EnrollmentPretext preEnroll(String name, String clientIp) {
        WebResource webResource = client.resource(identityResolver.getNext().resolve("preenroll"));
        MultivaluedMap queryParams = getQueryParams(name, clientIp, null);
        EnrollmentPretext enrollmentPretext = null;
        try {
            enrollmentPretext = webResource.queryParams(queryParams).get(EnrollmentPretext.class);
            logger.debug("got result of " + enrollmentPretext.getResult().getValue() + ", with message " + enrollmentPretext.getResult().getMessage());
        } catch (UniformInterfaceException uie) {
            logger.error(uie.getMessage(), uie);
        }
        return enrollmentPretext;
    }

    /**
     * Performs enrollment of the named user. The user must not already exist. The parameters argument is a map of the custom enrollment key/value pairs.
     * The {@link EnrollmentContext} will contain a {@link com.ufp.identity4j.data.Result} indicating SUCCESS or FAILURE. In the latter
     * case, the message and code will indicate the details of the error. Care should be taken not to propagate the error condition to the user.
     *
     * @param name the user id to be authenticated
     * @param clientIp the client ip of the user authenticating, usually from {@link javax.servlet.ServletRequest#getRemoteAddr()}
     * @param parameters additional parameters collected from the user
     * @return {@link EnrollmentContext} or null in the case of error
     */
    public EnrollmentContext enroll(String name, String clientIp, Map<String, String[]> parameters) {
        WebResource webResource = client.resource(identityResolver.getNext().resolve("enroll"));
        MultivaluedMap queryParams = getQueryParams(name, clientIp, parameters);
        EnrollmentContext enrollmentContext = null;
        try {
            enrollmentContext = webResource.queryParams(queryParams).get(EnrollmentContext.class);
            logger.debug("got result of " + enrollmentContext.getResult().getValue() + ", with message " + enrollmentContext.getResult().getMessage());
        } catch (UniformInterfaceException uie) {
            logger.error(uie.getMessage(), uie);
        }
        return enrollmentContext;
    }

    /**
     * Performs re-enrollment of the user. The user must already exist. The parameters argument is a map of the custom enrollment key/value pairs.
     * The {@link EnrollmentContext} will contain a {@link com.ufp.identity4j.data.Result} indicating SUCCESS or FAILURE. In the latter
     * case, the message and code will indicate the details of the error. Care should be taken not to propagate the error condition to the user.
     *
     * @param name the user id to be authenticated
     * @param clientIp the client ip of the user authenticating, usually from {@link javax.servlet.ServletRequest#getRemoteAddr()}
     * @param parameters additional parameters collected from the user
     * @return {@link EnrollmentContext} or null in the case of error
     */
    public EnrollmentContext reEnroll(String name, String clientIp, Map<String, String[]> parameters) {
        WebResource webResource = client.resource(identityResolver.getNext().resolve("reenroll"));
        MultivaluedMap queryParams = getQueryParams(name, clientIp, parameters);
        EnrollmentContext enrollmentContext = null;
        try {
            enrollmentContext = webResource.queryParams(queryParams).get(EnrollmentContext.class);
            logger.debug("got result of " + enrollmentContext.getResult().getValue() + ", with message " + enrollmentContext.getResult().getMessage());
        } catch (UniformInterfaceException uie) {
            logger.error(uie.getMessage(), uie);
        }
        return enrollmentContext;
    }

    private String getHeaderString(List <String> headerParams) {
        StringBuffer stringBuffer = new StringBuffer();
        int size = headerParams.size();

        for (int index = 0; index < size-1; index++) {
            stringBuffer.append(String.format("$%s,", headerParams.get(index)));
        }
        stringBuffer.append(String.format("$%s\n", headerParams.get(size-1)));
        return stringBuffer.toString();
    }

    /**
     * Batch enrollment provides very fast enrollment of existing users. It is only meant to be used once for importing existing users. Modifications
     * to existing users should be disabled while enrolling. New users can be created however as long as they are created with {@link #enroll}.
     * <p>
     * The header parameters are the names of the parameters that will be written to the output stream returned in the BatchEnrollmentContext. If, for instance,
     * the custom enrollment defines the enrollment parameters to be email, name and password then the list might be initialized as follows:
     * <pre>
     *  List<String> headerParams = new ArrayList<String>() {{
     *    add("email");
     *    add("name");
     *    add("password");
     *  }};
     * </pre>
     * After calling the batchEnroll method, the BatchEnrollmentContext contains an OutputStream. The caller is expected to write comma
     * separated, URL encoded values corresponding to the header parameters separated by new lines ('\n'). The caller is also expected to close
     * the output stream and wait for the thread to finish.
     * <pre>
     *  String [] elements = { "test01@example.com,test01,test01pass", "test02@example.com,test02,test02pass", "test03@example.com,test03,test03pass" };
     *  OutputStream outputStream = batchEnrollmentContext.getOutputStream();
     *  for (String element : elements) {
     *      outputStream.write(element.getBytes(), 0, element.length());
     *      outputStream.write('\n');
     *  }
     *  outputStream.flush();
     *  outputStream.close();
     *
     *  // wait for batch enroll thread to finish
     *  batchEnrollmentContext.getThread().join();
     * </pre>
     * The order of the parameters MUST match the order of the header parameters which name them.
     *
     * @param clientIp the client ip of the user authenticating, usually from {@link javax.servlet.ServletRequest#getRemoteAddr()}
     * @param headerParams custom import enrollment parameter names
     * @return BatchEnrollmentContext containing contextual objects for the batch enrollment
     */
    public BatchEnrollmentContext batchEnroll(String clientIp, List<String> headerParams) throws Exception {
        final PipedInputStream inputStream = new PipedInputStream();
        PipedOutputStream outputStream = new PipedOutputStream(inputStream);

        // first we write the parameters for batch enroll
        String hostParameter = String.format("$client_ip=%s\n$type=import\n", clientIp);
        outputStream.write(hostParameter.getBytes(), 0, hostParameter.length());

        String headerParameter = getHeaderString(headerParams);
        outputStream.write(headerParameter.getBytes(), 0, headerParameter.length());

        // now stream until close
        Thread thread = new Thread(new Runnable() {
                public void run() {
                    try {
                        WebResource webResource = client.resource(identityResolver.getNext().resolve("enroll"));
                        logger.debug("about to call post");
                        webResource.type(MediaType.APPLICATION_OCTET_STREAM_TYPE).post(inputStream);
                        logger.debug("about to call close");
                        inputStream.close();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            });
        thread.start();
        return new BatchEnrollmentContext(outputStream, thread);
    }

    private Object handleClientResponse(ClientResponse clientResponse) throws Exception {
        JAXBContext jaxbContext = JAXBContext.newInstance(AuthenticationPretext.class, AuthenticationContext.class);
        Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
        return unmarshaller.unmarshal(clientResponse.getEntityInputStream());
    }
    
    public void setIdentityResolver(IdentityResolver identityResolver) {
        this.identityResolver = identityResolver;
    }

    public void setHostnameVerifier(HostnameVerifier hostnameVerifier) {
        this.hostnameVerifier = hostnameVerifier;
    }

    public void setTrustManagerFactoryBuilder(TrustManagerFactoryBuilder trustManagerFactoryBuilder) {
        this.trustManagerFactoryBuilder = trustManagerFactoryBuilder;
    }

    public void setKeyManagerFactoryBuilder(KeyManagerFactoryBuilder keyManagerFactoryBuilder) {
        this.keyManagerFactoryBuilder = keyManagerFactoryBuilder;
    }
}