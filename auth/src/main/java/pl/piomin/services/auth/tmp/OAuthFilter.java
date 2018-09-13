package pl.piomin.services.auth.tmp;

import org.springframework.boot.autoconfigure.security.oauth2.resource.AuthoritiesExtractor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.PrincipalExtractor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

public class OAuthFilter extends OAuth2ClientAuthenticationProcessingFilter {

    private final String filterProcessesUrl;
    private final OAuth2ClientContext clientContext;
    private final ClientResources clientResources;
    private final UserInfoTokenServices tokenServices;
    private final OAuth2RestTemplate restTemplate;
    private final PrincipalExtractor principalExtractor;
    private final AuthoritiesExtractor authoritiesExtractor;

    public OAuthFilter(String defaultFilterProcessesUrl,
                       ClientResources clientResources,
                       OAuth2ClientContext clientContext,
                       PrincipalExtractor principalExtractor,
                       AuthoritiesExtractor authoritiesExtractor) {
        super(defaultFilterProcessesUrl);

        this.filterProcessesUrl = defaultFilterProcessesUrl;
        this.clientContext = clientContext;
        this.clientResources = clientResources;
        this.principalExtractor = principalExtractor;
        this.authoritiesExtractor = authoritiesExtractor;

        restTemplate = new OAuth2RestTemplate(clientResources.getClient(), clientContext);
        setRestTemplate(restTemplate);
        tokenServices = new UserInfoTokenServices(
            clientResources.getResource().getUserInfoUri(),
            clientResources.getClient().getClientId());

        tokenServices.setAuthoritiesExtractor(authoritiesExtractor);
        tokenServices.setPrincipalExtractor(principalExtractor);
        tokenServices.setRestTemplate(restTemplate);
        setTokenServices(tokenServices);

        // TODO: make this configurable?
        AuthenticationSuccessHandler successHandler = getSuccessHandler();
        if (successHandler instanceof SavedRequestAwareAuthenticationSuccessHandler) {
            ((SavedRequestAwareAuthenticationSuccessHandler) successHandler).setAlwaysUseDefaultTargetUrl(true);
        }
    }

    public OAuthFilter(OAuthFilterRegistration registration, String pathPrefix, OAuth2ClientContext clientContext) {
        this(combinePath(pathPrefix, registration.getFilterProcessesUrl()),
             registration.getClientResources(),
             clientContext,
             registration.getPrincipalExtractor(),
             registration.getAuthoritiesExtractor());
    }

    public String getFilterProcessesUrl() {
        return filterProcessesUrl;
    }

    public OAuth2ClientContext getClientContext() {
        return clientContext;
    }

    public ClientResources getClientResources() {
        return clientResources;
    }

    public UserInfoTokenServices getTokenServices() {
        return tokenServices;
    }

    public OAuth2RestTemplate getRestTemplate() {
        return restTemplate;
    }

    public boolean isValidFilter() {
        // TODO: Validate the services and template to ensure valid?
        return true;
    }

    private static String combinePath(String pathPrefix, String filterProcessesUrl) {
        String path = pathPrefix;

        if (!path.startsWith("/") && !path.startsWith("\\")) {
            path = "/" + path;
        }
        if (!filterProcessesUrl.startsWith("/") && !filterProcessesUrl.startsWith("\\")) {
            path = path + "/";
        }
        return path + filterProcessesUrl;
    }
}
