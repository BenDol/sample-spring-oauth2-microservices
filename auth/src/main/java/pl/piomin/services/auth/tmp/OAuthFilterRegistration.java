package pl.piomin.services.auth.tmp;

import org.springframework.boot.autoconfigure.security.oauth2.resource.AuthoritiesExtractor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.PrincipalExtractor;

public class OAuthFilterRegistration {

    private OAuthFilter filter;

    // Future registry information
    private final OAuthProvider provider;
    private final String filterProcessesUrl;
    private final ClientResources clientResources;
    private final PrincipalExtractor principalExtractor;
    private final AuthoritiesExtractor authoritiesExtractor;

    public OAuthFilterRegistration(OAuthProvider provider,
                                   String filterProcessesUrl,
                                   ClientResources clientResources,
                                   PrincipalExtractor principalExtractor,
                                   AuthoritiesExtractor authoritiesExtractor) {
        this.provider = provider;
        this.filterProcessesUrl = filterProcessesUrl;
        this.clientResources = clientResources;
        this.principalExtractor = principalExtractor;
        this.authoritiesExtractor = authoritiesExtractor;
    }

    public OAuthFilterRegistration(OAuthProvider provider, OAuthFilter filter) {
        this(provider, filter.getFilterProcessesUrl(), null, null, null);

        this.filter = filter;
    }

    public OAuthProvider getProvider() {
        return provider;
    }

    public String getFilterProcessesUrl() {
        return filterProcessesUrl;
    }

    public ClientResources getClientResources() {
        return clientResources;
    }

    public PrincipalExtractor getPrincipalExtractor() {
        return principalExtractor;
    }

    public AuthoritiesExtractor getAuthoritiesExtractor() {
        return authoritiesExtractor;
    }

    public OAuthFilter getFilter() {
        return filter;
    }

    public void setFilter(OAuthFilter filter) {
        this.filter = filter;
    }
}
