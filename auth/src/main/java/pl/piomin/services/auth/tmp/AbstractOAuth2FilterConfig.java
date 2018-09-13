/*
 * #%L
 * insclix-app-budget-server
 * %%
 * Copyright (C) 2017 - 2018 Insclix
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */
package pl.piomin.services.auth.tmp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.security.oauth2.resource.AuthoritiesExtractor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.PrincipalExtractor;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.web.filter.CompositeFilter;

import javax.servlet.Filter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@EnableOAuth2Client
@EnableAuthorizationServer
public abstract class AbstractOAuth2FilterConfig extends AuthorizationServerConfigurerAdapter {

    private static final Logger logger = LoggerFactory.getLogger(AbstractOAuth2FilterConfig.class);

    private final Map<OAuthFilterRegistration, OAuthFilter> filters = new HashMap<>();

    private final OAuth2ClientContext oauth2ClientContext;
    private final String pathPrefix;

    private CompositeFilter compositeFilter;

    public AbstractOAuth2FilterConfig(OAuth2ClientContext oauth2ClientContext) {
        this("/oauth", oauth2ClientContext);
    }

    public AbstractOAuth2FilterConfig(String pathPrefix, OAuth2ClientContext oauth2ClientContext) {
        this.pathPrefix = pathPrefix;
        this.oauth2ClientContext = oauth2ClientContext;
    }

    /**
     * Setup and SSO filters you require here.
     *
     * @see #addFilter(OAuthProvider, String, ClientResources, PrincipalExtractor, AuthoritiesExtractor)
     * @see #addFilter(OAuthProvider, OAuthFilter)
     */
    protected abstract void setupFilters();

    @Bean
    public FilterRegistrationBean oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter) {
        FilterRegistrationBean<OAuth2ClientContextFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(filter);
        registration.setOrder(-100);
        return registration;
    }

    @Bean
    public Filter ssoFilter() {
        if (!isFilterCreated()) {
            setupFilters();
            compositeFilter = new CompositeFilter();

            List<OAuthFilter> filters = new ArrayList<>();
            for (OAuthFilterRegistration registration : this.filters.keySet()) {
                OAuthFilter filter = registration.getFilter();
                if (filter != null) {
                    // we have a pre-constructed filter that someone is trying to register.
                    if (!filter.isValidFilter()) {
                        throw new IllegalStateException("The filter provided was invalid for OAuth2 usage: " + filter.toString());
                    }
                } else {
                    // create a new filter from the registry information
                    filter = new OAuthFilter(registration, pathPrefix, oauth2ClientContext);
                }

                filters.add(filter);
                this.filters.put(registration, filter);
                logger.info("Registering " + filter.getFilterProcessesUrl() + " OAuth2 Filter");
            }

            if (!filters.isEmpty()) {
                compositeFilter.setFilters(filters);
            } else {
                logger.warn("No OAuth2 filters were registered, make sure you are calling #addFilter(...) from #setupFilters().");
            }
        }

        return compositeFilter;
    }

    public OAuthFilterRegistration addFilter(OAuthProvider provider,
                                             String path,
                                             ClientResources client,
                                             PrincipalExtractor principalExtractor,
                                             AuthoritiesExtractor authoritiesExtractor) throws IllegalStateException {
        if (containsFilter(provider)) {
            logger.warn("Overriding existing OAuth2 filter for provider " + provider.name());
        }

        OAuthFilterRegistration registration;
        if (!isFilterCreated()) {
            registration = new OAuthFilterRegistration(provider, path, client, principalExtractor, authoritiesExtractor);
            filters.put(registration, null);
        } else {
            throw new IllegalStateException("Cannot add filters after the composite filter has already been registered.");
        }
        return registration;
    }

    public void addFilter(OAuthProvider provider, OAuthFilter filter) {
        if (containsFilter(provider)) {
            logger.warn("Overriding existing OAuth2 filter for provider " + provider.name());
        }

        if (!isFilterCreated()) {
            filters.put(new OAuthFilterRegistration(provider, filter), null);
        } else {
            throw new IllegalStateException("Cannot add filters after the composite filter has already been registered.");
        }
    }

    private boolean containsFilter(OAuthProvider provider) {
        return filters.keySet().stream().anyMatch(reg -> reg.getProvider().equals(provider));
    }

    public boolean isFilterCreated() {
        return compositeFilter != null;
    }

    public OAuth2ClientContext getOauth2ClientContext() {
        return oauth2ClientContext;
    }
}
