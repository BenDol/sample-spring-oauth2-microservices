package pl.piomin.services.auth;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import pl.piomin.services.auth.tmp.AbstractOAuth2FilterConfig;
import pl.piomin.services.auth.tmp.ClientResources;
import pl.piomin.services.auth.tmp.OAuthFilter;
import pl.piomin.services.auth.tmp.OAuthProvider;
import pl.piomin.services.auth.tmp.UserAuthoritiesExtractor;
import pl.piomin.services.auth.tmp.UserPrincipalExtractor;

@Configuration
@EnableAuthorizationServer
public class OAuth2Config extends AbstractOAuth2FilterConfig/*AuthorizationServerConfigurerAdapter*/ {

	@Autowired
	private DataSource dataSource;

	@Autowired
	private AuthenticationManager authenticationManager;

	private final UserPrincipalExtractor principalExtractor;
	private final UserAuthoritiesExtractor authoritiesExtractor;

	@Autowired
	public OAuth2Config(OAuth2ClientContext oauth2ClientContext,
						UserPrincipalExtractor principalExtractor,
						UserAuthoritiesExtractor authoritiesExtractor) {
		super(oauth2ClientContext);

		this.principalExtractor = principalExtractor;
		this.authoritiesExtractor = authoritiesExtractor;
	}

	@Override
	protected void setupFilters() {
		OAuthFilter filter = new OAuthFilter("/oauth/google", google(), getOauth2ClientContext(), principalExtractor, authoritiesExtractor);
		addFilter(OAuthProvider.GOOGLE, filter);
	}

	@Bean
	@ConfigurationProperties("google")
	public ClientResources google() {
		return new ClientResources();
	}

	@Bean
	public FilterRegistrationBean oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter) {
		FilterRegistrationBean<OAuth2ClientContextFilter> registration = new FilterRegistrationBean<>();
		registration.setFilter(filter);
		registration.setOrder(-100);
		return registration;
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints.authenticationManager(this.authenticationManager).tokenStore(tokenStore())
				.accessTokenConverter(accessTokenConverter());
	}

	@Override
	public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
		oauthServer.checkTokenAccess("permitAll()");
	}

	@Bean
	public JwtAccessTokenConverter accessTokenConverter() {
		return new JwtAccessTokenConverter();
	}

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients.jdbc(dataSource);
	}

	@Bean
	public JdbcTokenStore tokenStore() {
		return new JdbcTokenStore(dataSource);
	}

}
