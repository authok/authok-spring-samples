package cn.authok.spring.sample.config;

import com.auth0.AuthenticationController;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import java.io.UnsupportedEncodingException;

@EnableWebSecurity
@Configuration
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Value("${application.audience}")
    private String audience;

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuer;

    @Value(value = "${application.domain}")
    private String domain;

    @Value(value = "${application.client-id}")
    private String clientId;

    @Value(value = "${application.client-secret}")
    private String clientSecret;

    private final LogoutHandler logoutHandler;

    public SecurityConfiguration(LogoutHandler logoutHandler) {
        this.logoutHandler = logoutHandler;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf()
                    .disable()
                .cors()
                    .and()
                .logout()
                    .logoutUrl("/logout")
                    .addLogoutHandler(logoutHandler)
                    .and()
                .authorizeRequests()
                    .mvcMatchers("/", "/home", "/login", "/callback", "/logout/callback").permitAll()
                    .anyRequest().authenticated()
                    // .mvcMatchers(HttpMethod.GET, "/api/v1/contacts/**").authenticated() //.hasAuthority("SCOPE_read:contacts")
                    .and()
                .oauth2ResourceServer()
                    .jwt();
    }

    @Bean
    JwtDecoder jwtDecoder() {
        NimbusJwtDecoder jwtDecoder = JwtDecoders.fromOidcIssuerLocation(issuer);
        OAuth2TokenValidator<Jwt> audienceValidator = new AudienceValidator(audience);
        OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuer);
        OAuth2TokenValidator<Jwt> withAudience = new DelegatingOAuth2TokenValidator(withIssuer, audienceValidator);

        jwtDecoder.setJwtValidator(withAudience);
        return jwtDecoder;
    }

    @Bean
    public AuthenticationController authenticationController() throws UnsupportedEncodingException {
        JwkProvider jwkProvider = new JwkProviderBuilder(domain).build();
        return AuthenticationController.newBuilder(domain, clientId, clientSecret)
                .withJwkProvider(jwkProvider)
                .build();
    }
}
