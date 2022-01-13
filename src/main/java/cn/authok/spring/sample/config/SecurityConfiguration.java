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
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

@EnableWebSecurity
@Configuration
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Value("${authok.audience}")
    private String audience;

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuer;

    @Value(value = "${com.authok.domain}")
    private String domain;

    @Value(value = "${com.authok.clientId}")
    private String clientId;

    @Value(value = "${com.authok.clientSecret}")
    private String clientSecret;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf()
                    .disable()
                .cors()
                    .and()
                .logout()
                    .logoutUrl("/logout")
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        String returnUrl = String.format("%s://%s", request.getScheme(), request.getServerName());
                        if ((request.getScheme().equals("http") && request.getServerPort() != 80)
                                || (request.getScheme().equals("https") && request.getServerPort() != 443)) {
                            returnUrl += ":" + request.getServerPort();
                        }
                        returnUrl += "/logout_success";

                        String returnTo = ServletUriComponentsBuilder.fromCurrentContextPath()
                                .path("home")
                                .build().toString();

                        String logoutUrl =
                                UriComponentsBuilder.fromHttpUrl(issuer + "logout?client_id={client_id}&return_to={return_to}")
                                .encode()
                                .buildAndExpand(clientId, returnUrl)
                                .toUriString();

                        try {
                            response.sendRedirect(logoutUrl);
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                })
                    .and()
                .authorizeRequests()
                    .mvcMatchers("/", "/home", "/login", "/callback").permitAll()
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
