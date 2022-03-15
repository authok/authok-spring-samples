package cn.authok.spring.sample.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Controller
public class AuthokLogoutHandler extends SecurityContextLogoutHandler {
    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuer;

    @Value(value = "${application.domain}")
    private String domain;

    @Value(value = "${application.client-id}")
    private String clientId;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        super.logout(request, response, authentication);

        String returnTo = ServletUriComponentsBuilder.fromCurrentContextPath()
                .path("logout/callback")
                .build().toString();

        String logoutUrl =
                UriComponentsBuilder.fromHttpUrl(issuer + "logout?client_id={client_id}&return_to={return_to}")
                        .encode()
                        .buildAndExpand(clientId, returnTo)
                        .toUriString();

        try {
            response.sendRedirect(logoutUrl);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
