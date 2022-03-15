package cn.authok.spring.sample.controllers;

import com.auth0.AuthenticationController;
import com.auth0.Tokens;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RestController
public class AuthController {
    @Autowired
    private AuthenticationController authenticationController;

    @Value(value = "${application.domain}")
    private String domain;

    @Value(value = "${application.client-id}")
    private String clientId;

    @GetMapping(value = "/login")
    public void login(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String redirectUri = "http://localhost:8083/callback";
        String authorizeUrl = authenticationController.buildAuthorizeUrl(request, response, redirectUri)
                .withScope("openid email")
                .withState("http://localhost:8083/home")
                .build();
        response.sendRedirect(authorizeUrl);
    }

    @GetMapping(value="/callback")
    public void callback(final HttpServletRequest request, final HttpServletResponse response) throws Exception {
        Tokens tokens = authenticationController.handle(request, response);

        String redirectUrl = request.getParameter("state");

        DecodedJWT jwt = JWT.decode(tokens.getIdToken());
        TestingAuthenticationToken authToken2 = new TestingAuthenticationToken(jwt.getSubject(),
                jwt.getToken());
        authToken2.setAuthenticated(true);

        SecurityContextHolder.getContext().setAuthentication(authToken2);

        response.sendRedirect(redirectUrl);
    }
}
