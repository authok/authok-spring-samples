package cn.authok.spring.sample.controllers;

import com.alibaba.fastjson.JSON;
import com.auth0.AuthenticationController;
import com.auth0.Tokens;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.authok.client.auth.AuthAPI;
import com.authok.client.mgmt.ManagementAPI;
import com.authok.json.auth.UserInfo;
import com.authok.json.mgmt.users.Identity;
import com.authok.json.mgmt.users.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

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

    @Value(value = "${application.client-secret}")
    private String clientSecret;

    @GetMapping(value = "/login")
    public void login(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String redirectUri = "http://localhost:8083/callback";
        String authorizeUrl = authenticationController.buildAuthorizeUrl(request, response, redirectUri)
                .withScope("openid email profile")
                .withState("http://localhost:8083/home")
                .withConnection("doudian")
                .build();
        response.sendRedirect(authorizeUrl);
    }

    @GetMapping(value="logout/callback")
    public void logoutCallback(final HttpServletRequest request, final HttpServletResponse response) throws Exception {
        // sso登出成功，回调这里, 这里可以做一些本地退登清理工作

        response.sendRedirect("/home");
    }

    @GetMapping(value="/callback")
    public void callback(final HttpServletRequest request, final HttpServletResponse response) throws Exception {
        // 校验授权码 / state(防CSRF重放攻击) 并 获取 token
        Tokens tokens = authenticationController.handle(request, response);

        // 获取用户信息
        AuthAPI api = new AuthAPI(domain, clientId, clientSecret);
        UserInfo userInfo = api.userInfo(tokens.getAccessToken()).execute();
        ObjectMapper mapper = new ObjectMapper();
        User user = mapper.readValue(mapper.writeValueAsString(userInfo.getValues()), User.class);

        // 过滤 抖店的 身份信息, 如果多平台登录，会有多个身份信息
        Identity identity = user.getIdentities().stream().filter(x -> x.getConnection().equals("doudian")).findFirst().get();
        // 这里为平台的访问令牌
        String accessToken = identity.getAccessToken();
        System.out.printf("第三方平台颁发的访问令牌: %s\n", accessToken);
        
        // 完成会话认证等，具体应该根据自己的会话策略来实现
        String redirectUrl = request.getParameter("state");

        DecodedJWT jwt = JWT.decode(tokens.getIdToken());
        TestingAuthenticationToken authToken2 = new TestingAuthenticationToken(jwt.getSubject(),
                jwt.getToken());
        authToken2.setAuthenticated(true);
        SecurityContextHolder.getContext().setAuthentication(authToken2);

        response.sendRedirect(redirectUrl);
    }
}
