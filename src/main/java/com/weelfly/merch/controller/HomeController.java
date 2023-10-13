package com.weelfly.merch.controller;

import cn.hutool.core.lang.Assert;
import cn.hutool.core.util.URLUtil;
import cn.hutool.json.JSONUtil;
import com.google.common.collect.ImmutableMap;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@RequiredArgsConstructor
@RestController
public class HomeController {
    private final AuthenticationManager authenticationManager;
    private final StringKeyGenerator stateGenerator = new Base64StringKeyGenerator(Base64.getUrlEncoder());
    private static final Map<String,String> cache = new ConcurrentHashMap<>();
    {   String issuer = "https://dev-68763921.okta.com/oauth2/default/";
        cache.put("issuer",issuer);
        cache.put("authorizationUri",issuer+"v1/authorize");
        cache.put("tokenUri",issuer+"v1/token");
        cache.put("userInfoEndpointUri",issuer+"v1/userinfo");
        cache.put("jwkSetUri",issuer+"v1/keys");
        cache.put("clientId","0oac6ipptuwgWhYOF5d7");
        cache.put("scope","openid profile email phone");
        cache.put("responseType","code");
        cache.put("redirectUri","http://localhost:8080/oktaCallback");
        cache.put("secret","FHJonCpuVuIHMBWp0Va-ngIKlvUAcissA0NiRZ-CXqZoJZAaqkjwwDhGYNwchZ6J");
    }


    @GetMapping("/")
    public String home(@AuthenticationPrincipal OidcUser user) {
//        providerManager.authenticate(new OAuth2LoginAuthenticationToken(user.getIdToken()))
        return "Welcome, "+ user + "!";
    }

    @SneakyThrows
    @GetMapping("/loginOkta")
    public String loginOkta(HttpServletRequest request, HttpServletResponse response) {
        String authorizationUri = cache.get("authorizationUri");
        String clientId=cache.get("clientId");
        String scope=cache.get("scope");
        String state= stateGenerator.generateKey();
        cache.put("state",state);
        String nonce =
                UUID.randomUUID().toString().replaceAll("-","");
        cache.put("nonce",nonce);
        String redirectUri = cache.get("redirectUri");

        String authorizationRequestUri = authorizationUri
                + "?response_type=code&client_id=" + URLUtil.encode(clientId)
                + "&scope=" + URLUtil.encode(scope)
                + "&state=" + URLUtil.encode(state)
                + "&nonce=" + URLUtil.encode(nonce)
                + "&redirect_uri=" + redirectUri;
        cache.put("authorizationRequestUri",authorizationRequestUri);
        System.out.println(authorizationRequestUri);
        try {
            response.sendRedirect(authorizationRequestUri);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return "loginOkta";
    }
    @SneakyThrows
    @GetMapping("/oktaCallback")
    public String callback(String code,String state, HttpServletRequest request, HttpServletResponse response) {
        Assert.equals(state,cache.get("state"));
        //根据json值填充ClientRegistration对象，使用builder方法
        ClientRegistration clientRegistration = ClientRegistration.withRegistrationId("okta")
                .clientId(cache.get("clientId"))
                .clientSecret(cache.get("secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUriTemplate("{baseUrl}/oktaCallback")

                .scope(cache.get("scope").split(" "))
                .authorizationUri(cache.get("authorizationUri"))
                .tokenUri(cache.get("tokenUri"))
                .userInfoUri(cache.get("userInfoEndpointUri"))
                .userNameAttributeName("sub")
                .userInfoAuthenticationMethod(AuthenticationMethod.HEADER)
                .jwkSetUri(cache.get("jwkSetUri"))
                .build();

        OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode().authorizationUri(cache.get("authorizationUri"))
                .clientId(cache.get("clientId"))
                .redirectUri(cache.get("redirectUri"))
                .scope(cache.get("scope").split(" "))
                .state(state)
                .additionalParameters(ImmutableMap.of("registration_id", "okta"))
                .authorizationRequestUri(cache.get("authorizationRequestUri")).build();
       ;
        OAuth2AuthorizationResponse authorizationResponse = OAuth2AuthorizationResponse.success(code)
                .redirectUri(cache.get("redirectUri"))
                .state(state).build();
        OAuth2LoginAuthenticationToken authenticationRequest = new OAuth2LoginAuthenticationToken(
                clientRegistration, new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse));
        Authentication result = authenticationManager.authenticate(authenticationRequest);
        return JSONUtil.toJsonStr(result.getPrincipal());
    }

    @SneakyThrows
    public static void main(String[] args) {
        //"https://dev-68763921.okta.com/oauth2/default/v1/authorize?response_type=code&client_id=0oac6ipptuwgWhYOF5d7&scope=profile email openid&state=WqeP2G0gOSUoGfn-AfSRGFmPoFS4FEeNj89_8OaU9LA=&redirect_uri=http://localhost:8080/authorization-code/callback&nonce=wlA70LGWrT_KXC9Bas-PwpZzgk3cNkj-OW_XuB06YJo&code_challenge=RpN1l3K71a1f45XK8aHw08RyKGmzm2w9oEkw0QDSfi4&code_challenge_method=S256";
        String domain = "https://dev-68763921.okta.com/oauth2/default/v1/authorize";
        String clientId="0oac6ipptuwgWhYOF5d7";
        String scope="profile email openid";
        String state= UUID.randomUUID().toString().replaceAll("-","");
        String nonce =
                UUID.randomUUID().toString().replaceAll("-","");
//        int codeVerifierLength = 43;
//        String codeVerifier = PKCEGenerator.generateRandomString(codeVerifierLength);
//        String codeChallenge = PKCEGenerator.generateCodeChallenge(codeVerifier);
        String redirect_uri = "http://localhost:8080/authorization-code/callback";
//        String url = domain + "?response_type=code&client_id=" + URLUtil.encode(clientId) + "&scope=" + URLUtil.encode(scope) + "&state=" + URLUtil.encode(state)
//                + "&nonce=" + URLUtil.encode(nonce) + "&code_challenge=" + URLUtil.encode(codeChallenge) + "&code_challenge_method=S256&redirect_uri=" + redirect_uri;
//        url = URLEncoder.encode(url, "UTF-8");
//        System.out.println(url);
    }


}
