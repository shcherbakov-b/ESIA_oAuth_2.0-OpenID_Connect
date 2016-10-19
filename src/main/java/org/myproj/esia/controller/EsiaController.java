package org.myproj.esia.controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthJSONAccessTokenResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.myproj.esia.Pkcs7Util;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;

import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.*;

@Controller
public class EsiaController {

    private static final String ESIA_SERV = "https://esia-portal1.test.gosuslugi.ru";
    //    private static final String ESIA_SERV = "https://esia.gosuslugi.ru";
    private static final String ESIA_CODE_POINT = "/aas/oauth2/ac";
    private static final String ESIA_TOKEN_POINT = "/aas/oauth2/te";
    private static final String ESIA_INFO_POINT = "/rs/prns/";

    private static final String STATE = UUID.randomUUID().toString();
    private static final String REDIRECT_URL = "http://localhost:8080/esia-ok";
    private static final String CLIENT_ID = "CLIENT_ID";
    private static final String SCOPE = "email fullname";
    private static final String ACCESS_TYPE = "online";

    @Autowired
    private Pkcs7Util pkcs7Util;

    @RequestMapping("/")
    public ModelAndView initialize() {
        return new ModelAndView("index");
    }

    @RequestMapping(value = "/esia-get", method = RequestMethod.GET)
    public ModelAndView esiaAuthorize() throws OAuthSystemException {
        String scope = "snils";
        String responseType = "code";
        String timestamp = new SimpleDateFormat("yyyy.MM.dd HH:mm:ss Z").format(new Date());
        String clientSecret = generateClientSecret(scope, timestamp, CLIENT_ID, STATE);
        String accessType = "online";
        OAuthClientRequest request = OAuthClientRequest.authorizationLocation(ESIA_SERV + ESIA_CODE_POINT)
                .setClientId(CLIENT_ID)
                .setParameter("client_secret", clientSecret)
                .setRedirectURI(REDIRECT_URL)
                .setScope(scope)
                .setResponseType(responseType)
                .setState(STATE)
                .setParameter("timestamp", timestamp)
                .setParameter("access_type", accessType)
                .buildQueryMessage();
        return new ModelAndView(new RedirectView(request.getLocationUri()));
    }

    @RequestMapping(value = "/esia-ok", method = RequestMethod.GET)
    public void handleRedirect(HttpServletRequest request)
            throws OAuthSystemException, OAuthProblemException {
        OAuthAuthzResponse oar;
        try {
            oar = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
            String code = oar.getCode();
            String state = oar.getState();
            if (STATE.equals(state)) {
                String timestamp = new SimpleDateFormat("yyyy.MM.dd HH:mm:ss Z").format(new Date());
                String clientSecret = generateClientSecret(SCOPE, timestamp, CLIENT_ID, STATE);
                OAuthClientRequest oAuthClientRequest;
                oAuthClientRequest = OAuthClientRequest
                        .tokenLocation(ESIA_SERV + ESIA_TOKEN_POINT)
                        .setClientId(CLIENT_ID)
                        .setCode(code)
                        .setGrantType(GrantType.AUTHORIZATION_CODE)
                        .setClientSecret(clientSecret)
                        .setParameter("state", STATE)
                        .setRedirectURI(REDIRECT_URL)
                        .setScope(SCOPE)
                        .setParameter("timestamp", timestamp)
                        .setParameter("token_type", "Bearer")
                        .setParameter("access_type", ACCESS_TYPE)
                        .buildBodyMessage();

                OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
                OAuthJSONAccessTokenResponse oauthResponse = oAuthClient
                        .accessToken(oAuthClientRequest, OAuth.HttpMethod.POST, OAuthJSONAccessTokenResponse.class);
                String[] accessParts = oauthResponse.getAccessToken().split("\\.");
                ObjectMapper mapper = new ObjectMapper();
                HttpClient client = HttpClientBuilder.create().build();
                Map<String, String> info = mapper.readValue(new String(Base64.getUrlDecoder().decode(accessParts[1]), "UTF-8"),
                        new TypeReference<Map<String, String>>() {
                        });
                String username = info.get("urn:esia:sbj_id");
                Map<String, Object> userInfo = getUserInfo(client, mapper, username, oauthResponse);
            }
        } catch (OAuthProblemException | OAuthSystemException | IOException ignored) {
            //NOP
        }
    }

    private String generateClientSecret(String scope, String timestamp, String clientId, String state) {
        String secret = scope + timestamp + clientId + state;
        return pkcs7Util.getUrlSafeSign(secret);
    }

    private Map<String, Object> getUserInfo(HttpClient client, ObjectMapper mapper, String username,
                                            OAuthJSONAccessTokenResponse oauthResponse) throws IOException {
        HttpGet get = new HttpGet(ESIA_SERV + ESIA_INFO_POINT + username);
        String result = getResponse(client, oauthResponse, get);
        Map<String, Object> userMail = getUserEmail(client, mapper, username, oauthResponse);
        Map<String, Object> userInfo = mapper.readValue(result,
                new TypeReference<Map<String, Object>>() {
                });
        if (userMail != null && userMail.containsKey("value")) {
            if ("EML".equals(userMail.get("type"))) {
                userInfo.put("email", userMail.get("value"));
            }
        }
        return userInfo;
    }

    private Map<String, Object> getUserEmail(HttpClient client, ObjectMapper mapper, String username,
                                             OAuthJSONAccessTokenResponse oauthResponse) throws IOException {
        HttpGet get = new HttpGet(ESIA_SERV + ESIA_INFO_POINT + username + "/ctts");
        String result = getResponse(client, oauthResponse, get);
        Map<String, Object> map = new ObjectMapper().readValue(result,
                new TypeReference<Map<String, Object>>() {
                });
        String uri;
        try {
            uri = ((ArrayList) map.get("elements")).get(0).toString();
        } catch (Exception e) {
            return null;
        }
        get = new HttpGet(uri);
        result = getResponse(client, oauthResponse, get);
        return mapper.readValue(result, new TypeReference<Map<String, Object>>() {
        });
    }


    private String getResponse(HttpClient client, OAuthJSONAccessTokenResponse oauthResponse, HttpGet get) throws IOException {
        get.addHeader(OAuth.HeaderType.CONTENT_TYPE, OAuth.ContentType.URL_ENCODED);
        get.addHeader(OAuth.HeaderType.AUTHORIZATION, String.format("%s %s", oauthResponse.getTokenType(), oauthResponse.getAccessToken()));
        HttpResponse response = client.execute(get);
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int length;
        while ((length = response.getEntity().getContent().read(buffer)) != -1) {
            result.write(buffer, 0, length);
        }
        return result.toString("UTF-8");
    }

}
