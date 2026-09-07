/**
 * The contents of this file are subject to the license and copyright
 * detailed in the LICENSE and NOTICE files at the root of the source
 * tree and available online at
 *
 * http://www.dspace.org/license/
 */
package org.dspace.authenticate;

import static java.lang.String.format;
import static java.net.URLEncoder.encode;
import static org.apache.commons.lang.BooleanUtils.toBoolean;
import static org.apache.commons.lang3.StringUtils.isAnyBlank;
import static org.apache.commons.lang3.StringUtils.isBlank;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.dspace.authenticate.oidc.OidcClient;
import org.dspace.authenticate.oidc.model.OidcTokenResponseDTO;
import org.dspace.core.Context;
import org.dspace.eperson.EPerson;
import org.dspace.eperson.Group;
import org.dspace.eperson.service.EPersonService;
import org.dspace.services.ConfigurationService;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * OpenID Connect Authentication for DSpace.
 *
 * Extended to extract claims from JWT tokens (ID token / Access token)
 * as well as the standard UserInfo endpoint without external dependencies.
 *
 * @author Luca Giamminonni (luca.giamminonni at 4science.it)
 */
public class OidcAuthenticationBean implements AuthenticationMethod {

    public static final String OIDC_AUTH_ATTRIBUTE = "oidc";

    private final static String LOGIN_PAGE_URL_FORMAT = "%s?client_id=%s&response_type=code&scope=%s&redirect_uri=%s";

    private static final Logger LOGGER = LogManager.getLogger();

    private static final String OIDC_AUTHENTICATED = "oidc.authenticated";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Autowired
    private ConfigurationService configurationService;

    @Autowired
    private OidcClient oidcClient;

    @Autowired
    private EPersonService ePersonService;

    @Override
    public boolean allowSetPassword(Context context, HttpServletRequest request, String username) throws SQLException {
        return false;
    }

    @Override
    public boolean isImplicit() {
        return false;
    }

    @Override
    public boolean canSelfRegister(Context context, HttpServletRequest request, String username) throws SQLException {
        return canSelfRegister();
    }

    @Override
    public void initEPerson(Context context, HttpServletRequest request, EPerson eperson) throws SQLException {
    }

    @Override
    public List<Group> getSpecialGroups(Context context, HttpServletRequest request) throws SQLException {
        return List.of();
    }

    @Override
    public String getName() {
        return OIDC_AUTH_ATTRIBUTE;
    }

    @Override
    public int authenticate(Context context, String username, String password, String realm, HttpServletRequest request)
        throws SQLException {

        if (request == null) {
            LOGGER.warn("Unable to authenticate using OIDC because the request object is null.");
            return BAD_ARGS;
        }

        if (request.getAttribute(OIDC_AUTH_ATTRIBUTE) == null) {
            return NO_SUCH_USER;
        }

        String code = request.getParameter("code");
        if (StringUtils.isEmpty(code)) {
            LOGGER.warn("The incoming request has not code parameter");
            return NO_SUCH_USER;
        }

        return authenticateWithOidc(context, code, request);
    }

    private int authenticateWithOidc(Context context, String code, HttpServletRequest request) throws SQLException {

        OidcTokenResponseDTO tokenResponse = getOidcAccessToken(code);
        if (tokenResponse == null) {
            LOGGER.warn("No access token retrieved by code");
            return NO_SUCH_USER;
        }

        // Aggregate claims from both JWT (id_token/access_token) and the UserInfo endpoint
        Map<String, Object> aggregatedUserData = resolveUserData(tokenResponse);

        String email = getAttributeAsString(aggregatedUserData, getEmailAttribute());
        if (StringUtils.isBlank(email)) {
            LOGGER.warn("No email found in the token claims or user info attributes");
            return NO_SUCH_USER;
        }

        EPerson ePerson = ePersonService.findByEmail(context, email);
        if (ePerson != null) {
            request.setAttribute(OIDC_AUTHENTICATED, true);
            return ePerson.canLogIn() ? logInEPerson(context, ePerson) : BAD_ARGS;
        }

        // if self registration is disabled, warn about this failure to find a matching eperson
        if (!canSelfRegister()) {
            LOGGER.warn("Self registration is currently disabled for OIDC, and no ePerson could be found for email: {}",
                email);
        }

        return canSelfRegister() ? registerNewEPerson(context, aggregatedUserData, email) : NO_SUCH_USER;
    }

    /**
     * Aggregates user attributes by first attempting to query the UserInfo endpoint,
     * then overlaying/supplementing with claims parsed directly from the ID Token JWT
     * (or Access Token JWT if formatted as a JWT).
     */
    private Map<String, Object> resolveUserData(OidcTokenResponseDTO tokenResponse) {
        Map<String, Object> userData = new HashMap<>();

        // 1. Fetch from UserInfo endpoint if an access token is present
        if (StringUtils.isNotBlank(tokenResponse.getAccessToken())) {
            Map<String, Object> userInfo = getOidcUserInfo(tokenResponse.getAccessToken());
            if (userInfo != null && !userInfo.isEmpty()) {
                userData.putAll(userInfo);
            }
        }

        // 2. Supplement/override with claims parsed from the ID Token
        if (StringUtils.isNotBlank(tokenResponse.getIdToken())) {
            Map<String, Object> idTokenClaims = parseJwtPayload(tokenResponse.getIdToken());
            userData.putAll(idTokenClaims);
        }

        // 3. Fallback: If still no claims and accessToken is formatted as a JWT, parse claims from it
        if (userData.isEmpty() && StringUtils.isNotBlank(tokenResponse.getAccessToken())) {
            Map<String, Object> accessTokenClaims = parseJwtPayload(tokenResponse.getAccessToken());
            userData.putAll(accessTokenClaims);
        }

        return userData;
    }

    /**
     * Decodes the payload segment (second part) of a JWT string using Base64URL
     * and maps it to a Map via Jackson.
     */
    private Map<String, Object> parseJwtPayload(String jwtString) {
        if (isBlank(jwtString)) {
            return Map.of();
        }

        String[] parts = jwtString.split("\\.");
        if (parts.length < 2) {
            LOGGER.debug("Supplied token is not a valid multi-part JWT");
            return Map.of();
        }

        try {
            byte[] decodedBytes = Base64.getUrlDecoder().decode(parts[1]);
            String payloadJson = new String(decodedBytes, StandardCharsets.UTF_8);
            return MAPPER.readValue(payloadJson, new TypeReference<Map<String, Object>>() {});
        } catch (IllegalArgumentException e) {
            LOGGER.debug("Failed to Base64-decode JWT payload: {}", e.getMessage());
        } catch (Exception ex) {
            LOGGER.error("Error occurred while parsing claims from JWT payload", ex);
        }

        return Map.of();
    }

    @Override
    public String loginPageURL(Context context, HttpServletRequest request, HttpServletResponse response) {

        String authorizeUrl = configurationService.getProperty("authentication-oidc.authorize-endpoint");
        String clientId = configurationService.getProperty("authentication-oidc.client-id");
        String clientSecret = configurationService.getProperty("authentication-oidc.client-secret");
        String redirectUri = configurationService.getProperty("authentication-oidc.redirect-url");
        String tokenUrl = configurationService.getProperty("authentication-oidc.token-endpoint");
        String[] defaultScopes = new String[] { "openid", "email", "profile" };
        String scopes = String.join(" ", configurationService.getArrayProperty("authentication-oidc.scopes",
            defaultScopes));

        if (isAnyBlank(authorizeUrl, clientId, redirectUri, clientSecret, tokenUrl)) {
            LOGGER.error("Missing mandatory configuration properties for OidcAuthenticationBean");

            final Map<String, String> map = Map.of(
                "authorizeUrl", authorizeUrl,
                "clientId", clientId,
                "redirectUri", redirectUri,
                "clientSecret", clientSecret,
                "tokenUrl", tokenUrl
            );

            for (Entry<String, String> entry : map.entrySet()) {
                if (isBlank(entry.getValue())) {
                    LOGGER.error(" * {} is missing", entry.getKey());
                }
            }
            return "";
        }

        try {
            return format(LOGIN_PAGE_URL_FORMAT, authorizeUrl, clientId, scopes,
                encode(redirectUri, StandardCharsets.UTF_8.name()));
        } catch (UnsupportedEncodingException e) {
            LOGGER.error(e::getMessage, e);
            return "";
        }
    }

    private int logInEPerson(Context context, EPerson ePerson) {
        context.setCurrentUser(ePerson);
        return SUCCESS;
    }

    private int registerNewEPerson(Context context, Map<String, Object> userInfo, String email) throws SQLException {
        try {
            context.turnOffAuthorisationSystem();

            EPerson eperson = ePersonService.create(context);

            eperson.setNetid(email);
            eperson.setEmail(email);

            String firstName = getAttributeAsString(userInfo, getFirstNameAttribute());
            if (firstName != null) {
                eperson.setFirstName(context, firstName);
            }

            String lastName = getAttributeAsString(userInfo, getLastNameAttribute());
            if (lastName != null) {
                eperson.setLastName(context, lastName);
            }

            eperson.setCanLogIn(true);
            eperson.setSelfRegistered(true);

            ePersonService.update(context, eperson);
            context.setCurrentUser(eperson);
            context.dispatchEvents();

            return SUCCESS;

        } catch (Exception ex) {
            LOGGER.error("An error occurs registering a new EPerson from OIDC", ex);
            return NO_SUCH_USER;
        } finally {
            context.restoreAuthSystemState();
        }
    }

    private OidcTokenResponseDTO getOidcAccessToken(String code) {
        try {
            return oidcClient.getAccessToken(code);
        } catch (Exception ex) {
            LOGGER.error("An error occurs retriving the OIDC access_token", ex);
            return null;
        }
    }

    private Map<String, Object> getOidcUserInfo(String accessToken) {
        try {
            return oidcClient.getUserInfo(accessToken);
        } catch (Exception ex) {
            LOGGER.debug("Unable to retrieve user info from endpoint (falling back to JWT claims): {}", ex.getMessage());
            return Map.of();
        }
    }

    private String getAttributeAsString(Map<String, Object> userInfo, String attribute) {
        if (isBlank(attribute) || userInfo == null) {
            return null;
        }
        return userInfo.containsKey(attribute) ? String.valueOf(userInfo.get(attribute)) : null;
    }

    private String getEmailAttribute() {
        return configurationService.getProperty("authentication-oidc.user-info.email", "email");
    }

    private String getFirstNameAttribute() {
        return configurationService.getProperty("authentication-oidc.user-info.first-name", "given_name");
    }

    private String getLastNameAttribute() {
        return configurationService.getProperty("authentication-oidc.user-info.last-name", "family_name");
    }

    private boolean canSelfRegister() {
        String canSelfRegister = configurationService.getProperty("authentication-oidc.can-self-register", "true");
        if (isBlank(canSelfRegister)) {
            return true;
        }
        return toBoolean(canSelfRegister);
    }

    public OidcClient getOidcClient() {
        return this.oidcClient;
    }

    public void setOidcClient(OidcClient oidcClient) {
        this.oidcClient = oidcClient;
    }

    @Override
    public boolean isUsed(final Context context, final HttpServletRequest request) {
        return request != null &&
               context.getCurrentUser() != null &&
               request.getAttribute(OIDC_AUTHENTICATED) != null;
    }

    @Override
    public boolean canChangePassword(Context context, EPerson ePerson, String currentPassword) {
        return false;
    }
}
