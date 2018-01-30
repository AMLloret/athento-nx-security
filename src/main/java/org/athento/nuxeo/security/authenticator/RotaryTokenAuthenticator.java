package org.athento.nuxeo.security.authenticator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.core.api.DocumentModelList;
import org.nuxeo.ecm.directory.Session;
import org.nuxeo.ecm.directory.api.DirectoryService;
import org.nuxeo.ecm.platform.api.login.UserIdentificationInfo;
import org.nuxeo.ecm.platform.ui.web.auth.interfaces.NuxeoAuthenticationPlugin;
import org.nuxeo.ecm.tokenauth.TokenAuthenticationException;
import org.nuxeo.ecm.tokenauth.service.TokenAuthenticationService;
import org.nuxeo.runtime.api.Framework;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.Serializable;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Rotary token authenticator.
 */
public class RotaryTokenAuthenticator implements NuxeoAuthenticationPlugin {

    private static final Log LOG = LogFactory.getLog(RotaryTokenAuthenticator.class);

    private TokenAuthenticationService tokenAuthService;

    protected static final String DIRECTORY_NAME = "authTokens";
    protected static final String DIRECTORY_SCHEMA = "authtoken";
    protected static final String TOKEN_FIELD = "token";
    protected static final String PERMISSION_FIELD = "permission";

    protected static final String TOKEN_HEADER = "X-RotaryAuthentication-Token";

    public Boolean handleLoginPrompt(HttpServletRequest httpRequest,
            HttpServletResponse httpResponse, String baseURL) {
        return false;
    }

    public UserIdentificationInfo handleRetrieveIdentity(
            HttpServletRequest httpRequest, HttpServletResponse httpResponse) {

        String tokenAppDevice = httpRequest.getHeader(TOKEN_HEADER);

        LOG.info("Token " + tokenAppDevice);

        if (tokenAppDevice == null) {
            return null;
        }

        String [] tokenInfo = tokenAppDevice.split(":");
        if (tokenInfo.length != 3) {
            return null;
        }

        String token = tokenInfo[0];
        String app = tokenInfo[1];
        String device = tokenInfo[2];

        if (token == null) {
            LOG.info(String.format("Found no '%s' header in the request.",
                    TOKEN_HEADER));
            return null;
        }

        String userName = getUserByToken(token);
        if (userName == null) {
            LOG.info(String.format(
                    "No user bound to token."));
            return null;
        }


        token = getToken(userName, app, device);
        if (token == null) {
            LOG.info(String.format(
                    "No token found."));
            return null;
        } else {
            String permission = getTokenPermission(token);
            if (permission == null) {
                permission = "r";
            }
            // Revoke current token
            String newToken = revokeTokenAndRotary(userName, token, app, device, permission);
            if (newToken != null) {
                httpResponse.setHeader("X-RotaryAuthentication-Token", newToken);
            }
            return new UserIdentificationInfo(userName, userName);
        }
    }

    public Boolean needLoginPrompt(HttpServletRequest httpRequest) {
        return false;
    }

    public void initPlugin(Map<String, String> parameters) {}

    public List<String> getUnAuthenticatedURLPrefix() {
        return null;
    }

    /**
     * Get token by information.
     *
     * @param username
     * @param app
     * @param device
     * @return
     */
    protected String getToken(String username, String app, String device) {
        return getTokenAuthService().getToken(username, app, device);
    }

    /**
     * Revoke token and rotary.
     *
     * @param username
     * @param token
     * @param app
     * @param device
     * @param permission
     */
    protected String revokeTokenAndRotary(String username, String token, String app, String device, String permission) {
        // Revoke token
        getTokenAuthService().revokeToken(token);
        // Adquire new token
        return getTokenAuthService().acquireToken(username, app, device, "", permission);
    }

    /**
     * Get token permission.
     *
     * @param token
     * @return
     * @throws TokenAuthenticationException
     */
    public String getTokenPermission(String token) throws TokenAuthenticationException {
        if (token == null) {
            throw new TokenAuthenticationException(
                    "Please, token is mandatory to get permission about it.");
        }
        Session session = null;
        try {
            DirectoryService directoryService = Framework.getLocalService(DirectoryService.class);
            session = directoryService.open(DIRECTORY_NAME);
            Map<String, Serializable> filter = new HashMap<>();
            filter.put(TOKEN_FIELD, token);
            DocumentModelList tokens = session.query(filter);
            if (!tokens.isEmpty()) {
                if (tokens.size() > 1) {
                    throw new TokenAuthenticationException(
                            String.format(
                                    "Found multiple tokens, please check it."));
                }
                DocumentModel tokenModel = tokens.get(0);
                return (String) tokenModel.getPropertyValue(DIRECTORY_SCHEMA + ":" + PERMISSION_FIELD);
            }
            return null;
        } finally {
            if (session != null) {
                session.close();
            }
        }
    }

    /**
     * Get user by token.
     *
     * @param token
     * @return
     */
    protected String getUserByToken(String token) {
        return getTokenAuthService().getUserName(token);
    }

    /**
     * Get token auth service.
     *
     * @return
     */
    private TokenAuthenticationService getTokenAuthService() {
        if (tokenAuthService == null) {
            tokenAuthService = Framework.getLocalService(TokenAuthenticationService.class);
        }
        return tokenAuthService;
    }
}
