package org.athento.nuxeo.security.authenticator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.athento.nuxeo.security.api.CaptchaService;
import org.nuxeo.common.utils.URIUtils;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.core.api.DocumentModelList;
import org.nuxeo.ecm.platform.api.login.UserIdentificationInfo;
import org.nuxeo.ecm.platform.ui.web.auth.interfaces.NuxeoAuthenticationPlugin;
import org.nuxeo.ecm.platform.ui.web.auth.plugins.FormAuthenticator;
import org.nuxeo.ecm.platform.usermanager.UserManager;
import org.nuxeo.runtime.api.Framework;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.Serializable;
import java.util.*;

import static org.nuxeo.ecm.platform.ui.web.auth.NXAuthConstants.*;

/**
 * Forma captcha authenticator. Based on {@link FormAuthenticator of Nuxeo (c)}.
 */
public class FormCaptchaAuthenticator implements NuxeoAuthenticationPlugin {

    private static final Log LOG = LogFactory.getLog(FormAuthenticator.class);

    private static final String CAPTCHA_ERROR = "Captcha error";
    private static final String LOGIN_CAPTCHA_FAILED = "captchaError";
    public static final String CAPTCHA_UNDEFINED_HASH = "undefinedHash";

    /** Max login attemps. */
    private static final int MAX_LOGIN_ATTEMPS = 5;

    protected String loginPage = "login.jsp";

    protected String usernameKey = USERNAME_KEY;

    protected String passwordKey = PASSWORD_KEY;

    protected String captchaKey = "captcha";

    protected String getLoginPage() {
        return loginPage;
    }

    public Boolean handleLoginPrompt(HttpServletRequest httpRequest, HttpServletResponse httpResponse, String baseURL) {
        try {
            Map<String, String> parameters = new HashMap<String, String>();
            String redirectUrl = baseURL + getLoginPage();
            @SuppressWarnings("unchecked")
            Enumeration<String> paramNames = httpRequest.getParameterNames();
            while (paramNames.hasMoreElements()) {
                String name = paramNames.nextElement();
                String value = httpRequest.getParameter(name);
                parameters.put(name, value);
            }
            HttpSession session = httpRequest.getSession(false);
            String requestedUrl = null;
            boolean isTimeout = false;
            if (session != null) {
                requestedUrl = (String) session.getAttribute(START_PAGE_SAVE_KEY);
                Object obj = session.getAttribute(SESSION_TIMEOUT);
                if (obj != null) {
                    isTimeout = (Boolean) obj;
                }
            }
            if (requestedUrl != null && !requestedUrl.equals("")) {
                parameters.put(REQUESTED_URL, requestedUrl);
            }
            String loginError = (String) httpRequest.getAttribute(LOGIN_ERROR);
            if (loginError != null) {
                if (ERROR_USERNAME_MISSING.equals(loginError)) {
                    parameters.put(LOGIN_MISSING, "true");
                } else if (CAPTCHA_ERROR.equals(loginError)) {
                    parameters.put(LOGIN_CAPTCHA_FAILED, "true");
                } else if (ERROR_CONNECTION_FAILED.equals(loginError)) {
                    parameters.put(LOGIN_CONNECTION_FAILED, "true");
                    parameters.put(LOGIN_FAILED, "true"); // compat
                } else {
                    parameters.put(LOGIN_FAILED, "true");
                }
            }
            if (isTimeout) {
                parameters.put(SESSION_TIMEOUT, "true");
            }

            parameters.remove(passwordKey);
            parameters.remove(captchaKey);
            parameters.remove(CAPTCHA_UNDEFINED_HASH);
            redirectUrl = URIUtils.addParametersToURIQuery(redirectUrl, parameters);
            httpResponse.sendRedirect(redirectUrl);
        } catch (IOException e) {
            LOG.error(e, e);
            return Boolean.FALSE;
        }
        return Boolean.TRUE;
    }

    public UserIdentificationInfo handleRetrieveIdentity(HttpServletRequest httpRequest,
                                                         HttpServletResponse httpResponse) {
        String userName = httpRequest.getParameter(usernameKey);
        String password = httpRequest.getParameter(passwordKey);
        String captcha = httpRequest.getParameter(captchaKey);
        if (httpRequest.getParameter(FORM_SUBMITTED_MARKER) != null && (userName == null || userName.length() == 0)) {
            httpRequest.setAttribute(LOGIN_ERROR, ERROR_USERNAME_MISSING);
        }
        String hash = httpRequest.getParameter(CAPTCHA_UNDEFINED_HASH);
        if (captcha != null && hash != null && !hash.isEmpty()) {
            if (!rpHash(captcha).equals(
                    hash)) {
                httpRequest.setAttribute(LOGIN_ERROR, CAPTCHA_ERROR);
                return null;
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Reseting login attempts...");
                }
                // Reset login failed attempts
                CaptchaService captchaService = Framework.getService(CaptchaService.class);
                captchaService.resetLoginFailedAttempts(userName);
            }
        }
        if (userName == null || userName.length() == 0) {
            return null;
        }
        // Lookup for username
        UserManager userManager = Framework.getService(UserManager.class);
        DocumentModel userModel = userManager.getUserModel(userName);
        if (userModel == null) {
            // Find user for other fields
            String [] userFields = Framework.getProperty("athento.login.alternativefields", "").split(",");
            for (String userField : userFields) {
                if (userField.isEmpty()) {
                    continue;
                }
                try {
                    Map<String, Serializable> fields = new HashMap<>();
                    fields.put(userField.trim(), userName);
                    DocumentModelList users = userManager.searchUsers(fields, null);
                    if (!users.isEmpty()) {
                        DocumentModel user = users.get(0);
                        userName = (String) user.getPropertyValue("user:username");
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Username to use " + userName);
                        }
                        break;
                    }
                } catch (Exception e) {
                    LOG.error("Unable to check alternative field " + userField.trim(), e);
                }
            }

        }
        return new UserIdentificationInfo(userName, password);
    }

    public Boolean needLoginPrompt(HttpServletRequest httpRequest) {
        return Boolean.TRUE;
    }

    public void initPlugin(Map<String, String> parameters) {
        if (parameters.get("LoginPage") != null) {
            loginPage = parameters.get("LoginPage");
        }
        if (parameters.get("UsernameKey") != null) {
            usernameKey = parameters.get("UsernameKey");
        }
        if (parameters.get("PasswordKey") != null) {
            passwordKey = parameters.get("PasswordKey");
        }
        if (parameters.get("CaptchaKey") != null) {
            captchaKey = parameters.get("CaptchaKey");
        }
    }

    public List<String> getUnAuthenticatedURLPrefix() {
        List<String> prefix = new ArrayList<String>();
        prefix.add(getLoginPage());
        return prefix;
    }

    private  String rpHash(String value) {
        int hash = 5381;
        value = value.toUpperCase();
        for(int i = 0; i < value.length(); i++) {
            hash = ((hash << 5) + hash) + value.charAt(i);
        }
        return String.valueOf(hash);
    }

}
