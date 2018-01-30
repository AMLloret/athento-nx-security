package org.athento.nuxeo.security.core;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.athento.nuxeo.security.api.CaptchaService;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.platform.usermanager.UserManager;
import org.nuxeo.runtime.api.Framework;
import org.nuxeo.runtime.model.DefaultComponent;

/**
 * Captcha service.
 */
public class CaptchaServiceImpl extends DefaultComponent implements CaptchaService {

    public static final String NAME = "org.nuxeo.athento.athento-nx-security.CaptchaService";

    /** Log. */
    private static final Log LOG = LogFactory.getLog(CaptchaServiceImpl.class);


    /**
     * Register a login failed attempt.
     *
     * @param username
     */
    @Override
    public void registerLoginFailedAttempt(String username) {
        if (username == null) {
            return;
        }
        UserManager userManager = Framework.getService(UserManager.class);
        DocumentModel user = userManager.getUserModel(username);
        if (user == null){
            return;
        }
        Long currentLoginAttempts = (Long) user.getPropertyValue("user:loginAttempts");
        user.setPropertyValue("user:loginAttempts", currentLoginAttempts + 1);
        userManager.updateUser(user);
    }

    /**
     * Reset login failed attempts.
     *
     * @param username
     */
    @Override
    public void resetLoginFailedAttempts(String username) {
        UserManager userManager = Framework.getService(UserManager.class);
        DocumentModel user = userManager.getUserModel(username);
        if (user == null){
            return;
        }
        user.setPropertyValue("user:loginAttempts", 0);
        userManager.updateUser(user);
        LOG.info("Reseting login attempts for " + user.getPropertyValue("user:username") + " => " + user.getPropertyValue("user:loginAttempts"));
    }

    /**
     * Get login failed attempts for an user.
     *
     * @param username
     * @return
     */
    @Override
    public int getLoginFailedAttempts(String username) {
        UserManager userManager = Framework.getService(UserManager.class);
        DocumentModel user = userManager.getUserModel(username);
        if (user == null){
            return 0;
        }
        Long currentLoginAttemps = (Long) user.getPropertyValue("user:loginAttempts");
        return currentLoginAttemps.intValue();
    }
}
