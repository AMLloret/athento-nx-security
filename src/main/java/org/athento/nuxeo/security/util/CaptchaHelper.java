package org.athento.nuxeo.security.util;

import org.athento.nuxeo.security.api.CaptchaService;
import org.athento.nuxeo.security.core.CaptchaServiceImpl;
import org.nuxeo.runtime.api.Framework;

/**
 * Captcha helper.
 */
public final class CaptchaHelper {

    /**
     * Get login attempts for an user.
     *
     * @param username
     * @return
     */
    public static int getLoginAttempts(String username) {
        CaptchaService captchaService = (CaptchaService) Framework.getRuntime().getComponent(
                CaptchaServiceImpl.NAME);
        return captchaService.getLoginFailedAttempts(username);
    }

    /**
     * Register login attempt.
     *
     * @param username
     */
    public static void registerLoginAttempt(String username) {
        CaptchaService captchaService = (CaptchaService) Framework.getRuntime().getComponent(
                CaptchaServiceImpl.NAME);
        captchaService.registerLoginFailedAttempt(username);
    }

}
