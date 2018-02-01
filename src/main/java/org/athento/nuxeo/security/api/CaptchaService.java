package org.athento.nuxeo.security.api;


import java.io.Serializable;

/**
 * Captcha service.
 */
public interface CaptchaService extends Serializable {

    /**
     * Register a login failed attempt.
     *
     * @param username
     */
    void registerLoginFailedAttempt(String username);

    /**
     * Get login failed attempts for an user.
     *
     * @param username
     * @return
     */
    int getLoginFailedAttempts(String username);

    /**
     * Reset login failed attempts.
     *
     * @param username
     */
    void resetLoginFailedAttempts(String username);
}
