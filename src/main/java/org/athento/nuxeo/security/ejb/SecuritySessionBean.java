package org.athento.nuxeo.security.ejb;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.athento.nuxeo.security.api.ChangePasswordMode;
import org.athento.nuxeo.security.api.RememberPasswordService;
import org.athento.nuxeo.security.util.PasswordHelper;
import org.jboss.seam.annotations.Install;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Observer;
import org.nuxeo.ecm.core.api.CoreSession;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.core.api.UnrestrictedSessionRunner;
import org.nuxeo.ecm.platform.ui.web.auth.NuxeoAuthenticationFilter;
import org.nuxeo.ecm.platform.usermanager.UserManager;
import org.nuxeo.ecm.webapp.helpers.EventNames;
import org.nuxeo.runtime.api.Framework;

import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

/**
 * Security session bean.
 *
 * @author <a href="vs@athento.com">Victor Sanchez</a>
 */
@Name("securitySessionBean")
@Install(precedence = Install.FRAMEWORK)
public class SecuritySessionBean {

    /** Log. */
    private static final Log LOG = LogFactory.getLog(SecuritySessionBean.class);

    /** Number of days to indicate that a password is expired. */
    private static final int DAYS_TO_EXPIRE_PASSWORD = 30 * 12; // One year

    /** Default last modification date. */
    private static final String DEFAULT_LAST_MODIFICATION = "2016-01-15";

    /**
     * Check if user password is expired.
     *
     * @param session is the core session
     */
    @Observer(EventNames.USER_SESSION_STARTED)
    public void checkExpiredPassword(CoreSession session) {
        // Check enabled password control
        Boolean checkPasswordControlEnabled = Boolean.valueOf(Framework.getProperty("athento.password.control", "true"));
        if (!checkPasswordControlEnabled) {
            return;
        }
        final UserManager userManager = Framework.getService(UserManager.class);
        final DocumentModel user = userManager.getUserModel(session.getPrincipal().getName());
        if (user != null) {
            GregorianCalendar lastModificationDate =
                    (GregorianCalendar) user.getPropertyValue("user:lastPasswordModification");
            if (lastModificationDate == null) {
                String defaultLastModification = Framework.getProperty("password.lastmodification.date", DEFAULT_LAST_MODIFICATION);
                Date lastModificationDatePassword = null;
                try {
                    lastModificationDatePassword = new SimpleDateFormat("yyyy-MM-dd").parse(defaultLastModification);
                    Calendar gc = GregorianCalendar.getInstance();
                    gc.setTime(lastModificationDatePassword);
                    user.setPropertyValue("user:lastPasswordModification", gc);
                    // Save user
                    new UnrestrictedSessionRunner(session) {
                        @Override
                        public void run() {
                            userManager.updateUser(user);
                        }
                    }.runUnrestricted();
                } catch (Exception e) {
                    LOG.error("Unable to set default last modification password", e);
                }
            } else {
                int daysToExpire = Integer.valueOf(Framework.getProperty("password.expiration.days",
                        String.valueOf(DAYS_TO_EXPIRE_PASSWORD)));
                if (PasswordHelper.isExpiredPassword(lastModificationDate, daysToExpire)) {
                    try {
                        // Redirect to site to change password
                        ExternalContext externalContext = FacesContext.getCurrentInstance().getExternalContext();
                        // Create request to change password
                        RememberPasswordService rememberPasswordService = Framework.getService(RememberPasswordService.class);
                        String reqId = rememberPasswordService
                                .submitRememberPasswordRequest((String) user.getPropertyValue("user:email"),
                                        ChangePasswordMode.expiration.name());
                        String nuxeoUrl = Framework.getProperty("nuxeo.url");
                        externalContext.redirect(nuxeoUrl + "/site/security/expiredpassword/" + reqId);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        }
    }

}
