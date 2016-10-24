package org.athento.nuxeo.security.ejb;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.athento.nuxeo.security.api.ChangePasswordMode;
import org.athento.nuxeo.security.api.RememberPasswordService;
import org.athento.nuxeo.security.util.PasswordHelper;
import org.jboss.seam.annotations.Install;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Observer;
import org.jboss.seam.faces.Redirect;
import org.nuxeo.ecm.core.api.CoreSession;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.platform.usermanager.UserManager;
import org.nuxeo.ecm.webapp.helpers.EventNames;
import org.nuxeo.runtime.api.Framework;

import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import java.io.IOException;
import java.util.Calendar;
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
    private static final int DAYS_TO_EXPIRE_PASSWORD = 30;

    /**
     * Check if user password is expired.
     *
     * @param session is the core session
     */
    @Observer(EventNames.USER_SESSION_STARTED)
    public void checkExpiredPassword(CoreSession session) {
        UserManager userManager = Framework.getService(UserManager.class);
        DocumentModel user = userManager.getUserModel(session.getPrincipal().getName());
        if (user != null) {
            GregorianCalendar lastModificationDate =
                    (GregorianCalendar) user.getPropertyValue("user:lastPasswordModification");
            if (PasswordHelper.isExpiredPassword(lastModificationDate, DAYS_TO_EXPIRE_PASSWORD)) {
                try {
                    // Redirect to site to change password
                    ExternalContext externalContext = FacesContext.getCurrentInstance().getExternalContext();
                    // Create request to change password
                    RememberPasswordService rememberPasswordService = Framework.getService(RememberPasswordService.class);
                    String reqId = rememberPasswordService.submitRememberPasswordRequest((String) user.getPropertyValue("user:email"), ChangePasswordMode.expiration.name());
                    String nuxeoUrl = Framework.getProperty("nuxeo.url");
                    externalContext.redirect(nuxeoUrl + "/site/security/expiredpassword/" + reqId);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

}
