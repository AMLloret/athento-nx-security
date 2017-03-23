package org.athento.nuxeo.security.ejb;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.athento.nuxeo.security.api.ChangePasswordMode;
import org.athento.nuxeo.security.api.RememberPasswordService;
import org.athento.nuxeo.security.util.PasswordHelper;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Install;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Observer;
import org.nuxeo.ecm.core.api.ClientException;
import org.nuxeo.ecm.core.api.CoreSession;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.platform.ui.web.auth.NuxeoAuthenticationFilter;
import org.nuxeo.ecm.platform.usermanager.UserManager;
import org.nuxeo.ecm.webapp.helpers.EventNames;
import org.nuxeo.ecm.webapp.security.UserManagementActions;
import org.nuxeo.ecm.webengine.model.ValidatorException;
import org.nuxeo.runtime.api.Framework;

import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import java.io.IOException;
import java.io.Serializable;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * User action bean.
 *
 * @author <a href="vs@athento.com">Victor Sanchez</a>
 */
@Name("athentoUserAction")
@Install(precedence = Install.FRAMEWORK)
public class UserActionBean {

    /** Log. */
    private static final Log LOG = LogFactory.getLog(UserActionBean.class);

    /** Number of days to indicate that a password is expired. */
    private static final int DAYS_TO_EXPIRE_PASSWORD = 30 * 12; // One year

    /** Default last modification date. */
    private static final String DEFAULT_LAST_MODIFICATION = "2016-01-15";

    @In(required = true)
    private UserManagementActions userManagementActions;

    /**
     * Change password. This method overrides {@link UserManagementActions#changePassword()} of Nuxeo DM.}
     *
     * @return
     */
    public String changePassword() {
        if (LOG.isInfoEnabled()) {
            LOG.info("Changing password with Athento security manager...");
        }
        // Get selected user
        DocumentModel selectedUser = userManagementActions.getSelectedUser();
        if (selectedUser == null) {
            throw new ClientException("Selected user must be not null");
        }
        RememberPasswordService passwordService = getService();
        String password = (String) selectedUser.getPropertyValue("user:password");
        // Validate the password request
        passwordService.changePassword(selectedUser, password);
        return null;
    }

    /**
     * Get service.
     *
     * @return
     */
    protected RememberPasswordService getService() {
        return Framework.getLocalService(RememberPasswordService.class);
    }

}
