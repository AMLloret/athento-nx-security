package org.athento.nuxeo.security.ejb;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.athento.nuxeo.security.api.InvalidPasswordException;
import org.athento.nuxeo.security.api.RememberPasswordSave;
import org.athento.nuxeo.security.api.RememberPasswordService;
import org.athento.nuxeo.security.core.RememberPasswordComponent;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Install;
import org.jboss.seam.annotations.Name;
import static org.jboss.seam.ScopeType.CONVERSATION;

import org.jboss.seam.annotations.Scope;
import org.jboss.seam.core.Events;
import org.jboss.seam.faces.FacesMessages;
import org.nuxeo.ecm.core.api.ClientException;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.core.api.repository.RepositoryManager;
import org.nuxeo.ecm.webapp.helpers.ResourcesAccessor;
import org.nuxeo.ecm.webapp.security.AbstractUserGroupManagement;
import org.nuxeo.ecm.webapp.security.UserManagementActions;
import org.nuxeo.runtime.api.Framework;

import javax.faces.application.FacesMessage;
import java.io.Serializable;

/**
 * User action bean.
 *
 * @author <a href="vs@athento.com">Victor Sanchez</a>
 */
@Name("athentoUserAction")
@Scope(CONVERSATION)
@Install(precedence = Install.FRAMEWORK)
public class UserActionBean implements Serializable {

    /** Log. */
    private static final Log LOG = LogFactory.getLog(UserActionBean.class);

    /** Number of days to indicate that a password is expired. */
    private static final int DAYS_TO_EXPIRE_PASSWORD = 30 * 12; // One year

    /** Default last modification date. */
    private static final String DEFAULT_LAST_MODIFICATION = "2016-01-15";

    @In(required = true)
    protected UserManagementActions userManagementActions;

    @In(create = true, required = false)
    protected FacesMessages facesMessages;

    @In(create = true)
    protected ResourcesAccessor resourcesAccessor;

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
        String password = (String) selectedUser.getPropertyValue("user:password");
        try {
            RememberPasswordSave save = new RememberPasswordSave(getTargetRepositoryName(), selectedUser,
                    (String) selectedUser.getPropertyValue("user:username"), password);
            save.runUnrestricted();
            LOG.info("Changed.");
            String message = resourcesAccessor.getMessages().get("label.userManager.password.changed");
            facesMessages.add(FacesMessage.SEVERITY_INFO, message);
        } catch (InvalidPasswordException e) {
            String message = resourcesAccessor.getMessages().get("label.error.invalidPassword");
            facesMessages.add(FacesMessage.SEVERITY_ERROR, message);
        }
        fireSeamEvent("usersListingChanged");
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

    /**
     * Fire seam events.
     *
     * @param eventName
     */
    protected void fireSeamEvent(String eventName) {
        Events evtManager = Events.instance();
        evtManager.raiseEvent(eventName);
    }

    /**
     * Get target repository name.
     *
     * @return
     */
    protected String getTargetRepositoryName() {
        String repoName;
        try {
            RepositoryManager rm = Framework.getService(RepositoryManager.class);
            repoName = rm.getDefaultRepositoryName();
        } catch (Exception e) {
            LOG.error("Error while getting default repository name", e);
            repoName = "default";
        }
        return repoName;
    }

}
