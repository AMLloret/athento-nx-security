package org.athento.nuxeo.security.ejb;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.athento.nuxeo.security.api.InvalidPasswordException;
import org.athento.nuxeo.security.api.RememberPasswordSave;
import org.athento.nuxeo.security.api.RememberPasswordService;
import org.athento.nuxeo.security.util.PasswordHelper;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Install;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.core.Events;
import org.jboss.seam.faces.FacesMessages;
import org.nuxeo.ecm.core.api.ClientException;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.core.api.repository.RepositoryManager;
import org.nuxeo.ecm.platform.ui.web.util.ComponentUtils;
import org.nuxeo.ecm.webapp.helpers.ResourcesAccessor;
import org.nuxeo.ecm.webapp.security.UserManagementActions;
import org.nuxeo.runtime.api.Framework;

import javax.faces.application.FacesMessage;
import javax.faces.component.UIComponent;
import javax.faces.component.UIInput;
import javax.faces.context.FacesContext;
import javax.faces.validator.ValidatorException;
import java.io.Serializable;
import java.util.Map;

import static org.jboss.seam.ScopeType.CONVERSATION;

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
     * Validate password.
     *
     * @param context
     * @param component
     * @param value
     */
    public void validatePassword(FacesContext context, UIComponent component, Object value) {

        UIInput currentPasswordInput = getReferencedComponent("currentPasswordInputId", component);
        Object firstPassword = getReferencedComponent("firstPasswordInputId", component).getLocalValue();
        Object secondPassword = getReferencedComponent("secondPasswordInputId", component).getLocalValue();

        // Get selected user
        DocumentModel selectedUser = userManagementActions.getSelectedUser();
        if (selectedUser == null) {
            throw new ClientException("Selected user must be not null");
        }
        // Check current password
        String password = (String) selectedUser.getPropertyValue("user:password");
        if (password == null || !PasswordHelper.verifyPassword((String) currentPasswordInput.getLocalValue(), password)) {
            FacesMessage fmessage = new FacesMessage(FacesMessage.SEVERITY_ERROR, ComponentUtils.translate(context,
                    "label.userManager.password.check", new String[0]), null);
            context.addMessage(currentPasswordInput.getClientId(context), new FacesMessage(FacesMessage.SEVERITY_ERROR, ComponentUtils.translate(context,
                    "label.userManager.password.invalid", new String[0]), null));
            throw new ValidatorException(fmessage);
        }

        if (firstPassword == null || secondPassword == null) {
            LOG.error("Cannot validate passwords: value(s) not found");
            return;
        }

        if (!firstPassword.equals(secondPassword)) {
            FacesMessage fmessage = new FacesMessage(FacesMessage.SEVERITY_ERROR, ComponentUtils.translate(context,
                    "label.userManager.password.not.match", new String[0]), null);
            throw new ValidatorException(fmessage);
        }

    }

    /**
     * Change password. This method overrides {@link UserManagementActions#changePassword()} of Nuxeo DM.}
     *
     * @return
     */
    public String changePassword() {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Changing password with Athento security manager...");
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

    /**
     * Get value from JSF component.
     *
     * @param attribute
     * @param component
     * @return
     */
    private UIInput getReferencedComponent(String attribute, UIComponent component) {
        Map<String, Object> attributes = component.getAttributes();
        String targetComponentId = (String) attributes.get(attribute);

        if (targetComponentId == null) {
            LOG.error(String.format("Target component id (%s) not found in attributes", attribute));
            return null;
        }

        UIInput targetComponent = (UIInput) component.findComponent(targetComponentId);
        if (targetComponent == null) {
            return null;
        }

        return targetComponent;
    }

}
