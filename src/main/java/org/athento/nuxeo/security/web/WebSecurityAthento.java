package org.athento.nuxeo.security.web;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.athento.nuxeo.security.api.AlreadyRememberPasswordException;
import org.athento.nuxeo.security.api.RememberPasswordException;
import org.athento.nuxeo.security.api.RememberPasswordService;
import org.nuxeo.ecm.core.api.ClientException;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.platform.web.common.vh.VirtualHostHelper;
import org.nuxeo.ecm.webengine.forms.FormData;
import org.nuxeo.ecm.webengine.model.Template;
import org.nuxeo.ecm.webengine.model.WebObject;
import org.nuxeo.ecm.webengine.model.impl.ModuleRoot;
import org.nuxeo.runtime.api.Framework;

import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.ws.rs.*;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

/**
 * Web security site.
 *
 * @author <a href="vs@athento.com">Victor Sanchez</a>
 */
@Path("/security")
@Produces("text/html;charset=UTF-8")
@WebObject(type = "webSecurity")
public class WebSecurityAthento extends ModuleRoot {

    /** Log. */
    private static final Log LOG = LogFactory.getLog(WebSecurityAthento.class);

    /**
     * Change password.
     *
     * @return
     * @throws Exception
     */
    @POST
    @Path("changepassword")
    public Object changePassword() throws Exception {
        RememberPasswordService rememberPasswordService = getService();

        FormData formData = getContext().getForm();
        String requestId = formData.getString("RequestId");
        String password = formData.getString("Password");
        String passwordConfirmation = formData.getString("PasswordConfirmation");

        // Check if the requestId is an existing one
        try {
            rememberPasswordService.checkChangePasswordRequestId(requestId);
        } catch (AlreadyRememberPasswordException ape) {
            return getView("ChangePasswordErrorTemplate").arg("exceptionMsg",
                    ctx.getMessage("label.error.requestAlreadyProcessed"));
        } catch (RememberPasswordException ue) {
            return getView("ChangePasswordErrorTemplate").arg("exceptionMsg",
                    ctx.getMessage("label.error.requestNotExisting", requestId));
        }

        // Check if both entered passwords are correct
        if (password == null || "".equals(password.trim())) {
            return redisplayFormWithErrorMessage("EnterPassword",
                    ctx.getMessage("label.webSecurity.validation.password"),
                    formData);
        }
        if (passwordConfirmation == null
                || "".equals(passwordConfirmation.trim())) {
            return redisplayFormWithErrorMessage(
                    "EnterPassword",
                    ctx.getMessage("label.webSecurity.validation.passwordconfirmation"),
                    formData);
        }
        password = password.trim();
        passwordConfirmation = passwordConfirmation.trim();
        if (!password.equals(passwordConfirmation)) {
            return redisplayFormWithErrorMessage(
                    "EnterPassword",
                    ctx.getMessage("label.webSecurity.validation.passwordvalidation"),
                    formData);
        }
        Map<String, Serializable> changePasswordData = new HashMap<String, Serializable>();
        try {
            Map<String, Serializable> additionalInfo = buildAdditionalInfos();

            // Add the entered password to the document model
            additionalInfo.put("password", password);
            // Validate the password request
            changePasswordData = rememberPasswordService.validatePasswordChange(requestId,
                    additionalInfo);
            // Change password
            rememberPasswordService.changePassword((DocumentModel) changePasswordData.get("changePasswordDoc"), password);
        } catch (AlreadyRememberPasswordException ape) {
            LOG.info("Try to validate an already processed remember password");
            return getView("ChangePasswordErrorTemplate").arg("exceptionMsg",
                    ctx.getMessage("label.error.requestAlreadyProcessed"));
        } catch (RememberPasswordException ue) {
            LOG.warn("Unable to validate change password request", ue);
            return getView("ChangePasswordErrorTemplate").arg("exceptionMsg",
                    ctx.getMessage("label.errror.requestNotAccepted"));
        } catch (ClientException e) {
            LOG.error("Error while validating change password request", e);
            return getView("ChangePasswordErrorTemplate").arg("error", e);
        }
        // User redirected to the logout page after validating the password
        String webappName = VirtualHostHelper.getWebAppName(getContext().getRequest());
        String logoutUrl = "/" + webappName + "/logout";

        return getView("PasswordChanged").arg("data", changePasswordData).arg("logout", logoutUrl);
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
     * Send change password request by email.
     *
     * @return
     * @throws Exception
     */
    @POST
    @Path("sendpassword")
    public Object sendPassword() throws Exception {
        FormData formData = getContext().getForm();
        String email = formData.getString("Email");
        if (email == null || email.trim().isEmpty() || !isValidEmailAddress(email)) {
            return redisplayFormWithErrorMessage(
                    "EnterEmail",
                    ctx.getMessage("label.webSecurity.emailerror"),
                    formData);
        }
        RememberPasswordService rememberPasswordService = getService();
        rememberPasswordService.submitRememberPasswordRequest(email);
        // User redirected to the logout page after validating the password
        String webappName = VirtualHostHelper.getWebAppName(getContext().getRequest());
        String logoutUrl = "/" + webappName + "/logout";
        return getView("PasswordSent").arg("logout", logoutUrl);
    }

    /**
     * Check valid email.
     *
     * @param email
     * @return
     */
    public static boolean isValidEmailAddress(String email) {
        boolean result = true;
        try {
            InternetAddress emailAddr = new InternetAddress(email);
            emailAddr.validate();
        } catch (AddressException ex) {
            result = false;
        }
        return result;
    }

    /**
     * Enter new password.
     *
     * @param requestId
     * @return
     * @throws Exception
     */
    @GET
    @Path("enterpassword/{requestId}")
    public Object validatePasswordForm(@PathParam("requestId")
                                       String requestId) throws Exception {

        RememberPasswordService rememberPasswordService = getService();
        try {
            rememberPasswordService.checkChangePasswordRequestId(requestId);
        } catch (AlreadyRememberPasswordException ape) {
            return getView("ChangePasswordErrorTemplate").arg("exceptionMsg",
                    ctx.getMessage("label.error.requestAlreadyProcessed"));
        } catch (RememberPasswordException ue) {
            return getView("ChangePasswordErrorTemplate").arg("exceptionMsg",
                    ctx.getMessage("label.error.requestNotExisting", requestId));
        }

        Map<String, String> data = new HashMap<String, String>();
        data.put("RequestId", requestId);
        return getView("EnterPassword").arg("data", data);
    }

    /**
     * Enter and send email form view.
     *
     * @return the view
     * @throws Exception on view error
     */
    @GET
    @Path("enteremailforremember")
    public Object entrerEmailForm() throws Exception {
        Map<String, String> data = new HashMap<String, String>();
        return getView("EnterEmail").arg("data", data);
    }

    protected Map<String, Serializable> buildAdditionalInfos() {
        return new HashMap<String, Serializable>();
    }

    protected Template redisplayFormWithMessage(String messageType,
                                                String formName, String message, FormData data) {
        Map<String, String> savedData = new HashMap<String, String>();
        for (String key : data.getKeys()) {
            savedData.put(key, data.getString(key));
        }
        return getView(formName).arg("data", savedData).arg(messageType,
                message);
    }

    protected Template redisplayFormWithInfoMessage(String formName,
                                                    String message, FormData data) {
        return redisplayFormWithMessage("info", formName, message, data);
    }

    protected Template redisplayFormWithErrorMessage(String formName,
                                                     String message, FormData data) {
        return redisplayFormWithMessage("err", formName, message, data);
    }

}