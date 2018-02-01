package org.athento.nuxeo.security.api;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.athento.nuxeo.security.core.RememberPasswordComponent;
import org.athento.nuxeo.security.util.PasswordHelper;
import org.nuxeo.ecm.core.api.ClientException;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.core.api.UnrestrictedSessionRunner;
import org.nuxeo.ecm.platform.usermanager.UserManager;
import org.nuxeo.runtime.api.Framework;

import java.util.Arrays;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.List;

/**
 * Class to save the password into user.
 */
public class RememberPasswordSave extends UnrestrictedSessionRunner {

    protected static Log LOG = LogFactory.getLog(RememberPasswordComponent.class);

    private DocumentModel rememberPasswordDocument;
    private String username;
    private String password;

    public RememberPasswordSave(String repo, DocumentModel document, String username, String password) {
        super(repo);
        this.rememberPasswordDocument = document;
        this.username = username;
        this.password = password;
    }

    @Override
    public void run() throws ClientException {
        if (!PasswordHelper.isValidPassword(password)) {
            throw new InvalidPasswordException("Invalid password.");
        }
        // Update user password
        UserManager userManager = Framework.getService(UserManager.class);
        DocumentModel user = userManager.getUserModel(this.username);
        // Get current password and save to oldPasswords
        String oldPasswords = (String) user.getPropertyValue("user:oldPasswords");
        // Check if the new password is in old password
        if (oldPasswords != null && !oldPasswords.isEmpty()) {
            // Decrypt old passwords
            oldPasswords = new String(PasswordHelper.CipherUtil.decrypt(oldPasswords));
            List<String> oldPasswordList = Arrays.asList(oldPasswords.split(","));
            int oldPasswordDays = Integer.valueOf(Framework.getProperty("password.oldpassword.days",
                    String.valueOf(RememberPasswordComponent.OLD_PASSWORD_DAYS)));
            if (PasswordHelper.isOldPassword(password, oldPasswordList, oldPasswordDays)) {
                throw new OldPasswordException("Your new password was a old password");
            }
        } else {
            oldPasswords = "";
        }
        oldPasswords += "," + password + ":" + Calendar.getInstance().getTimeInMillis();
        String cipherOld = PasswordHelper.CipherUtil.encrypt(oldPasswords);
        if (cipherOld != null) {
            oldPasswords = new String(cipherOld);
            user.setPropertyValue("user:oldPasswords", oldPasswords);
        }
        user.setPropertyValue("user:password", password);
        // Set date for the new password
        user.setPropertyValue("user:lastPasswordModification", new GregorianCalendar());
        userManager.updateUser(user);
        // Update remember password document
        if (rememberPasswordDocument != null && rememberPasswordDocument.getRef() != null) {
            // Transition for remember request
            session.followTransition(rememberPasswordDocument, "change");
        }
    }

}
