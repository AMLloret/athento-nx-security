package org.athento.nuxeo.security.api;

import org.nuxeo.ecm.core.api.ClientException;
import org.nuxeo.ecm.core.api.CoreSession;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.core.api.DocumentModelList;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

/**
 * Remember password service.
 *
 * @author <a href="vs@athento.com">Victor Sanchez</a>
 */
public interface RememberPasswordService {

    /**
     * Stores a send mail for remember password request and return a unique ID for it.
     *
     * @param email
     * @return docid of request
     */
    String submitRememberPasswordRequest(String email)
            throws RememberPasswordException;

    /**
     * Delete remember password request.
     *
     * @param session
     * @param registrationDocs
     */
    void deleteRememberPasswordRequests(CoreSession session,
                                        List<DocumentModel> registrationDocs);

    /**
     * Check if change password request exists.
     *
     * @param requestId
     */
    void checkChangePasswordRequestId(String requestId);

    /**
     * Validate password change.
     *
     * @param requestId
     * @param additionalInfo
     * @return
     * @throws ClientException
     * @throws RememberPasswordException
     */
    Map<String, Serializable> validatePasswordChange(String requestId, Map<String, Serializable> additionalInfo) throws ClientException,
            RememberPasswordException;

    /**
     * Get remember password request by email.
     *
     * @param email
     * @return
     * @throws ClientException
     */
    DocumentModelList getRememberPasswordForEmail(final String email) throws ClientException;

    /**
     * Change password.
     *
     * @param email
     * @param password
     * @throws RememberPasswordException
     */
    void changePassword(DocumentModel email, String password) throws RememberPasswordException;
}
