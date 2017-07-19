package org.athento.nuxeo.security.operation;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.athento.nuxeo.security.api.TokenException;
import org.athento.nuxeo.security.util.PasswordHelper;
import org.athento.nuxeo.security.util.SignHelper;
import org.nuxeo.ecm.automation.core.annotations.Context;
import org.nuxeo.ecm.automation.core.annotations.Operation;
import org.nuxeo.ecm.automation.core.annotations.OperationMethod;
import org.nuxeo.ecm.automation.core.annotations.Param;
import org.nuxeo.ecm.core.api.CoreSession;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.core.api.IdRef;
import org.nuxeo.ecm.core.api.PathRef;
import org.nuxeo.runtime.api.Framework;

import java.io.Serializable;
import java.util.*;

/**
 * Generate a public URL to download a document content.
 *
 * @author victorsanchez
 *
 */
@Operation(id = GetPublicURLOperation.ID, category = "Athento", label = "Get public URL to download", description = "Return a public URL to download a document content")
public class GetPublicURLOperation {

	/** Log. */
	private static final Log LOG = LogFactory.getLog(GetPublicURLOperation.class);

	private static final String DOWNLOAD_RESTLET_STRING = "%s/restAPI/athdownload/%s/%s/%s?d=%s&t=%s";

    /** Operation ID. */
	public static final String ID = "Athento.GetPublicURL";

    @Context
    protected CoreSession session;

    @Param(name = "document", required = false, description = "It is document to get the public URL")
    protected String document;

    @Param(name = "principals", required = false, description = "It is the allowed principals, separated by comma")
    protected String principals;

    @Param(name = "ips", required = false, description = "It is the allowed IPs, separated by comma")
    protected String ips;

    @Param(name = "onlyOneUse", required = false, description = "Only one use for download document")
    protected boolean onlyOneUse = false;

    @Param(name = "expirationDate", required = false, description = "It is expiration date access")
    protected Date expirationDate;

    @Param(name = "xpath", required = false, description = "It is xpath to get blob content from document", values = { "file:content" })
    protected String xpath = "file:content";

    @Param(name = "disposition", required = false, description = "It is the download disposition mode", values = { "attachment", "inline" })
    protected String disposition = "attachment";

    @Param(name = "auth", required = false, description = "It is check metadata list for authorization")
    protected String auth;

    /**
     * Operation method.
     *
     * @return
     * @throws Exception
     */
	@OperationMethod
	public String run() throws Exception {
	    DocumentModel doc;
	    if (document.startsWith("/")) {
	        doc = session.getDocument(new PathRef(document));
        } else {
            doc = session.getDocument(new IdRef(document));
        }
        return run(doc);
	}

    /**
     * Operation method.
     *
     * @return
     * @throws Exception
     */
    @OperationMethod
    public String run(DocumentModel doc) throws Exception {
        String token = null;
        // Update document with security information
        if (doc.hasSchema("athentosec")) {
            doc.setPropertyValue("athentosec:ips", ips);
            doc.setPropertyValue("athentosec:principals", principals);
            doc.setPropertyValue("athentosec:xpath", xpath);
            // Sign a new token
            try {
                token = addNewSignedToken(doc);
            } catch (TokenException e) {
                LOG.error("Unable to generate new signed token", e);
            }
            session.saveDocument(doc);
        } else {
            throw new TokenException("Unable to generate the public url for document type " + doc.getType());
        }
        String host = Framework.getProperty("nuxeo.url");
        // Return download URL
        String url = String.format(DOWNLOAD_RESTLET_STRING, host, "default", doc.getId(), xpath, disposition, token);
        if (auth != null) {
            url += "&auth=" + auth;
        }
        return url;
    }

    /**
     * Add new signed token.
     *
     * @param doc
     * @return new signed token
     * @throws TokenException on generation error
     */
    private String addNewSignedToken(DocumentModel doc) throws TokenException {
        String token = PasswordHelper.generateSecToken(128);
        String signedToken = SignHelper.getSignedToken(token);
        ArrayList<Map<String, Serializable>> tokens = (ArrayList) doc.getPropertyValue("athentosec:tokens");
        HashMap<String, Serializable> tokenInfo = new HashMap<>();
        tokenInfo.put("sign", signedToken);
        tokenInfo.put("onlyOneUse", onlyOneUse);
        tokenInfo.put("expirationDate", expirationDate);
        tokens.add(tokenInfo);
        doc.setPropertyValue("athentosec:tokens", tokens);
        return token;
    }

}