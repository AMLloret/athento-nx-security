package org.athento.nuxeo.security.operation;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.nuxeo.ecm.automation.core.annotations.Context;
import org.nuxeo.ecm.automation.core.annotations.Operation;
import org.nuxeo.ecm.automation.core.annotations.OperationMethod;
import org.nuxeo.ecm.automation.core.annotations.Param;
import org.nuxeo.ecm.core.api.CoreSession;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.core.api.IdRef;
import org.nuxeo.ecm.core.api.PathRef;
import org.nuxeo.runtime.api.Framework;

import java.util.Date;

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

	private static final String DOWNLOAD_RESTLET_STRING = "%s/restAPI/athdownload/%s/%s/%s?disposition=%s";

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

    @Param(name = "expirationDate", required = false, description = "It is expiration date access")
    protected Date expirationDate;

    @Param(name = "xpath", required = false, description = "It is xpath to get blob content from document", values = { "file:content" })
    protected String xpath = "file:content";

    @Param(name = "disposition", required = false, description = "It is the download disposition mode", values = { "attachment", "inline" })
    protected String disposition = "attachment";

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
        // Update document with security information
        if (doc.hasSchema("athentosec")) {
            doc.setPropertyValue("athentosec:ips", ips);
            doc.setPropertyValue("athentosec:principals", principals);
            doc.setPropertyValue("athentosec:expirationDate", expirationDate);
            doc.setPropertyValue("athentosec:xpath", xpath);
            session.saveDocument(doc);
        }
        String host = Framework.getProperty("nuxeo.url");
        // Return download URL
        return String.format(DOWNLOAD_RESTLET_STRING, host, "default", doc.getId(), xpath, disposition);
    }

}