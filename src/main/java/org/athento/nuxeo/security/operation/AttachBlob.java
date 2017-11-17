package org.athento.nuxeo.security.operation;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.athento.nuxeo.security.util.MimeUtils;
import org.nuxeo.ecm.automation.core.Constants;
import org.nuxeo.ecm.automation.core.annotations.Context;
import org.nuxeo.ecm.automation.core.annotations.Operation;
import org.nuxeo.ecm.automation.core.annotations.OperationMethod;
import org.nuxeo.ecm.automation.core.annotations.Param;
import org.nuxeo.ecm.automation.core.collectors.BlobCollector;
import org.nuxeo.ecm.automation.core.util.DocumentHelper;
import org.nuxeo.ecm.core.api.Blob;
import org.nuxeo.ecm.core.api.CoreSession;
import org.nuxeo.ecm.core.api.DocumentModel;

/**
 * Attach blob.
 */
@Operation(id = AttachBlob.ID, category = Constants.CAT_BLOB, label = "Attach File (mime types controlled)",
        description = "Attach the input file to the document given as a parameter. If the xpath points to a blob list then the blob is appended to the list, otherwise the xpath should point to a blob property. If the save parameter is set the document modification will be automatically saved. Return the blob.")
public class AttachBlob {

    public static final String ID = "Blob.Attach";

    @Context
    protected CoreSession session;

    @Param(name = "xpath", required = false, values = "file:content")
    protected String xpath = "file:content";

    @Param(name = "document")
    protected DocumentModel doc;

    @Param(name = "save", required = false, values = "true")
    protected boolean save = true;

    @OperationMethod(collector = BlobCollector.class)
    public Blob run(Blob blob) throws Exception {
        Blob returnedValue;
        // will throw an Exception if is not allowed (if DocType and mimeType match)
        MimeUtils.checkMimeType(blob);
        returnedValue = attachBlob(blob);
        return returnedValue;
    }



    private Blob attachBlob(Blob _blob) {
        DocumentHelper.addBlob(doc.getProperty(xpath), _blob);
        if (save) {
            doc = session.saveDocument(doc);
        }
        return _blob;
    }

    private static Log _log = LogFactory.getLog(AttachBlob.class);
}