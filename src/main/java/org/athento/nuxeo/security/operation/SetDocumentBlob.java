package org.athento.nuxeo.security.operation;

import org.athento.nuxeo.security.util.MimeUtils;
import org.nuxeo.ecm.automation.core.Constants;
import org.nuxeo.ecm.automation.core.annotations.Context;
import org.nuxeo.ecm.automation.core.annotations.Operation;
import org.nuxeo.ecm.automation.core.annotations.OperationMethod;
import org.nuxeo.ecm.automation.core.annotations.Param;
import org.nuxeo.ecm.automation.core.collectors.DocumentModelCollector;
import org.nuxeo.ecm.automation.core.util.DocumentHelper;
import org.nuxeo.ecm.core.api.Blob;
import org.nuxeo.ecm.core.api.CoreSession;
import org.nuxeo.ecm.core.api.DocumentModel;

/**
 * Set document blob.
 */
@Operation(id = SetDocumentBlob.ID, category = Constants.CAT_DOCUMENT,
        label = "Set File  (mime types controlled)", description = "Set the input file to the given property on the input document. If the xpath points to a blob list then the blob is appended to the list, otherwise the xpath should point to a blob property. If the save parameter is set the document modification will be automatically saved. Return the document.")
public class SetDocumentBlob {

    public static final String ID = "Blob.Set";

    @Context
    protected CoreSession session;

    @Param(name = "xpath", required = false, values = "file:content")
    protected String xpath = "file:content";

    @Param(name = "file")
    protected Blob blob;

    @Param(name = "save", required = false, values = "true")
    protected boolean save = true;

    @OperationMethod(collector = DocumentModelCollector.class)
    public DocumentModel run(DocumentModel doc) throws Exception {
        MimeUtils.checkMimeType(blob);
        attachBlob(doc, blob);
        return doc;
    }

    private Blob attachBlob(DocumentModel doc, Blob blob) {
        DocumentHelper.addBlob(doc.getProperty(xpath), blob);
        if (save) {
            session.saveDocument(doc);
        }
        return blob;
    }
}