package org.athento.nuxeo.security.listener;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.athento.nuxeo.security.util.MimeUtils;
import org.nuxeo.ecm.core.api.ClientException;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.core.event.Event;
import org.nuxeo.ecm.core.event.EventContext;
import org.nuxeo.ecm.core.event.EventListener;
import org.nuxeo.ecm.core.event.impl.DocumentEventContext;
import org.nuxeo.runtime.transaction.TransactionHelper;

/**
 * Document save with security restriction.
 */
public class DocumentSaveRestrictListener implements EventListener {

    /** Log. */
    private static Log LOG = LogFactory.getLog(DocumentSaveRestrictListener.class);
    
    /**
     * Handle event.
     * 
     * @param event document save event
     */
    @Override
    public void handleEvent(Event event) throws ClientException {
        EventContext ctx = event.getContext();
        if (ctx instanceof DocumentEventContext) {
            DocumentEventContext docCtx = (DocumentEventContext) ctx;
            DocumentModel doc = docCtx.getSourceDocument();
            try {
                MimeUtils.checkMimeType(doc);
            } catch (Exception e) {
                TransactionHelper.setTransactionRollbackOnly();
                event.markRollBack(e.getMessage(), e);
                throw new ClientException(e);
            }
        }
    }

}