package org.athento.nuxeo.security.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.nuxeo.ecm.core.api.Blob;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.runtime.api.Framework;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Mimetype utils.
 *
 * @author pacoalias
 */
public final class MimeUtils {

    /** Log. */
    private static Log LOG = LogFactory.getLog(MimeUtils.class);

    private static List<String> includedDocumentTypes = new ArrayList<>();
    private static List<String> mimeTypesAllowed = new ArrayList<>();

    private static final String DEFAULT_DOCUMENT_TYPES_RESTRICTED = "File";
    private static final String DEFAULT_MIMETYPES_ALLOWED = "application/vnd.oasis.opendocument.text," +
                                                            "text/xml, text/html, text/plain, text/rtf, text/csv, text/css," +
                                                            "application/msword, application/msexcel, application/vnd.ms-excel, application/vnd.ms-powerpoint," +
                                                            "application/vnd.openxmlformats-officedocument.wordprocessingml.document," +
                                                            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet," +
                                                            "application/vnd.openxmlformats-officedocument.spreadsheetml.template," +
                                                            "application/vnd.sun.xml.writer, application/vnd.sun.xml.writer.template, " +
                                                            "application/vnd.oasis.opendocument.text," +
                                                            "application/vnd.oasis.opendocument.text-template," +
                                                            "audio/ogg, video/ogg, application/ogg," +
                                                            "application/wordperfect, application/rtf," +
                                                            "video/mpeg, video/quicktime, application/visio, audio/midi," +
                                                            "audio/mp3, image/gif, image/png, image/jpg, image/jpeg, image/tiff,"+
                                                            "application/pdf, application/x-gzip, application/csv, audio/aac, video/x-msvideo";


    private static final String PROPERTY_DOCUMENT_TYPES = "plugin.athento-nx-security-limit-file-upload-mime-types.documentTypesChecked";
    private static final String PROPERTY_MIMETYPES_ALLOWED = "plugin.athento-nx-security-limit-file-upload-mime-types.mimeTypesAllowed";
    private static final String XPATH_FILE_CONTENT = "file:content";

    static {
        includedDocumentTypes.addAll(Arrays.stream(DEFAULT_DOCUMENT_TYPES_RESTRICTED.split(",")).map(String::trim).collect(Collectors.toList()));
        mimeTypesAllowed.addAll(Arrays.stream(DEFAULT_MIMETYPES_ALLOWED.split(",")).map(String::trim).collect(Collectors.toList()));
        String mimeTypesAllowedValue = Framework
                .getProperty(PROPERTY_MIMETYPES_ALLOWED, DEFAULT_MIMETYPES_ALLOWED);
        if (LOG.isInfoEnabled()) {
            LOG.info("Framework Property ["
                    + PROPERTY_MIMETYPES_ALLOWED + "] value ["
                    + mimeTypesAllowedValue + "]");
        }
        if (mimeTypesAllowedValue != null) {
            mimeTypesAllowed.addAll(Arrays.stream(mimeTypesAllowedValue.split(",")).map(String::trim).collect(Collectors.toList()));
        } else {
            LOG.warn("No mimeTypes are restricted!!. To restrict mimetypes uploadable set property "
                    + PROPERTY_MIMETYPES_ALLOWED);
        }
        String documentTypesTraced = Framework.getProperty(
                PROPERTY_DOCUMENT_TYPES);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Framework property "
                    + PROPERTY_DOCUMENT_TYPES
                    + " value: " + documentTypesTraced + ")");
        }
        if (documentTypesTraced != null) {
            if (!"all".equalsIgnoreCase(documentTypesTraced)) {
                includedDocumentTypes.addAll(Arrays.stream(documentTypesTraced.split(",")).map(String::trim).collect(Collectors.toList()));
            } else {
                includedDocumentTypes.clear();
            }
        }
        if (includedDocumentTypes == null) {
            LOG.warn("No document types are traced!!. Set property "
                    + PROPERTY_DOCUMENT_TYPES);
        }
    }

    /**
     * @return the includedDocumentTypes
     */
    public static List<String> getIncludedDocumentTypes() {
        return includedDocumentTypes;
    }

    /**
     * @return the mimeTypesAllowed
     */
    public static List<String> getMimeTypesAllowed() {
        return mimeTypesAllowed;
    }

    public static void checkMimeType(DocumentModel doc) throws Exception {
        if (!doc.hasSchema("file")) {
            return;
        }
        if (getIncludedDocumentTypes() == null) {
            return;
        }
        String documentType = doc.getDocumentType().getName();
        if (isWatchedDocumentType(documentType)) {
            checkMimeType((Blob) doc
                    .getPropertyValue(XPATH_FILE_CONTENT));
        }
    }

    public static void checkMimeType(Blob blob) throws Exception {
        if (blob == null) {
            return;
        }
        if (getMimeTypesAllowed() == null) {
            return;
        }
        boolean allowed;
        String mimeType = blob.getMimeType();
        if (LOG.isDebugEnabled()) {
            LOG.debug("Searching for mimeType [" + mimeType + "] in allowed mimeTypes");
        }
        allowed = isMimeTypeAllowed(mimeType);
        if (LOG.isDebugEnabled()) {
            LOG.debug("This mimeType [" + mimeType + "] is allowed: " + allowed);
        }
        if (allowed) {
            return;
        } else {
            throw new Exception("This mimeType is NOT allowed: " + mimeType);
        }
    }

    private static boolean isWatchedDocumentType (String documentType) {
        if (includedDocumentTypes.isEmpty()) {
            // all documents are allowed
            return true;
        }
        for (String dt: includedDocumentTypes) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("  documentType watched [" + dt + "]");
            }
            if (dt.equalsIgnoreCase(documentType)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug(" WATCHED documentType [" + documentType + "]");
                }
                return true;
            }
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug(" not watched documentType [" + documentType + "]");
        }

        return false;
    }

    private static boolean isMimeTypeAllowed (String mimeType) {
        for (String mt : mimeTypesAllowed) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("  mimeType allowed [" + mt + "]");
            }
            if (mt.equalsIgnoreCase(mimeType)) {
                return true;
            }
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug(" NOT allowed mimeType [" + mimeType + "]");
        }
        return false;
    }
}
