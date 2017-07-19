package org.athento.nuxeo.security.restlet;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.athento.nuxeo.security.util.SignHelper;
import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.nuxeo.ecm.core.api.*;
import org.nuxeo.ecm.core.api.model.PropertyNotFoundException;
import org.nuxeo.ecm.platform.ui.web.api.NavigationContext;
import org.nuxeo.ecm.platform.ui.web.restAPI.BaseNuxeoRestlet;
import org.nuxeo.ecm.platform.util.RepositoryLocation;
import org.nuxeo.runtime.api.Framework;
import org.restlet.data.Request;
import org.restlet.data.Response;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.*;

/**
 * Download restlet with stateless no auth. Check extended-security schema to check access to document.
 */
@Name("athentoDownloadRestlet")
@Scope(ScopeType.EVENT)
public class DownloadRestlet extends BaseNuxeoRestlet {

    private static final Log LOG = LogFactory.getLog(DownloadRestlet.class);

    @In(create = true)
    protected NavigationContext navigationContext;

    protected transient CoreSession documentManager;

    protected DocumentModel targetDocument;

    protected String username;

    /**
     * Handler.
     *
     * @param req
     * @param res
     */
    @Override
    public void handle(Request req, Response res) {

        // Get attributes from restlet
        String repo = (String) req.getAttributes().get("repo");
        String docid = (String) req.getAttributes().get("docid");
        String xpath = (String) req.getAttributes().get("xpath");

        // Get parameters from restlet query
        String disposition = getQueryParamValue(req, "disposition", "attachment");
        
        String token = getQueryParamValue(req, "t", null);
        if (token == null) {
            handleError(res, "You need the signed token to download");
            return;
        }

        if (xpath == null || xpath.isEmpty()) {
            xpath = "file:content";
        }

        xpath = xpath.replace("-", "/");
        List<String> segments = req.getResourceRef().getSegments();
        StringBuilder sb = new StringBuilder();
        for (int i = 6; i < segments.size(); i++) {
            sb.append(segments.get(i));
            sb.append("/");
        }

        try {
            xpath = URLDecoder.decode(xpath, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            LOG.error(e);
        }

        if (repo == null || repo.equals("*")) {
            handleError(res, "you must specify a repository");
            return;
        }
        if (docid == null || repo.equals("*")) {
            handleError(res, "you must specify a documentId");
            return;
        }

        try {
            Framework.login();
            navigationContext.setCurrentServerLocation(new RepositoryLocation(
                    repo));
            documentManager = navigationContext.getOrCreateDocumentManager();
            targetDocument = documentManager.getDocument(new IdRef(docid));
            username = documentManager.getPrincipal().getName();
            // Check if document has extended-security schema to check access
            if (!hasGrantedAccess(documentManager, req, targetDocument, xpath, token)) {
                handleError(res, "Access to document " + targetDocument.getId() + " is not allowed");
                return;
            }
        } catch (Exception e) {
            LOG.error("Unable to get document from session", e);
            handleError(res, e);
            return;
        } 

        Blob blob;
        try {
            blob = (Blob) targetDocument.getPropertyValue(xpath);
            if (blob == null) {
                handleError(res, "Document " + targetDocument.getId() + " has no content for xpath " + xpath);
                return;
            }
        } catch (PropertyNotFoundException | ClassCastException e) {
            LOG.error("Document " + targetDocument.getId() + " has no content with xpath " + xpath);
            handleError(res, e);
            return;
        }

        String filename = getQueryParamValue(req, "filename", blob.getFilename());

        HttpServletResponse response = getHttpResponse(res);
        response.setHeader("Cache-Control", "no-cache");
        response.setHeader("Pragma", "no-cache");
        response.setContentType(blob.getMimeType());
        response.setHeader("Content-Disposition", disposition + ";filename=" + filename);
        long fileSize = blob.getLength();
        if(fileSize > 0L) {
            response.setContentLength((int)fileSize);
        }
        try {
            blob.transferTo(response.getOutputStream());
        } catch (IOException e) {
            handleError(res, e);
        }
    }

    /**
     * Check granted access to document.
     *
     * @param session
     * @param req
     * @param doc
     * @param xpath
     * @param token
     * @return
     */
    private boolean hasGrantedAccess(CoreSession session, Request req, DocumentModel doc, String xpath, String token) {
        boolean accessGranted = false;
        if (doc.hasSchema("athentosec")) {
            // Check content xpath
            String xpathSec = (String) doc.getPropertyValue("athentosec:xpath");
            if (!xpath.equals(xpathSec)) {
                return false;
            }
            // Check IPs
            String ips = (String) doc.getPropertyValue("athentosec:ips");
            accessGranted = checkAllowedIps(req, ips);
            if (!accessGranted) {
                return false;
            }
            // Check principals
            String principals = (String) doc.getPropertyValue("athentosec:principals");
            accessGranted = checkAllowedPrincipals(principals);
            if (!accessGranted) {
                return false;
            }
            // Check expiration date
            GregorianCalendar expirationDate = (GregorianCalendar) doc.getPropertyValue("athentosec:expirationDate");
            accessGranted = checkAllowedExpirationDate(expirationDate);
            if (!accessGranted) {
                return false;
            }
            // Check signed token (with onlyOneUse to remove it)
            ArrayList<Map<String, Serializable>> signedTokens = (ArrayList) doc.getPropertyValue("athentosec:tokens");
            accessGranted = checkSignedToken(token, signedTokens);
            if (!accessGranted) {
                return false;
            }
            // Update tokens for document
            doc.setPropertyValue("athentosec:tokens", signedTokens);
            session.saveDocument(doc);
            accessGranted = true;
        }
        return accessGranted;
    }

    /**
     * Check RSA-1 signed token valid.
     *
     * @param token
     * @param signedTokens
     * @return
     */
    private boolean checkSignedToken(String token, ArrayList<Map<String, Serializable>> signedTokens) {
        if (signedTokens == null) {
            if (token != null) {
                return false;
            }
            return true;
        }
        boolean valid = false;
        int validTokenIndex = -1;
        for (int i = 0; i < signedTokens.size(); i++) {
            Map<String, Serializable> tokenData = signedTokens.get(i);
            String signedToken = (String) tokenData.get("sign");
            boolean validTmp = SignHelper.verifySignedToken(token, signedToken);
            if (validTmp) {
                // Check if token is only one use
                boolean onlyOneUseToken = (Boolean) tokenData.get("onlyOneUse");
                if (onlyOneUseToken) {
                    validTokenIndex = i;
                }
                valid = true;
                break;
            }
        }
        if (validTokenIndex != -1) {
            signedTokens.remove(validTokenIndex);
        }
        return valid;
    }

    /**
     * Check expiration date.
     *
     * @param expirationDate
     * @return
     */
    private boolean checkAllowedExpirationDate(GregorianCalendar expirationDate) {
        if (expirationDate == null) {
            return true;
        }
        LOG.info("Check Expiration Date " + expirationDate);
        return !Calendar.getInstance().after(expirationDate);
    }

    /**
     * Check allowed principals.
     *
     * @param principals
     * @return
     */
    private boolean checkAllowedPrincipals(String principals) {
        if (principals == null || principals.isEmpty()) {
            return true;
        }
        // Get username
        LOG.info("Check principal " + username + " against " + principals);
        String [] separatedPrincipals = principals.split(",");
        for (String principal : separatedPrincipals) {
            if (principal.equals(username)) {
                return true;
            }
        }
        // TODO: Check user groups
        return false;
    }

    /**
     * Check allowed ips.
     *
     * @params request
     * @param ips
     * @return
     */
    private boolean checkAllowedIps(Request req, String ips) {
        if (ips == null || ips.isEmpty()) {
            return true;
        }
        // Get IP
        String clientIP = req.getClientInfo().getAddress();
        if (clientIP == null) {
            return false;
        }
        LOG.info("Check IP " + clientIP + " against " + ips);
        String [] separatedIps = ips.split(",");
        for (String ip : separatedIps) {
            if (clientIP.equals(ip)) {
                return true;
            }
        }
        return false;
    }

}
