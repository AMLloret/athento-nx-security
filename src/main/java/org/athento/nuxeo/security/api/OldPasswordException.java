package org.athento.nuxeo.security.api;

/**
 * Old password exception.
 *
 * @author <a href="vs@athento.com">Victor Sanchez</a>
 */
public class OldPasswordException extends
        InvalidPasswordException {

    private static final long serialVersionUID = 1L;

    public OldPasswordException(String message) {
        super(message);
    }
}
