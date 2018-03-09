package org.athento.nuxeo.security.api;

/**
 * Token exception.
 *
 * @author <a href="vs@athento.com">Victor Sanchez</a>
 */
public class TokenException extends
        Exception {

    private static final long serialVersionUID = 1L;

    public TokenException(String message) {
        super(message);
    }

    public TokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
