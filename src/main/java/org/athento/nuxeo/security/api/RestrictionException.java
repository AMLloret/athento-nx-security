package org.athento.nuxeo.security.api;

/**
 * Restriction exception.
 *
 * @author <a href="vs@athento.com">Victor Sanchez</a>
 */
public class RestrictionException extends Exception {

    private static final long serialVersionUID = 1L;

    public RestrictionException(String message) {
        super(message);
    }

    public RestrictionException(String message, Throwable cause) {
        super(message, cause);
    }

    public RestrictionException(Throwable cause) {
        super(cause);
    }
}
