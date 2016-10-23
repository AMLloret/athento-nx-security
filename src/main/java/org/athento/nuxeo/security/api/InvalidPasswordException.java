package org.athento.nuxeo.security.api;

/**
 * Invalid password exception.
 *
 * @author <a href="vs@athento.com">Victor Sanchez</a>
 */
public class InvalidPasswordException extends
        RememberPasswordException {

    private static final long serialVersionUID = 1L;

    public InvalidPasswordException(String message) {
        super(message);
    }
}
