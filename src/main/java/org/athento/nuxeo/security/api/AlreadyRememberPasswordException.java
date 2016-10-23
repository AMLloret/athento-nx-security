package org.athento.nuxeo.security.api;

/**
 * @author <a href="vs@athento.com">Victor Sanchez</a>
 */
public class AlreadyRememberPasswordException extends
        RememberPasswordException {

    private static final long serialVersionUID = 1L;

    public AlreadyRememberPasswordException(String message) {
        super(message);
    }
}
