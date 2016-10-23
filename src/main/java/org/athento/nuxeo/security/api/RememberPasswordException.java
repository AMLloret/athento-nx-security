package org.athento.nuxeo.security.api;

import org.nuxeo.ecm.core.api.ClientException;

/**
 * Remember password exception.
 *
 * @author <a href="vs@athento.com">Victor Sanchez</a>
 */
public class RememberPasswordException extends ClientException {

    private static final long serialVersionUID = 1L;

    public RememberPasswordException(String message) {
        super(message);
    }

}
