package org.athento.security.test;


import org.athento.nuxeo.security.util.PasswordHelper;
import org.athento.nuxeo.security.util.SignHelper;
import org.junit.Test;

/**
 * Test sign.
 */
public class TestSign {

    @Test
    public void testSignToken() {
        try {
            String t1 = PasswordHelper.generateSecToken(128);
            System.out.println(t1);
            String a1 = SignHelper.getSignedToken(t1);
            String t2 = PasswordHelper.generateSecToken(128);
            System.out.println(t2);
            String a2 = SignHelper.getSignedToken(t2);
            System.out.println(SignHelper.verifySignedToken(t1, a1));
            System.out.println(SignHelper.verifySignedToken(t1, a2));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
