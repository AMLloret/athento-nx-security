package org.athento.security.test;

import org.apache.commons.lang.StringEscapeUtils;
import org.junit.Test;

/**
 * Test escape.
 */
public class TestEscape {

    @Test
    public void testEscape() {
        try {
            String t1 = "\"/><script>alert('XXS')</script>";
            System.out.println(t1);
            String t2 = StringEscapeUtils.escapeJavaScript(t1);
            System.out.println(t2);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
