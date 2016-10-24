package org.athento.nuxeo.security.util;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.nuxeo.runtime.api.Framework;

import javax.crypto.*;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.util.*;

/**
 * Password helper.
 *
 * @author <a href="vs@athento.com">Victor Sanchez</a>
 */
public final class PasswordHelper {

    private static final Log LOG = LogFactory.getLog(PasswordHelper.class);

    /** Min chars. */
    public static final int MIN_CHARS = 8;

    /** Min chars. */
    public static final int MIN_DIGITS = 2;

    /** Min chars. */
    public static final int MIN_CAPS = 2;

    /** Min chars. */
    public static final int MIN_SPECIAL = 1;

    /**
     * Check is password is valid.
     *
     * Min size: 8 chars
     * Min digits: 2 chars
     * Min Special chars: 1 char
     * May chars: 2 chars
     *
     * @param password to check
     * @return true if password is valid
     */
    public static boolean isValidPassword(String password) {
        int digits = 0;
        int special = 0;
        int caps = 0;
        if (password == null) {
            return false;
        }
        if (password.length() < MIN_CHARS) {
            return false;
        }
        for (char c : password.toCharArray()) {
            if (Character.isDigit(c)) {
                digits++;
            } else if (Character.isUpperCase(c)) {
                caps++;
            } else if (!Character.isLetter(c)) {
                special++;
            }
        }
        return digits >= MIN_DIGITS && caps >= MIN_CAPS && special >= MIN_SPECIAL;
    }

    /**
     * Check if the password is into password list from today to today - days.
     *
     * @param password is the password to check
     * @param passwordList is the password list
     * @param days to check the password
     * @return true if password is a old password
     */
    public static boolean isOldPassword(String password, List<String> passwordList, int days) {
        for (String pass : passwordList) {
            String [] passInfo = pass.split(":");
            if (passInfo.length == 2) {
                long passTime = Long.valueOf(passInfo[1]);
                long now = Calendar.getInstance().getTimeInMillis();
                if ((now - passTime) < (days * 24L * 3600L * 1000L)) {
                    if (passInfo[0].equals(password)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /**
     * Check if password is expired.
     *
     * @param lastModificationDate
     * @param days
     * @return true if password is expired
     */
    public static boolean isExpiredPassword(GregorianCalendar lastModificationDate, int days) {
        if (lastModificationDate == null) {
            return true;
        }
        Calendar gc = GregorianCalendar.getInstance();
        return (gc.getTimeInMillis() - lastModificationDate.getTimeInMillis()) > (days * 24L * 3600L * 1000L);
    }

    public static class CipherUtil {

        private static final String UNICODE_FORMAT = "UTF8";
        public static final String DESEDE_ENCRYPTION_SCHEME = "DESede";
        private static KeySpec ks;
        private static SecretKeyFactory skf;
        private static Cipher cipher;

        static byte[] arrayBytes;
        private static String myEncryptionKey;
        private static String myEncryptionScheme;
        static SecretKey key;

        private static void init() {
            try {
                myEncryptionKey = Framework.getProperty("encryption.key");
                myEncryptionScheme = DESEDE_ENCRYPTION_SCHEME;
                arrayBytes = myEncryptionKey.getBytes(UNICODE_FORMAT);
                ks = new DESedeKeySpec(arrayBytes);
                skf = SecretKeyFactory.getInstance(myEncryptionScheme);
                cipher = Cipher.getInstance(myEncryptionScheme);
                key = skf.generateSecret(ks);
                System.out.print("=" + cipher);
            } catch (Exception e) {
                System.err.print("Unable to init decrypt algorithm " + e.getMessage());
            }
        }


        public static String encrypt(String unencryptedString) {
            init();
            String encryptedString = null;
            try {
                cipher.init(Cipher.ENCRYPT_MODE, key);
                byte[] plainText = unencryptedString.getBytes(UNICODE_FORMAT);
                byte[] encryptedText = cipher.doFinal(plainText);
                encryptedString = new String(Base64.encodeBase64(encryptedText));
            } catch (Exception e) {
                e.printStackTrace();
            }
            return encryptedString;
        }


        public static String decrypt(String encryptedString) {
            init();
            String decryptedText=null;
            try {
                cipher.init(Cipher.DECRYPT_MODE, key);
                byte[] encryptedText = Base64.decodeBase64(encryptedString);
                byte[] plainText = cipher.doFinal(encryptedText);
                decryptedText= new String(plainText);
            } catch (Exception e) {
                e.printStackTrace();
            }
            return decryptedText;
        }

    }

}