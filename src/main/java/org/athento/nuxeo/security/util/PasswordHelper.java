package org.athento.nuxeo.security.util;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.nuxeo.runtime.api.Framework;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.List;

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

    private static final String HSSHA = "{SSHA}";

    private static final String HSMD5 = "{SMD5}";

    private static final String SHA1 = "SHA-1";

    private static final String MD5 = "MD5";

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
                myEncryptionKey = Framework.getProperty("encryption.key",
                        "u78a7fg7y9776FFYOAD68GOYGsafasdfoG66fdF6DF6dss234");
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
                LOG.info("==" + encryptedString);
                cipher.init(Cipher.ENCRYPT_MODE, key);
                byte[] plainText = unencryptedString.getBytes(UNICODE_FORMAT);
                byte[] encryptedText = cipher.doFinal(plainText);
                encryptedString = new String(Base64.encodeBase64(encryptedText));
                LOG.info("==2" + encryptedString);
            } catch (Exception e) {
                LOG.error("Unable to encrypt string", e);
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
                LOG.error("Unable to decript string", e);
            }
            return decryptedText;
        }

    }

    /**
     * Verify a password against a hashed password.
     *
     * @param password the password to verify
     * @param hashedPassword the hashed password
     * @return {@code true} if the password matches
     */
    public static boolean verifyPassword(String password, String hashedPassword) {
        String digestalg;
        int len;
        if (hashedPassword.startsWith(HSSHA)) {
            digestalg = SHA1;
            len = 20;
        } else if (hashedPassword.startsWith(HSMD5)) {
            digestalg = MD5;
            len = 16;
        } else {
            return hashedPassword.equals(password);
        }
        String digest = hashedPassword.substring(6);

        byte[] bytes = Base64.decodeBase64(digest);
        if (bytes == null) {
            // invalid base64
            return false;
        }
        if (bytes.length < len + 2) {
            // needs hash + at least two bytes of salt
            return false;
        }
        byte[] hash = new byte[len];
        byte[] salt = new byte[bytes.length - len];
        System.arraycopy(bytes, 0, hash, 0, hash.length);
        System.arraycopy(bytes, hash.length, salt, 0, salt.length);
        return MessageDigest.isEqual(hash, digestWithSalt(password, salt, digestalg));
    }

    public static byte[] digestWithSalt(String password, byte[] salt, String algorithm) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            md.update(password.getBytes("UTF-8"));
            md.update(salt);
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(algorithm, e);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

}
