package org.athento.nuxeo.security.util;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.List;

/**
 * Password helper.
 *
 * @author <a href="vs@athento.com">Victor Sanchez</a>
 */
public final class PasswordHelper {

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
                if ((now - passTime) < (days * 24 * 3600 * 1000)) {
                    if (passInfo[0].equals(password)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

}
