/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.common.util;

/**
 * @author Lijun Liao
 * @since 2.1.0
 */

public class Hex {

    private static final char[] DIGITS = {
            '0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

    private static final char[] UPPER_DIGITS = {
            '0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
    };

    private static final int[] LINTS = new int['f' + 1];
    private static final int[] HINTS = new int[LINTS.length];

    static {
        for (int i = 0; i < DIGITS.length; i++) {
            LINTS[DIGITS[i]] = i;
        }

        for (int i = 10; i < UPPER_DIGITS.length; i++) {
            LINTS[UPPER_DIGITS[i]] = i;
        }

        for (int i = 0; i < LINTS.length; i++) {
            HINTS[i] = LINTS[i] << 4;
        }
    }

    public static String encode(byte[] bytes) {
        return new String(encodeToChars(bytes));
    }

    public static char[] encodeToChars(byte[] data) {
        int l = data.length;

        char[] out = new char[l << 1];

        // two characters form the hex value.
        for (int i = 0, j = 0; i < l; i++) {
            out[j++] = DIGITS[(0xF0 & data[i]) >>> 4];
            out[j++] = DIGITS[0x0F & data[i]];
        }

        return out;
    }

    public static String encodeUpper(byte[] bytes) {
        return new String(encodeToUpperChars(bytes));
    }

    public static char[] encodeToUpperChars(byte[] data) {
        int l = data.length;

        char[] out = new char[l << 1];

        // two characters form the hex value.
        for (int i = 0, j = 0; i < l; i++) {
            out[j++] = UPPER_DIGITS[(0xF0 & data[i]) >>> 4];
            out[j++] = UPPER_DIGITS[0x0F & data[i]];
        }

        return out;
    }

    public static byte[] decode(byte[] array) {
        int len = array.length;

        if ((len & 0x01) != 0) {
            throw new IllegalArgumentException("Odd number of characters.");
        }

        byte[] out = new byte[len >> 1];

        // two characters form the hex value.
        for (int i = 0, j = 0; j < len; i++) {
            out[i] = (byte) (HINTS[0xff & array[j++]] | LINTS[0xff & array[j++]]);
        }

        return out;
    }

    public static byte[] decode(String hex) {
        return decode(hex.toCharArray());
    }

    public static byte[] decode(char[] data) {
        int len = data.length;

        if ((len & 0x01) != 0) {
            throw new IllegalArgumentException("Odd number of characters.");
        }

        byte[] out = new byte[len >> 1];

        // two characters form the hex value.
        for (int i = 0, j = 0; j < len; i++) {
            out[i] = (byte) (HINTS[data[j++]] | LINTS[data[j++]]);
        }

        return out;
    }

}
