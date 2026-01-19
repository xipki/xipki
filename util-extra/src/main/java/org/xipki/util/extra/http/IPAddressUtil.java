// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.extra.http;

/**
 * Utility methods for processing String objects containing IP addresses.
 * @author Lijun Liao (xipki)
 */
public class IPAddressUtil {
    /**
     * Validate the given IPv4 or IPv6 address.
     *
     * @param address the IP address as a String.
     *
     * @return true if a valid address, false otherwise
     */
    public static boolean isValid(String address) {
        return isValidIPv4(address) || isValidIPv6(address);
    }

    /**
     * Validate the given IPv4 address.
     *
     * @param address the IP address as a String.
     *
     * @return true if a valid IPv4 address, false otherwise
     */
    public static boolean isValidIPv4(String address) {
        int length = address.length();
        if (length < 7 || length > 15) {
            return false;
        }

        int pos = 0;
        for (int octetIndex = 0; octetIndex < 3; ++octetIndex) {
            int end = address.indexOf('.', pos);

            if (!isParsableIPv4Octet(address, pos, end)) {
                return false;
            }

            pos = end + 1;
        }

        return isParsableIPv4Octet(address, pos, length);
    }

    /**
     * Validate the given IPv6 address.
     *
     * @param address the IP address as a String.
     *
     * @return true if a valid IPv6 address, false otherwise
     */
    public static boolean isValidIPv6(String address) {
        if (address.isEmpty()) {
            return false;
        }

        char firstChar = address.charAt(0);
        if (firstChar != ':' && Character.digit(firstChar, 16) < 0) {
            return false;
        }

        int segmentCount = 0;
        String temp = address + ":";
        boolean doubleColonFound = false;

        int pos = 0, end;
        while (pos < temp.length() && (end = temp.indexOf(':', pos)) >= pos) {
            if (segmentCount == 8) {
                return false;
            }

            if (pos != end) {
                String value = temp.substring(pos, end);

                if (end == temp.length() - 1 && value.indexOf('.') > 0) {
                    // add an extra one as address covers 2 words.
                    if (++segmentCount == 8) {
                        return false;
                    }
                    if (!isValidIPv4(value)) {
                        return false;
                    }
                }
                else if (!isParsableIPv6Segment(temp, pos, end)) {
                    return false;
                }
            }
            else {
                if (end != 1 && end != temp.length() - 1 && doubleColonFound) {
                    return false;
                }
                doubleColonFound = true;
            }

            pos = end + 1;
            ++segmentCount;
        }

        return segmentCount == 8 || doubleColonFound;
    }

    private static boolean isParsableIPv4Octet(String s, int pos, int end) {
        return isParsable(s, pos, end, 10, 3, true, 0, 255);
    }

    private static boolean isParsableIPv6Segment(String s, int pos, int end) {
        return isParsable(s, pos, end, 16, 4, true, 0x0000, 0xFFFF);
    }

    private static boolean isParsable(
        String s, int pos, int end, int radix, int maxLength,
        boolean allowLeadingZero, int minValue, int maxValue) {
        int length = end - pos;
        if (length < 1 | length > maxLength) {
            return false;
        }

        boolean checkLeadingZero = length > 1 & !allowLeadingZero;
        if (checkLeadingZero && Character.digit(s.charAt(pos), radix) <= 0) {
            return false;
        }

        int value = 0;
        while (pos < end) {
            char c = s.charAt(pos++);
            int d = Character.digit(c, radix);
            if (d < 0) {
                return false;
            }

            value *= radix;
            value += d;
        }

        return value >= minValue & value <= maxValue;
    }
}
