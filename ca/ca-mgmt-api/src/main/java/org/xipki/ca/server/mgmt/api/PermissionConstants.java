/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.ca.server.mgmt.api;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class PermissionConstants {

    private static final Map<Integer, String> codeTextMap = new HashMap<>();
    private static final Map<String, Integer> textCodeMap = new HashMap<>();

    public static final int ENROLL_CERT = 1;
    public static final int REVOKE_CERT = 2;
    public static final int UNREVOKE_CERT = 4;
    public static final int REMOVE_CERT = 8;
    public static final int KEY_UPDATE = 16;
    public static final int GEN_CRL = 32;
    public static final int GET_CRL = 64;
    public static final int ENROLL_CROSS = 128;
    public static final int ALL = ENROLL_CERT
            | REVOKE_CERT
            | UNREVOKE_CERT
            | REMOVE_CERT
            | KEY_UPDATE
            | GEN_CRL
            | GET_CRL
            | ENROLL_CROSS;

    static {
        codeTextMap.put(ENROLL_CERT, "ENROLL_CERT");
        codeTextMap.put(REVOKE_CERT, "REVOKE_CERT");
        codeTextMap.put(UNREVOKE_CERT, "UNREVOKE_CERT");
        codeTextMap.put(REMOVE_CERT, "REMOVE_CERT");
        codeTextMap.put(KEY_UPDATE, "KEY_UPDATE");
        codeTextMap.put(GEN_CRL, "GEN_CRL");
        codeTextMap.put(GET_CRL, "GET_CRL");
        codeTextMap.put(ENROLL_CROSS, "ENROLL_CROSS");
        codeTextMap.put(ALL, "ALL");

        for (Integer code : codeTextMap.keySet()) {
            textCodeMap.put(codeTextMap.get(code), code);
        }
    }

    private PermissionConstants() {
    }

    public static boolean contains(final int permissionA, final int permissionB) {
        return (permissionA & permissionB) == permissionB;
    }

    public static Integer getPermissionForText(String text) {
        return (text == null) ? null : textCodeMap.get(text.toUpperCase());
    }

    public static String getTextForCode(int code) {
        String text = codeTextMap.get(code);
        return (text == null) ? Integer.toString(code) : text;
    }

}
