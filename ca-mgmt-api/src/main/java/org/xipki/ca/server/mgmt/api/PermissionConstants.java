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
    public static final int ALL = ENROLL_CERT | REVOKE_CERT | UNREVOKE_CERT | REMOVE_CERT
            | KEY_UPDATE | GEN_CRL | GET_CRL | ENROLL_CROSS;

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

    public static boolean contains(int permissionA, int permissionB) {
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
