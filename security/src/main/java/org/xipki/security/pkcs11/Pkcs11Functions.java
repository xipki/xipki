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

package org.xipki.security.pkcs11;

import iaik.pkcs.pkcs11.wrapper.Functions;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class Pkcs11Functions {
    public static String mechanismCodeToString(final long mechanism) {
        return Functions.mechanismCodeToString(mechanism);
    }

    /**
     * get the code of the given mechanism name.
     * @param mechanismName
     *          Mechanism name. Must not be {@code null}.
     * @return the code if could be found, -1 otherwise.
     */
    public static long mechanismStringToCode(final String mechanismName) {
        Long mech = Functions.mechanismStringToCode(mechanismName);
        return mech == null ? -1 : mech.longValue();
    }

    public static String getMechanismDesc(final long mechanism) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("%#010x", mechanism));
        String name = Functions.mechanismCodeToString(mechanism);
        if (name != null) {
            sb.append(" (").append(name).append(")");
        }
        return sb.toString();
    }

    private Pkcs11Functions() {
    }

}
