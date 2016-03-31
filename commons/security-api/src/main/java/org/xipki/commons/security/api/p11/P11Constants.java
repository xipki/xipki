/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
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

package org.xipki.commons.security.api.p11;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.annotation.Nonnull;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11Constants {
    /* Security Officer */
    public static final long CKU_SO = 0L;

    /* Normal user */
    public static final long CKU_USER = 1L;

    /* Context specific (added in v2.20) */
    public static final long CKU_CONTEXT_SPECIFIC = 2L;

    /* key types */
    public static final long CKK_RSA = 0x00000000L;
    public static final long CKK_DSA = 0x00000001L;
    public static final long CKK_EC = 0x00000003L;

    /* key pair generation */
    public static final long CKM_RSA_PKCS_KEY_PAIR_GEN = 0x00000000L;

    public static final long CKM_DSA_KEY_PAIR_GEN = 0x00000010L;

    public static final long CKM_EC_KEY_PAIR_GEN = 0x00001040L;

    /* RSA algorithm */
    public static final long CKM_RSA_9796 = 0x00000002L;

    public static final long CKM_RSA_X_509 = 0x00000003L;

    /* RSA :: PKCS1v1.5 encoding */

    public static final long CKM_RSA_PKCS = 0x00000001L;

    public static final long CKM_SHA1_RSA_PKCS = 0x00000006L;

    public static final long CKM_SHA224_RSA_PKCS = 0x00000046L;

    public static final long CKM_SHA256_RSA_PKCS = 0x00000040L;

    public static final long CKM_SHA384_RSA_PKCS = 0x00000041L;

    public static final long CKM_SHA512_RSA_PKCS = 0x00000042L;

    /* RSA :: PSS */
    public static final long CKM_RSA_PKCS_PSS = 0x0000000DL;

    public static final long CKM_SHA1_RSA_PKCS_PSS = 0x0000000EL;

    public static final long CKM_SHA224_RSA_PKCS_PSS = 0x00000047;

    public static final long CKM_SHA256_RSA_PKCS_PSS = 0x00000043L;

    public static final long CKM_SHA384_RSA_PKCS_PSS = 0x00000044L;

    public static final long CKM_SHA512_RSA_PKCS_PSS = 0x00000045L;

    /* DSA */
    public static final long CKM_DSA = 0x00000011L;

    public static final long CKM_DSA_SHA1 = 0x00000012L;

    public static final long CKM_DSA_SHA224 = 0x00000013L;

    public static final long CKM_DSA_SHA256 = 0x00000014L;

    public static final long CKM_DSA_SHA384 = 0x00000015L;

    public static final long CKM_DSA_SHA512 = 0x00000016L;

    /* DSA */
    public static final long CKM_ECDSA = 0x00001041L;

    public static final long CKM_ECDSA_SHA1 = 0x00001042L;

    public static final long CKM_ECDSA_SHA224 = 0x00001043L;

    public static final long CKM_ECDSA_SHA256 = 0x00001044L;

    public static final long CKM_ECDSA_SHA384 = 0x00001045L;

    public static final long CKM_ECDSA_SHA512 = 0x00001046L;

    /* MGFs */
    public static final long CKG_MGF1_SHA1 = 0x00000001L;

    public static final long CKG_MGF1_SHA224 = 0x00000005L;

    public static final long CKG_MGF1_SHA256 = 0x00000002L;

    public static final long CKG_MGF1_SHA384 = 0x00000003L;

    public static final long CKG_MGF1_SHA512 = 0x00000004L;

    /* Hashs*/
    public static final long CKM_SHA_1 = 0x00000220L;

    public static final long CKM_SHA224 = 0x00000255L;

    public static final long CKM_SHA256 = 0x00000250L;

    public static final long CKM_SHA384 = 0x00000260L;

    public static final long CKM_SHA512 = 0x00000270L;

    private static final Map<Long, String> mechanismNameMap;

    private static final Map<String, Long> nameMechanismNameMap;

    static {
        Map<Long, String> mp = new HashMap<>(300);

        mp.put(CKM_RSA_PKCS_KEY_PAIR_GEN, "CKM_RSA_PKCS_KEY_PAIR_GEN");
        mp.put(CKM_EC_KEY_PAIR_GEN, "CKM_EC_KEY_PAIR_GEN");
        mp.put(CKM_DSA_KEY_PAIR_GEN, "CKM_DSA_KEY_PAIR_GEN");

        mp.put(CKM_DSA, "CKM_DSA");
        mp.put(CKM_DSA_SHA1, "CKM_DSA_SHA1");
        mp.put(CKM_DSA_SHA224, "CKM_DSA_SHA224");
        mp.put(CKM_DSA_SHA256, "CKM_DSA_SHA256");
        mp.put(CKM_DSA_SHA384, "CKM_DSA_SHA384");
        mp.put(CKM_DSA_SHA512, "CKM_DSA_SHA512");

        mp.put(CKM_ECDSA, "CKM_ECDSA");
        mp.put(CKM_ECDSA_SHA1, "CKM_ECDSA_SHA1");
        mp.put(CKM_ECDSA_SHA224, "CKM_ECDSA_SHA224");
        mp.put(CKM_ECDSA_SHA256, "CKM_ECDSA_SHA256");
        mp.put(CKM_ECDSA_SHA384, "CKM_ECDSA_SHA384");
        mp.put(CKM_ECDSA_SHA512, "CKM_ECDSA_SHA512");

        mp.put(CKM_RSA_X_509, "CKM_RSA_X_509");

        mp.put(CKM_RSA_9796, "CKM_RSA_9796");

        mp.put(CKM_RSA_PKCS, "CKM_RSA_PKCS");

        mp.put(CKM_SHA1_RSA_PKCS, "CKM_SHA1_RSA_PKCS");
        mp.put(CKM_SHA224_RSA_PKCS, "CKM_SHA224_RSA_PKCS");
        mp.put(CKM_SHA256_RSA_PKCS, "CKM_SHA256_RSA_PKCS");
        mp.put(CKM_SHA384_RSA_PKCS, "CKM_SHA384_RSA_PKCS");
        mp.put(CKM_SHA512_RSA_PKCS, "CKM_SHA512_RSA_PKCS");

        mp.put(CKM_RSA_PKCS_PSS, "CKM_RSA_PKCS_PSS");

        mp.put(CKM_SHA1_RSA_PKCS_PSS, "CKM_SHA1_RSA_PKCS_PSS");
        mp.put(CKM_SHA224_RSA_PKCS_PSS, "CKM_SHA224_RSA_PKCS_PSS");
        mp.put(CKM_SHA256_RSA_PKCS_PSS, "CKM_SHA256_RSA_PKCS_PSS");
        mp.put(CKM_SHA384_RSA_PKCS_PSS, "CKM_SHA384_RSA_PKCS_PSS");
        mp.put(CKM_SHA512_RSA_PKCS_PSS, "CKM_SHA512_RSA_PKCS_PSS");

        mp.put(CKM_SHA_1, "CKM_SHA_1");
        mp.put(CKM_SHA224, "CKM_SHA224");
        mp.put(CKM_SHA256, "CKM_SHA256");
        mp.put(CKM_SHA384, "CKM_SHA384");
        mp.put(CKM_SHA512, "CKM_SHA512");

        mechanismNameMap = Collections.unmodifiableMap(mp);

        Map<String, Long> imp = new HashMap<>();
        for (Long mech : mp.keySet()) {
            String name = mp.get(mech);
            imp.put(name, mech);
        }
        imp.put("CKM_SHA1", CKM_SHA_1);
        imp.put("CKM_ECDSA_KEY_PAIR_GEN", CKM_EC_KEY_PAIR_GEN);
        nameMechanismNameMap = Collections.unmodifiableMap(imp);
    }

    public static String getMechanismName(
            final long mechanism) {
        return mechanismNameMap.get(mechanism);
    }

    public static long getMechanism(
            @Nonnull final String mechanismName) {
        Long mech = nameMechanismNameMap.get(mechanismName);
        return mech == null
                ? -1
                : mech.longValue();
    }

    public static String getMechanismDesc(
            final long mechanism) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("%#08x", mechanism));
        String name = mechanismNameMap.get(mechanism);
        if (name != null) {
            sb.append(" (").append(name).append(")");
        }
        return sb.toString();
    }

    private P11Constants() {
    }

}
