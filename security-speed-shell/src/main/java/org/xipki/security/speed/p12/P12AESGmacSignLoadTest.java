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

package org.xipki.security.speed.p12;

import org.xipki.security.SecurityFactory;
import org.xipki.security.pkcs12.KeystoreGenerationParameters;
import org.xipki.security.pkcs12.P12KeyGenerationResult;
import org.xipki.security.pkcs12.P12KeyGenerator;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */
// CHECKSTYLE:SKIP
public class P12AESGmacSignLoadTest extends P12SignLoadTest {

    public P12AESGmacSignLoadTest(final SecurityFactory securityFactory,
            final String signatureAlgorithm)
            throws Exception {
        super("JCEKS", securityFactory, signatureAlgorithm, generateKeystore(signatureAlgorithm),
                "JCEKS AES-GMAC signature creation");
    }

    private static byte[] generateKeystore(final String signatureAlgorithm)
            throws Exception {
        int keysize = getKeysize(signatureAlgorithm);
        P12KeyGenerationResult identity = new P12KeyGenerator().generateSecretKey(
                "AES", keysize, new KeystoreGenerationParameters(PASSWORD.toCharArray()));
        return identity.keystore();
    }

    public static int getKeysize(String hmacAlgorithm) {
        int keysize;
        if ("AES128-GMAC".equalsIgnoreCase(hmacAlgorithm)) {
            keysize = 128;
        } else if ("AES192-GMAC".equalsIgnoreCase(hmacAlgorithm)) {
            keysize = 192;
        } else if ("AES256-GMAC".equalsIgnoreCase(hmacAlgorithm)) {
            keysize = 256;
        } else {
            throw new IllegalArgumentException("unknown HMAC algorithm " + hmacAlgorithm);
        }
        return keysize;
    }

}
