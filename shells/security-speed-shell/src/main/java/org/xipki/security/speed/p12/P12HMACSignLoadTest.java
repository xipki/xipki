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
public class P12HMACSignLoadTest extends P12SignLoadTest {

    public P12HMACSignLoadTest(SecurityFactory securityFactory, String signatureAlgorithm)
            throws Exception {
        super("JCEKS", securityFactory, signatureAlgorithm, generateKeystore(signatureAlgorithm),
                "JCEKS HMAC signature creation");
    }

    private static byte[] generateKeystore(String signatureAlgorithm) throws Exception {
        int keysize = getKeysize(signatureAlgorithm);
        P12KeyGenerationResult identity = new P12KeyGenerator().generateSecretKey(
                "GENERIC", keysize, new KeystoreGenerationParameters(PASSWORD.toCharArray()));
        return identity.keystore();
    }

    public static int getKeysize(String hmacAlgorithm) {
        int keysize;
        if ("HMACSHA1".equalsIgnoreCase(hmacAlgorithm)) {
            keysize = 160;
        } else if ("HMACSHA224".equalsIgnoreCase(hmacAlgorithm)
                || "HMACSHA3-224".equalsIgnoreCase(hmacAlgorithm)) {
            keysize = 224;
        } else if ("HMACSHA256".equalsIgnoreCase(hmacAlgorithm)
                || "HMACSHA3-256".equalsIgnoreCase(hmacAlgorithm)) {
            keysize = 256;
        } else if ("HMACSHA384".equalsIgnoreCase(hmacAlgorithm)
                || "HMACSHA3-384".equalsIgnoreCase(hmacAlgorithm)) {
            keysize = 384;
        } else if ("HMACSHA512".equalsIgnoreCase(hmacAlgorithm)
                || "HMACSHA3-512".equalsIgnoreCase(hmacAlgorithm)) {
            keysize = 512;
        } else {
            throw new IllegalArgumentException("unknown HMAC algorithm " + hmacAlgorithm);
        }
        return keysize;
    }

}
