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

package org.xipki.security.pkcs11.provider;

import org.xipki.security.HashAlgoType;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

// CHECKSTYLE:SKIP
public class P11ECDSASignatureSpi extends AbstractP11ECDSASignatureSpi {

    // CHECKSTYLE:SKIP
    public static class NONE extends P11ECDSASignatureSpi {

        public NONE() {
            super(null);
        }

    } // class NONE

    // CHECKSTYLE:SKIP
    public static class SHA1 extends P11ECDSASignatureSpi {

        public SHA1() {
            super(HashAlgoType.SHA1);
        }

    } // class SHA1

    // CHECKSTYLE:SKIP
    public static class SHA224 extends P11ECDSASignatureSpi {

        public SHA224() {
            super(HashAlgoType.SHA224);
        }

    } // class SHA224

    // CHECKSTYLE:SKIP
    public static class SHA256 extends P11ECDSASignatureSpi {

        public SHA256() {
            super(HashAlgoType.SHA256);
        }

    } // class SHA256

    // CHECKSTYLE:SKIP
    public static class SHA384 extends P11ECDSASignatureSpi {

        public SHA384() {
            super(HashAlgoType.SHA384);
        }

    } // class SHA384

    // CHECKSTYLE:SKIP
    public static class SHA512 extends P11ECDSASignatureSpi {

        public SHA512() {
            super(HashAlgoType.SHA512);
        }

    } // class SHA512

    // CHECKSTYLE:SKIP
    public static class SHA3_224 extends P11ECDSASignatureSpi {

        public SHA3_224() {
            super(HashAlgoType.SHA3_224);
        }

    } // class SHA3_224

    // CHECKSTYLE:SKIP
    public static class SHA3_256 extends P11ECDSASignatureSpi {

        public SHA3_256() {
            super(HashAlgoType.SHA3_256);
        }

    } // class SHA3_256

    // CHECKSTYLE:SKIP
    public static class SHA3_384 extends P11ECDSASignatureSpi {

        public SHA3_384() {
            super(HashAlgoType.SHA3_384);
        }

    } // class SHA3_384

    // CHECKSTYLE:SKIP
    public static class SHA3_512 extends P11ECDSASignatureSpi {

        public SHA3_512() {
            super(HashAlgoType.SHA3_512);
        }

    } // class SHA3_512

    private P11ECDSASignatureSpi(final HashAlgoType hashAlgo) {
        super(hashAlgo, false);
    }

}
