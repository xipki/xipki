/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

import org.xipki.security.HashAlgo;

/**
 * TODO.
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
      super(HashAlgo.SHA1);
    }

  } // class SHA1

  // CHECKSTYLE:SKIP
  public static class SHA224 extends P11ECDSASignatureSpi {

    public SHA224() {
      super(HashAlgo.SHA224);
    }

  } // class SHA224

  // CHECKSTYLE:SKIP
  public static class SHA256 extends P11ECDSASignatureSpi {

    public SHA256() {
      super(HashAlgo.SHA256);
    }

  } // class SHA256

  // CHECKSTYLE:SKIP
  public static class SHA384 extends P11ECDSASignatureSpi {

    public SHA384() {
      super(HashAlgo.SHA384);
    }

  } // class SHA384

  // CHECKSTYLE:SKIP
  public static class SHA512 extends P11ECDSASignatureSpi {

    public SHA512() {
      super(HashAlgo.SHA512);
    }

  } // class SHA512

  // CHECKSTYLE:SKIP
  public static class SHA3_224 extends P11ECDSASignatureSpi {

    public SHA3_224() {
      super(HashAlgo.SHA3_224);
    }

  } // class SHA3_224

  // CHECKSTYLE:SKIP
  public static class SHA3_256 extends P11ECDSASignatureSpi {

    public SHA3_256() {
      super(HashAlgo.SHA3_256);
    }

  } // class SHA3_256

  // CHECKSTYLE:SKIP
  public static class SHA3_384 extends P11ECDSASignatureSpi {

    public SHA3_384() {
      super(HashAlgo.SHA3_384);
    }

  } // class SHA3_384

  // CHECKSTYLE:SKIP
  public static class SHA3_512 extends P11ECDSASignatureSpi {

    public SHA3_512() {
      super(HashAlgo.SHA3_512);
    }

  } // class SHA3_512

  private P11ECDSASignatureSpi(HashAlgo hashAlgo) {
    super(hashAlgo, false);
  }

}
