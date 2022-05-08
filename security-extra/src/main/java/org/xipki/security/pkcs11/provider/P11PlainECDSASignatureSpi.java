/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

import java.security.SignatureSpi;

/**
 * PKCS#11 ECDSA {@link SignatureSpi}.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */
public class P11PlainECDSASignatureSpi extends AbstractP11ECDSASignatureSpi {

  public static class SHA1 extends P11PlainECDSASignatureSpi {

    public SHA1() {
      super(HashAlgo.SHA1);
    }

  } // class SHA1

  public static class NONE extends P11PlainECDSASignatureSpi {

    public NONE() {
      super(null);
    }

  } // class NONE

  public static class SHA224 extends P11PlainECDSASignatureSpi {

    public SHA224() {
      super(HashAlgo.SHA224);
    }

  } // class SHA224

  public static class SHA256 extends P11PlainECDSASignatureSpi {

    public SHA256() {
      super(HashAlgo.SHA256);
    }

  } // class SHA256

  static class SHA384 extends P11PlainECDSASignatureSpi {

    SHA384() {
      super(HashAlgo.SHA384);
    }

  } // class SHA384

  public static class SHA512 extends P11PlainECDSASignatureSpi {

    public SHA512() {
      super(HashAlgo.SHA512);
    }

  } // class SHA512

  private P11PlainECDSASignatureSpi(HashAlgo hashAlgo) {
    super(hashAlgo, true);
  }

}
