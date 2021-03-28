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

package org.xipki.security.pkcs11;

import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import org.xipki.security.HashAlgo;

/**
 * PKCS#11 params.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public interface P11Params {

  class P11ByteArrayParams implements P11Params {

    private final byte[] bytes;

    public P11ByteArrayParams(byte[] bytes) {
      this.bytes = bytes;
    }

    public byte[] getBytes() {
      return bytes;
    }

  }

  // CHECKSTYLE:SKIP
  class P11IVParams implements P11Params {

    private final byte[] iv;

    public P11IVParams(byte[] iv) {
      this.iv = iv;
    }

    // CHECKSTYLE:SKIP
    public byte[] getIV() {
      return iv;
    }

  }

  //CHECKSTYLE:SKIP
  class P11RSAPkcsPssParams implements P11Params {

    private final long hashAlgorithm;

    private final long maskGenerationFunction;

    private final long saltLength;

    public P11RSAPkcsPssParams(long hashAlgorithm, long maskGenerationFunction, long saltLength) {
      this.hashAlgorithm = hashAlgorithm;
      this.maskGenerationFunction = maskGenerationFunction;
      this.saltLength = saltLength;
    }

    public P11RSAPkcsPssParams(HashAlgo hashAlgo) {
      this.saltLength = hashAlgo.getLength();

      switch (hashAlgo) {
        case SHA1:
          this.hashAlgorithm = PKCS11Constants.CKM_SHA_1;
          this.maskGenerationFunction = PKCS11Constants.CKG_MGF1_SHA1;
          break;
        case SHA224:
          this.hashAlgorithm = PKCS11Constants.CKM_SHA224;
          this.maskGenerationFunction = PKCS11Constants.CKG_MGF1_SHA224;
          break;
        case SHA256:
          this.hashAlgorithm = PKCS11Constants.CKM_SHA256;
          this.maskGenerationFunction = PKCS11Constants.CKG_MGF1_SHA256;
          break;
        case SHA384:
          this.hashAlgorithm = PKCS11Constants.CKM_SHA384;
          this.maskGenerationFunction = PKCS11Constants.CKG_MGF1_SHA384;
          break;
        case SHA512:
          this.hashAlgorithm = PKCS11Constants.CKM_SHA512;
          this.maskGenerationFunction = PKCS11Constants.CKG_MGF1_SHA512;
          break;
        case SHA3_224:
          this.hashAlgorithm = PKCS11Constants.CKM_SHA3_224;
          this.maskGenerationFunction = PKCS11Constants.CKG_MGF1_SHA3_224;
          break;
        case SHA3_256:
          this.hashAlgorithm = PKCS11Constants.CKM_SHA3_256;
          this.maskGenerationFunction = PKCS11Constants.CKG_MGF1_SHA3_256;
          break;
        case SHA3_384:
          this.hashAlgorithm = PKCS11Constants.CKM_SHA3_384;
          this.maskGenerationFunction = PKCS11Constants.CKG_MGF1_SHA3_384;
          break;
        case SHA3_512:
          this.hashAlgorithm = PKCS11Constants.CKM_SHA3_512;
          this.maskGenerationFunction = PKCS11Constants.CKG_MGF1_SHA3_512;
          break;
        default:
          throw new IllegalStateException("unsupported Hash algorithm " + hashAlgo);
      }
    }

    public long getHashAlgorithm() {
      return hashAlgorithm;
    }

    public long getMaskGenerationFunction() {
      return maskGenerationFunction;
    }

    public long getSaltLength() {
      return saltLength;
    }

  }

}
