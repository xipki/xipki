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

package org.xipki.security.bc;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DSAExt;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.DSAEncoding;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;
import org.bouncycastle.jcajce.provider.asymmetric.util.DSABase;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.xipki.security.HashAlgo;

/**
 * SHAKE-ECDSA implementation.
 *
 * @author Lijun Liao
 */
// CHECKSTYLE:SKIP
public class ShakeECDSASignatureSpi extends DSABase {
  ShakeECDSASignatureSpi(Digest digest, DSAExt signer, DSAEncoding encoding) {
    super(digest, signer, encoding);
  }

  protected void engineInitVerify(PublicKey publicKey)
      throws InvalidKeyException {
    CipherParameters param = generatePublicKeyParameter(publicKey);

    digest.reset();
    signer.init(false, param);
  }

  static AsymmetricKeyParameter generatePublicKeyParameter(
      PublicKey key)
      throws InvalidKeyException {
    return ECUtil.generatePublicKeyParameter(key);
  }

  protected void engineInitSign(
      PrivateKey privateKey)
      throws InvalidKeyException {
    CipherParameters param = ECUtil.generatePrivateKeyParameter(privateKey);

    digest.reset();

    if (appRandom != null) {
      signer.init(true, new ParametersWithRandom(param, appRandom));
    } else {
      signer.init(true, param);
    }
  }

  // CHECKSTYLE:SKIP
  static public class SHAKE128 extends ShakeECDSASignatureSpi {
    public SHAKE128() {
      super(HashAlgo.SHAKE128.createDigest(), new ECDSASigner(), StandardDSAEncoding.INSTANCE);
    }
  }

  // CHECKSTYLE:SKIP
  static public class SHAKE256 extends ShakeECDSASignatureSpi {
    public SHAKE256() {
      super(HashAlgo.SHAKE256.createDigest(), new ECDSASigner(), StandardDSAEncoding.INSTANCE);
    }
  }

}
