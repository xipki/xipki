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

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.xipki.security.exception.P11TokenException;
import org.xipki.security.exception.XiSecurityException;

import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */
//CHECKSTYLE:SKIP
public class P11PlainRSASigner implements AsymmetricBlockCipher {

  private P11RSAKeyParameter param;

  public P11PlainRSASigner() {
  }

  @Override
  public void init(boolean forEncryption, CipherParameters cipherParam) {
    if (!forEncryption) {
      throw new RuntimeCryptoException("verification mode not supported.");
    }

    if (!(cipherParam instanceof P11RSAKeyParameter)) {
      throw new IllegalArgumentException("invalid param type " + cipherParam.getClass().getName());
    }
    this.param = (P11RSAKeyParameter) cipherParam;
  }

  @Override
  public int getInputBlockSize() {
    return (param.keysize() + 7) / 8;
  }

  @Override
  public int getOutputBlockSize() {
    return (param.keysize() + 7) / 8;
  }

  @Override
  public byte[] processBlock(byte[] in, int inOff, int len) throws InvalidCipherTextException {
    byte[] content = new byte[getInputBlockSize()];
    System.arraycopy(in, inOff, content, content.length - len, len);

    try {
      P11Identity identity = param.p11CryptService().getIdentity(param.identityId());
      return identity.sign(PKCS11Constants.CKM_RSA_X_509, null, content);
    } catch (XiSecurityException | P11TokenException ex) {
      throw new InvalidCipherTextException(ex.getMessage(), ex);
    }
  }

}
