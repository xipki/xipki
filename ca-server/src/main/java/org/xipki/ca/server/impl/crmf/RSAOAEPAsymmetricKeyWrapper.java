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

package org.xipki.ca.server.impl.crmf;

import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.OperatorException;

/**
 * TODO.
 * @author Lijun Liao
 */

// CHECKSTYLE:SKIP
public class RSAOAEPAsymmetricKeyWrapper implements CrmfKeyWrapper {

  private static final AlgorithmIdentifier OAEP_DFLT = new AlgorithmIdentifier(
      PKCSObjectIdentifiers.id_RSAES_OAEP, new RSAESOAEPparams());

  private RSAPublicKey publicKey;

  public RSAOAEPAsymmetricKeyWrapper(RSAPublicKey publicKey) {
    this.publicKey = publicKey;
  }

  @Override
  public AlgorithmIdentifier getAlgorithmIdentifier() {
    return OAEP_DFLT;
  }

  @Override
  public byte[] generateWrappedKey(byte[] encryptionKey) throws OperatorException {
    try {
      Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPPADDING", "BC");
      cipher.init(Cipher.ENCRYPT_MODE, publicKey);
      return cipher.doFinal(encryptionKey);
    } catch (Exception ex) {
      throw new OperatorException("error in generateWrappedKey", ex);
    }
  }

}
