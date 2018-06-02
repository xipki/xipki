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

import java.io.IOException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.operator.bc.BcAsymmetricKeyWrapper;

/**
 * TODO.
 * @author Lijun Liao
 */

// CHECKSTYLE:SKIP
public class RSAOAEPAsymmetricKeyWrapper extends BcAsymmetricKeyWrapper {

  private static final AlgorithmIdentifier OAEP_DFLT = new AlgorithmIdentifier(
      PKCSObjectIdentifiers.id_RSAES_OAEP, new RSAESOAEPparams());

  public RSAOAEPAsymmetricKeyWrapper(SubjectPublicKeyInfo publicKeyInfo) throws IOException {
    super(OAEP_DFLT, PublicKeyFactory.createKey(publicKeyInfo));
  }

  protected AsymmetricBlockCipher createAsymmetricWrapper(ASN1ObjectIdentifier algorithm) {
    if (!PKCSObjectIdentifiers.id_RSAES_OAEP.equals(algorithm)) {
      throw new IllegalStateException("unsupported algorithm " + algorithm.getId());
    }
    return new OAEPEncoding(new RSAEngine());
  }

}
