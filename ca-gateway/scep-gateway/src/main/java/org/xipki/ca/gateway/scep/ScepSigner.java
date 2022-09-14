/*
 *
 * Copyright (c) 2013 - 2022 Lijun Liao
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

package org.xipki.ca.gateway.scep;

import org.xipki.scep.message.EnvelopedDataDecryptor;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.X509Cert;

import java.security.Key;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class ScepSigner {

  private final PrivateKey key;

  private final X509Cert cert;

  private final EnvelopedDataDecryptor decryptor;

  public ScepSigner(ConcurrentContentSigner signer) {
    Key signingKey = signer.getSigningKey();
    if (!(signingKey instanceof PrivateKey)) {
      throw new IllegalArgumentException("Unsupported signer type: the signing key is not a PrivateKey");
    }

    if (!(signer.getCertificate().getPublicKey() instanceof RSAPublicKey)) {
      throw new IllegalArgumentException("The SCEP responder key is not RSA key");
    }

    this.key = (PrivateKey) signingKey;
    this.cert = signer.getCertificate();
    this.decryptor = new EnvelopedDataDecryptor(new EnvelopedDataDecryptor.EnvelopedDataDecryptorInstance(cert, key));
  }

  public ScepSigner(PrivateKey key, X509Cert cert, EnvelopedDataDecryptor decryptor) {
    this.key = key;
    this.cert = cert;
    this.decryptor = decryptor;
  }

  public PrivateKey getKey() {
    return key;
  }

  public X509Cert getCert() {
    return cert;
  }

  public EnvelopedDataDecryptor getDecryptor() {
    return decryptor;
  }

}
