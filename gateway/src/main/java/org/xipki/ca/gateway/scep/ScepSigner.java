// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.scep;

import org.xipki.security.pkix.X509Cert;
import org.xipki.security.scep.message.EnvelopedDataDecryptor;
import org.xipki.security.sign.ConcurrentSigner;

import java.security.Key;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 *
 * @author Lijun Liao (xipki)
 */

public class ScepSigner {

  private final PrivateKey key;

  private final X509Cert cert;

  private final EnvelopedDataDecryptor decryptor;

  public ScepSigner(ConcurrentSigner signer) {
    Key signingKey = signer.signingKey();
    if (!(signingKey instanceof PrivateKey)) {
      throw new IllegalArgumentException(
          "Unsupported signer type: the signing key is not a PrivateKey");
    }

    if (!(signer.x509Cert().publicKey() instanceof RSAPublicKey)) {
      throw new IllegalArgumentException("The SCEP responder key is not RSA key");
    }

    this.key = (PrivateKey) signingKey;
    this.cert = signer.x509Cert();
    this.decryptor = new EnvelopedDataDecryptor(
        new EnvelopedDataDecryptor.EnvelopedDataDecryptorInstance(cert, key));
  }

  public PrivateKey key() {
    return key;
  }

  public X509Cert cert() {
    return cert;
  }

  public EnvelopedDataDecryptor decryptor() {
    return decryptor;
  }

}
