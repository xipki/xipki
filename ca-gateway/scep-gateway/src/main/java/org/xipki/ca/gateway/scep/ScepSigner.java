// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.scep;

import org.xipki.scep.message.EnvelopedDataDecryptor;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.X509Cert;

import java.security.Key;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 *
 * @author Lijun Liao (xipki)
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
