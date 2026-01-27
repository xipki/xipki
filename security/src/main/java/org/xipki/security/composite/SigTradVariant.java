// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.security.composite;

import org.xipki.security.KeySpec;
import org.xipki.security.SignAlgo;

/**
 * Enumeration of Traditional algorithm variants used in
 * {@link CompositeSigSuite}.
 * @author Lijun Liao (xipki)
 */
public enum SigTradVariant {

  Ed25519       (SignAlgo.ED25519,       KeySpec.ED25519),
  Ed448         (SignAlgo.ED448,         KeySpec.ED448),
  ECDSA_P256    (SignAlgo.ECDSA_SHA256,  KeySpec.SECP256R1),
  ECDSA_P384    (SignAlgo.ECDSA_SHA384,  KeySpec.SECP384R1),
  ECDSA_P521    (SignAlgo.ECDSA_SHA512,  KeySpec.SECP521R1),
  ECDSA_BP256   (SignAlgo.ECDSA_SHA256,  KeySpec.BRAINPOOLP256R1),
  ECDSA_BP384   (SignAlgo.ECDSA_SHA384,  KeySpec.BRAINPOOLP384R1),
  RSA2048_PSS   (SignAlgo.RSAPSS_SHA256, KeySpec.RSA2048),
  RSA2048_PKCS15(SignAlgo.RSA_SHA256,    KeySpec.RSA2048),
  RSA3072_PSS   (SignAlgo.RSAPSS_SHA256, KeySpec.RSA3072),
  RSA3072_PKCS15(SignAlgo.RSA_SHA256,    KeySpec.RSA3072),
  RSA4096_PSS   (SignAlgo.RSAPSS_SHA384, KeySpec.RSA4096),
  RSA4096_PKCS15(SignAlgo.RSA_SHA384,    KeySpec.RSA4096);

  private final SignAlgo signAlgo;

  private final KeySpec keySpec;

  SigTradVariant(SignAlgo signAlgo, KeySpec keySpec) {
    this.signAlgo = signAlgo;
    this.keySpec = keySpec;
  }

  public SignAlgo signAlgo() {
    return signAlgo;
  }

  public KeySpec keySpec() {
    return keySpec;
  }

}
