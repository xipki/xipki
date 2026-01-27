// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.util.codec.Args;

import java.security.KeyPair;

/**
 * @author Lijun Liao (xipki)
 */
public class KeyInfoPair {

  private final SubjectPublicKeyInfo _public;

  private final PrivateKeyInfo _private;

  public KeyInfoPair(KeyPair keyPair) {
    Args.notNull(keyPair, "keyPair");
    this._private = PrivateKeyInfo.getInstance(
        keyPair.getPrivate().getEncoded());
    this._public = SubjectPublicKeyInfo.getInstance(
        keyPair.getPublic().getEncoded());
  }

  public KeyInfoPair(
      SubjectPublicKeyInfo _public, PrivateKeyInfo _private) {
    this._private = Args.notNull(_private, "_private");
    this._public = Args.notNull(_public, "_public");
  }

  public SubjectPublicKeyInfo getPublic() {
    return _public;
  }

  public PrivateKeyInfo getPrivate() {
    return _private;
  }
}
