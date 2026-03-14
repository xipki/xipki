// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs12;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.security.util.X509Util;

import java.security.KeyPair;

/**
 * XiPKI component.
 *
 * @author Lijun Liao (xipki)
 */
public class KeyPairWithSubjectPublicKeyInfo {

  private final KeyPair keypair;

  private final SubjectPublicKeyInfo subjectPublicKeyInfo;

  public KeyPairWithSubjectPublicKeyInfo(
      KeyPair keypair, SubjectPublicKeyInfo subjectPublicKeyInfo) {
    this.keypair = keypair;
    this.subjectPublicKeyInfo = X509Util.toRfc3279Style(subjectPublicKeyInfo);
  }

  public KeyPair keypair() {
    return keypair;
  }

  public SubjectPublicKeyInfo subjectPublicKeyInfo() {
    return subjectPublicKeyInfo;
  }

}
