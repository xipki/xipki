// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs12;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.util.codec.Args;

/**
 * Keystore wrapper (containing the keystore object and its encoded form).
 *
 * @author Lijun Liao (xipki)
 */
public class PKCS12KeyStoreWrapper {

  private final byte[] keystore;

  private PKCS12KeyStore keystoreObject;

  private SubjectPublicKeyInfo subjectPublicKeyInfo;

  public PKCS12KeyStoreWrapper(byte[] keystore) {
    this.keystore = Args.notNull(keystore, "keystore");
  }

  public byte[] keystore() {
    return keystore;
  }

  public PKCS12KeyStore keystoreObject() {
    return keystoreObject;
  }

  public void setKeystoreObject(PKCS12KeyStore keystoreObject) {
    this.keystoreObject = keystoreObject;
  }

  public SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
    return subjectPublicKeyInfo;
  }

  public void setSubjectPublicKeyInfo(SubjectPublicKeyInfo subjectPublicKeyInfo) {
    this.subjectPublicKeyInfo = subjectPublicKeyInfo;
  }

}
