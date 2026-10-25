// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.ca;

import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.crypto.core.KeySpec;
import org.xipki.pkix.util.KeyUtil;

import java.security.SecureRandom;

/**
 * CA Enroll Bench Key entry.
 *
 * @author Lijun Liao (xipki)
 */
public class CaEnrollBenchKeyEntry {

  private SubjectPublicKeyInfo spki;

  private final KeySpec keySpec;

  private final SecureRandom random;

  public CaEnrollBenchKeyEntry(KeySpec keySpec, boolean reuse, SecureRandom random)
      throws Exception {
    this.keySpec = keySpec;
    this.random = (random != null) ? random : new SecureRandom();
    if (!reuse) {
      return;
    }

    this.spki = KeyUtil.generateKeyPair2(keySpec, this.random).subjectPublicKeyInfo();
  }

  public SubjectPublicKeyInfo getSubjectPublicKeyInfo() throws Exception {
    if (spki != null) {
      return spki;
    }

    return KeyUtil.generateKeyPair2(keySpec, random).subjectPublicKeyInfo();
  }

}
