// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.ca;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.security.KeySpec;
import org.xipki.security.util.KeyUtil;

import java.security.SecureRandom;

/**
 * SubjectPublicKeyInfo entry for benchmark enrollment test.
 *
 * @author Lijun Liao
 */

public class CaEnrollBenchKeyEntry {

  private SubjectPublicKeyInfo spki;

  private final KeySpec keySpec;

  private final SecureRandom random;

  public CaEnrollBenchKeyEntry(KeySpec keySpec, boolean reuse,
                               SecureRandom random)
      throws Exception {
    this.keySpec = keySpec;
    this.random = (random != null) ? random : new SecureRandom();
    if (!reuse) {
      return;
    }

    this.spki = KeyUtil.generateKeypair2(keySpec, this.random)
                  .subjectPublicKeyInfo();
  }

  public SubjectPublicKeyInfo getSubjectPublicKeyInfo() throws Exception {
    if (spki != null) {
      return spki;
    }

    return KeyUtil.generateKeypair2(keySpec, random).subjectPublicKeyInfo();
  }

}
