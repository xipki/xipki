// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.ca;

import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.crypto.core.KeySpec;
import org.xipki.pkix.util.KeyUtil;


/**
 * CA Enroll Bench Key entry.
 *
 * @author Lijun Liao (xipki)
 */
public class CaEnrollBenchKeyEntry {

  private SubjectPublicKeyInfo spki;

  private final KeySpec keySpec;

  public CaEnrollBenchKeyEntry(KeySpec keySpec, boolean reuse) throws Exception {
    this.keySpec = keySpec;
    if (!reuse) {
      return;
    }

    this.spki = KeyUtil.generateKeyPair2(keySpec).subjectPublicKeyInfo();
  }

  public SubjectPublicKeyInfo getSubjectPublicKeyInfo() throws Exception {
    if (spki != null) {
      return spki;
    }

    return KeyUtil.generateKeyPair2(keySpec).subjectPublicKeyInfo();
  }

}
