/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.scep.client;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.xipki.scep.crypto.ScepHashAlgo;
import org.xipki.scep.util.ScepUtil;

/**
 * TODO.
 * @author Lijun Liao
 */

public final class PreprovisionedHashCaCertValidator implements CaCertValidator {

  private final ScepHashAlgo hashAlgo;

  private final Set<byte[]> hashValues;

  public PreprovisionedHashCaCertValidator(ScepHashAlgo hashAlgo, Set<byte[]> hashValues) {
    this.hashAlgo = ScepUtil.requireNonNull("hashAlgo", hashAlgo);
    ScepUtil.requireNonEmpty("hashValues", hashValues);

    final int hLen = hashAlgo.getLength();
    for (byte[] m : hashValues) {
      if (m.length != hLen) {
        throw new IllegalArgumentException("invalid the length of hashValue: "
            + m.length + " != " + hLen);
      }
    }

    this.hashValues = new HashSet<byte[]>(hashValues.size());
    for (byte[] m : hashValues) {
      this.hashValues.add(Arrays.copyOf(m, m.length));
    }
  }

  @Override
  public boolean isTrusted(X509Certificate cert) {
    ScepUtil.requireNonNull("cert", cert);
    byte[] actual;
    try {
      actual = hashAlgo.digest(cert.getEncoded());
    } catch (CertificateEncodingException ex) {
      return false;
    }

    for (byte[] m : hashValues) {
      if (Arrays.equals(actual, m)) {
        return true;
      }
    }

    return false;
  }

}
