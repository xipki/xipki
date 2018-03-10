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
import java.util.concurrent.ConcurrentHashMap;

import org.xipki.scep.crypto.ScepHashAlgo;
import org.xipki.scep.util.ScepUtil;

/**
 * CA certificate validator with caching certificates.
 * @author Lijun Liao
 */

public final class CachingCertificateValidator implements CaCertValidator {

  private final ConcurrentHashMap<String, Boolean> cachedAnswers;

  private final CaCertValidator delegate;

  public CachingCertificateValidator(CaCertValidator delegate) {
    this.delegate = ScepUtil.requireNonNull("delegate", delegate);
    this.cachedAnswers = new ConcurrentHashMap<String, Boolean>();
  }

  @Override
  public boolean isTrusted(X509Certificate cert) {
    ScepUtil.requireNonNull("cert", cert);
    String hexFp;
    try {
      hexFp = ScepHashAlgo.SHA256.hexDigest(cert.getEncoded());
    } catch (CertificateEncodingException ex) {
      return false;
    }

    Boolean bo = cachedAnswers.get(hexFp);

    if (bo != null) {
      return bo.booleanValue();
    } else {
      boolean answer = delegate.isTrusted(cert);
      cachedAnswers.put(hexFp, answer);
      return answer;
    }
  }

}
