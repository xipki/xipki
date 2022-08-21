/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.qa.ca;

import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;

import java.security.cert.CertificateException;
import java.util.*;

import static org.xipki.util.Args.notNull;
import static org.xipki.util.CollectionUtil.isEmpty;

/**
 * Certificate issuer information.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class IssuerInfo {

  private final Set<String> caIssuerUrls;

  private final Set<String> ocspUrls;

  private final Set<String> crlUrls;

  private final Set<String> deltaCrlUrls;

  private final X509Cert cert;

  private final boolean cutoffNotAfter;

  public IssuerInfo(
      List<String> caIssuerUrls, List<String> ocspUrls, List<String> crlUrls,
      List<String> deltaCrlUrls, byte[] certBytes, boolean cutoffNotAfter)
      throws CertificateException {
    notNull(certBytes, "certBytes");

    this.cutoffNotAfter = cutoffNotAfter;

    if (isEmpty(caIssuerUrls)) {
      this.caIssuerUrls = null;
    } else {
      this.caIssuerUrls = Collections.unmodifiableSet(new HashSet<>(caIssuerUrls));
    }

    if (isEmpty(ocspUrls)) {
      this.ocspUrls = null;
    } else {
      this.ocspUrls = Collections.unmodifiableSet(new HashSet<>(ocspUrls));
    }

    if (isEmpty(crlUrls)) {
      this.crlUrls = null;
    } else {
      this.crlUrls = Collections.unmodifiableSet(new HashSet<>(crlUrls));
    }

    this.deltaCrlUrls = isEmpty(deltaCrlUrls) ? null : Collections.unmodifiableSet(new HashSet<>(deltaCrlUrls));

    this.cert = X509Util.parseCert(certBytes);
  } // constructor

  public Set<String> getCaIssuerUrls() {
    return caIssuerUrls;
  }

  public Set<String> getOcspUrls() {
    return ocspUrls;
  }

  public Set<String> getCrlUrls() {
    return crlUrls;
  }

  public Set<String> getDeltaCrlUrls() {
    return deltaCrlUrls;
  }

  public X509Cert getCert() {
    return cert;
  }

  public byte[] getSubjectKeyIdentifier() {
    return cert.getSubjectKeyId();
  }

  public boolean isCutoffNotAfter() {
    return cutoffNotAfter;
  }

  public Date getCaNotBefore() {
    return cert.getNotBefore();
  }

  public Date getCaNotAfter() {
    return cert.getNotAfter();
  }

}
