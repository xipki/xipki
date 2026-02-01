// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.ca;

import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.codec.Args;
import org.xipki.util.extra.misc.CollectionUtil;

import java.security.cert.CertificateException;
import java.time.Instant;
import java.util.List;
import java.util.Set;

/**
 * Certificate issuer information.
 *
 * @author Lijun Liao
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
    Args.notNull(certBytes, "certBytes");

    this.cutoffNotAfter = cutoffNotAfter;
    this.caIssuerUrls = CollectionUtil.isEmpty(caIssuerUrls) ? null
        : Set.copyOf(caIssuerUrls);
    this.ocspUrls     = CollectionUtil.isEmpty(ocspUrls) ? null
        : Set.copyOf(ocspUrls);
    this.crlUrls      = CollectionUtil.isEmpty(crlUrls) ? null
        : Set.copyOf(crlUrls);
    this.deltaCrlUrls = CollectionUtil.isEmpty(deltaCrlUrls) ? null
        : Set.copyOf(deltaCrlUrls);
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
    return cert.subjectKeyId();
  }

  public boolean isCutoffNotAfter() {
    return cutoffNotAfter;
  }

  public Instant getCaNotBefore() {
    return cert.notBefore();
  }

  public Instant getCaNotAfter() {
    return cert.notAfter();
  }

}
