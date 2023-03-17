// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

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
 * @author Lijun Liao (xipki)
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
    this.caIssuerUrls = isEmpty(caIssuerUrls) ? null : Collections.unmodifiableSet(new HashSet<>(caIssuerUrls));
    this.ocspUrls = isEmpty(ocspUrls) ? null : Collections.unmodifiableSet(new HashSet<>(ocspUrls));
    this.crlUrls = isEmpty(crlUrls) ? null : Collections.unmodifiableSet(new HashSet<>(crlUrls));
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
