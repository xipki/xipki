// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt;

import org.xipki.security.CertRevocationInfo;
import org.xipki.security.X509Cert;

/**
 * Certificate with status info.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class CertWithStatusInfo {

  private X509Cert cert;

  private String certprofile;

  private CertRevocationInfo revocationInfo;

  public CertWithStatusInfo() {
  }

  public X509Cert getCert() {
    return cert;
  }

  public void setCert(X509Cert cert) {
    this.cert = cert;
  }

  public String getCertprofile() {
    return certprofile;
  }

  public void setCertprofile(String certprofile) {
    this.certprofile = certprofile;
  }

  public CertRevocationInfo getRevocationInfo() {
    return revocationInfo;
  }

  public void setRevocationInfo(CertRevocationInfo revocationInfo) {
    this.revocationInfo = revocationInfo;
  }

}
