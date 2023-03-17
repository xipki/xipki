// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt;

import org.xipki.ca.api.CertWithDbId;
import org.xipki.security.CertRevocationInfo;

/**
 * Certificate with revocation information.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class CertWithRevocationInfo {

  private CertWithDbId cert;

  private CertRevocationInfo revInfo;

  private String certprofile;

  public CertWithRevocationInfo() {
  }

  public CertWithDbId getCert() {
    return cert;
  }

  public boolean isRevoked() {
    return revInfo != null;
  }

  public CertRevocationInfo getRevInfo() {
    return revInfo;
  }

  public void setCert(CertWithDbId cert) {
    this.cert = cert;
  }

  public void setRevInfo(CertRevocationInfo revInfo) {
    this.revInfo = revInfo;
  }

  public String getCertprofile() {
    return certprofile;
  }

  public void setCertprofile(String certprofile) {
    this.certprofile = certprofile;
  }

}
