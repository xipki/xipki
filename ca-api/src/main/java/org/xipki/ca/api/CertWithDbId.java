// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api;

import org.xipki.security.X509Cert;

/**
 * Certificate with id of this certificate in the database.
 *
 * @author Lijun Liao (xipki)
 */

public class CertWithDbId {

  private final X509Cert cert;

  private Long certId;

  public CertWithDbId(X509Cert cert) {
    this.cert = cert;
  }

  public X509Cert cert() {
    return cert;
  }

  public Long certId() {
    return certId;
  }

  public void setCertId(Long certId) {
    this.certId = certId;
  }

}
