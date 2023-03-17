// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api;

import org.xipki.security.X509Cert;

/**
 * Certificate with id of this certificate in the database.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CertWithDbId {

  private final X509Cert cert;

  private Long certId;

  public CertWithDbId(X509Cert cert) {
    this.cert = cert;
  }

  public X509Cert getCert() {
    return cert;
  }

  public Long getCertId() {
    return certId;
  }

  public void setCertId(Long certId) {
    this.certId = certId;
  }

}
