// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp.client;

import org.bouncycastle.asn1.crmf.CertId;
import org.xipki.cmp.PkiStatusInfo;
import org.xipki.util.Args;

/**
 * CertId or PKI error.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class CertIdOrError {

  private final CertId certId;

  private final PkiStatusInfo error;

  public CertIdOrError(CertId certId) {
    this.certId = Args.notNull(certId, "certId");
    this.error = null;
  }

  public CertIdOrError(PkiStatusInfo error) {
    this.certId = null;
    this.error = Args.notNull(error, "error");
  }

  public CertId getCertId() {
    return certId;
  }

  public PkiStatusInfo getError() {
    return error;
  }

}
