// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp.client;

import org.bouncycastle.asn1.crmf.CertId;
import org.xipki.security.cmp.PkiStatusInfo;
import org.xipki.util.codec.Args;

/**
 * CertId or PKI error.
 *
 * @author Lijun Liao (xipki)
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

  public CertId certId() {
    return certId;
  }

  public PkiStatusInfo error() {
    return error;
  }

}
