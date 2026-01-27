// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp.client.internal;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.xipki.cmp.client.IdentifiedObject;
import org.xipki.util.codec.Args;

/**
 * CMP request to enroll certificate for given CSR.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

class CsrEnrollCertRequest extends IdentifiedObject {

  private final String certprofile;

  private final CertificationRequest csr;

  CsrEnrollCertRequest(String id, String certprofile,
                       CertificationRequest csr) {
    super(id);
    this.certprofile = Args.notBlank(certprofile, "certprofile");
    this.csr = Args.notNull(csr, "csr");
  }

  CertificationRequest getCsr() {
    return csr;
  }

  String getCertprofile() {
    return certprofile;
  }

}
