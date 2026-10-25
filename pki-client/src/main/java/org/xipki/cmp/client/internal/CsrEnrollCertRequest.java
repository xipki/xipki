// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp.client.internal;

import org.xipki.pkix.asn1.pkcs10.CertificationRequest;
import org.xipki.cmp.client.IdentifiedObject;
import org.xipki.codec.util.Args;

/**
 * CMP request to enroll certificate for given CSR.
 *
 * @author Lijun Liao (xipki)
 */
class CsrEnrollCertRequest extends IdentifiedObject {

  private final String certprofile;

  private final CertificationRequest csr;

  CsrEnrollCertRequest(String id, String certprofile, CertificationRequest csr) {
    super(id);
    this.certprofile = Args.notBlank(certprofile, "certprofile");
    this.csr = Args.notNull(csr, "csr");
  }

  CertificationRequest csr() {
    return csr;
  }

  String certprofile() {
    return certprofile;
  }

}
