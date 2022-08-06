/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.cmpclient.internal;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.xipki.cmpclient.IdentifiedObject;

import static org.xipki.util.Args.notBlank;
import static org.xipki.util.Args.notNull;

/**
 * CMP request to enroll certificate for given CSR.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

class CsrEnrollCertRequest extends IdentifiedObject {

  private final String certprofile;

  private final CertificationRequest csr;

  CsrEnrollCertRequest(String id, String certprofile, CertificationRequest csr) {
    super(id);
    this.certprofile = notBlank(certprofile, "certprofile");
    this.csr = notNull(csr, "csr");
  }

  CertificationRequest getCsr() {
    return csr;
  }

  String getCertprofile() {
    return certprofile;
  }

}
