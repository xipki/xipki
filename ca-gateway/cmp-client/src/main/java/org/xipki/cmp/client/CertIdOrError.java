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

package org.xipki.cmp.client;

import org.bouncycastle.asn1.crmf.CertId;
import org.xipki.cmp.PkiStatusInfo;

import static org.xipki.util.Args.notNull;

/**
 * CertId or PKI error.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CertIdOrError {

  private final CertId certId;

  private final PkiStatusInfo error;

  public CertIdOrError(CertId certId) {
    this.certId = notNull(certId, "certId");
    this.error = null;
  }

  public CertIdOrError(PkiStatusInfo error) {
    this.certId = null;
    this.error = notNull(error, "error");
  }

  public CertId getCertId() {
    return certId;
  }

  public PkiStatusInfo getError() {
    return error;
  }

}
