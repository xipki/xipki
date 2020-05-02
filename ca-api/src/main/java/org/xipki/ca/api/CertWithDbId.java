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
