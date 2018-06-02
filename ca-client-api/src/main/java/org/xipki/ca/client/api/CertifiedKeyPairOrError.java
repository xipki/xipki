/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.ca.client.api;

import java.security.cert.Certificate;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.xipki.cmp.PkiStatusInfo;
import org.xipki.common.util.ParamUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CertifiedKeyPairOrError {

  private final Certificate certificate;

  private final PrivateKeyInfo privateKeyInfo;

  private final PkiStatusInfo error;

  public CertifiedKeyPairOrError(Certificate certificate, PrivateKeyInfo privateKeyInfo) {
    this.certificate = ParamUtil.requireNonNull("certificate", certificate);
    this.privateKeyInfo = privateKeyInfo;
    this.error = null;
  }

  public CertifiedKeyPairOrError(PkiStatusInfo error) {
    this.certificate = null;
    this.privateKeyInfo = null;
    this.error = ParamUtil.requireNonNull("error", error);
  }

  public Certificate getCertificate() {
    return certificate;
  }

  public PrivateKeyInfo getPrivateKeyInfo() {
    return privateKeyInfo;
  }

  public PkiStatusInfo getError() {
    return error;
  }

}
