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

package org.xipki.ca.client.api.dto;

import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.xipki.util.ParamUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class EnrollCertRequestEntry extends IdentifiedObject {

  private final String certprofile;

  private final CertRequest certReq;

  private final ProofOfPossession popo;

  private final boolean caGenerateKeypair;

  public EnrollCertRequestEntry(String id, String certprofile, CertRequest certReq,
      ProofOfPossession popo) {
    super(id);

    this.certprofile = ParamUtil.requireNonBlank("certprofile", certprofile);
    this.certReq = ParamUtil.requireNonNull("certReq", certReq);
    this.caGenerateKeypair = false;
    this.popo = ParamUtil.requireNonNull("popo", popo);
  }

  public EnrollCertRequestEntry(String id, String certprofile, CertRequest certReq,
      ProofOfPossession popo, boolean caGenerateKeypair, boolean kup) {
    super(id);

    if (kup) {
      this.certprofile = certprofile;
    } else {
      this.certprofile = ParamUtil.requireNonBlank("certprofile", certprofile);
    }

    this.certReq = ParamUtil.requireNonNull("certReq", certReq);
    this.caGenerateKeypair = caGenerateKeypair;
    if (!caGenerateKeypair) {
      ParamUtil.requireNonNull("popo", popo);
    }
    this.popo = popo;
  }

  public String getCertprofile() {
    return certprofile;
  }

  public CertRequest getCertReq() {
    return certReq;
  }

  public ProofOfPossession getPopo() {
    return popo;
  }

  public boolean isCaGenerateKeypair() {
    return caGenerateKeypair;
  }

}
