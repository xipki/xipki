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

package org.xipki.qa.ocsp;

import java.security.NoSuchAlgorithmException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.security.X509Cert;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.TripleState;

/**
 * OCSP response option.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class OcspResponseOption {

  private X509Cert respIssuer;

  private TripleState nonceOccurrence;

  private TripleState certhashOccurrence;

  private TripleState nextUpdateOccurrence;

  private ASN1ObjectIdentifier certhashAlgId;

  private String signatureAlgName;

  public OcspResponseOption() {
  }

  public X509Cert getRespIssuer() {
    return respIssuer;
  }

  public void setRespIssuer(X509Cert respIssuer) {
    this.respIssuer = respIssuer;
  }

  public TripleState getNonceOccurrence() {
    return nonceOccurrence;
  }

  public void setNonceOccurrence(TripleState nonceOccurrence) {
    this.nonceOccurrence = nonceOccurrence;
  }

  public TripleState getCerthashOccurrence() {
    return certhashOccurrence;
  }

  public void setCerthashOccurrence(TripleState certhashOccurrence) {
    this.certhashOccurrence = certhashOccurrence;
  }

  public TripleState getNextUpdateOccurrence() {
    return nextUpdateOccurrence;
  }

  public void setNextUpdateOccurrence(TripleState nextUpdateOccurrence) {
    this.nextUpdateOccurrence = nextUpdateOccurrence;
  }

  public ASN1ObjectIdentifier getCerthashAlgId() {
    return certhashAlgId;
  }

  public void setCerthashAlgId(ASN1ObjectIdentifier certhashAlgId) {
    this.certhashAlgId = certhashAlgId;
  }

  public String getSignatureAlgName() {
    return signatureAlgName;
  }

  public void setSignatureAlgName(String signatureAlgName) throws NoSuchAlgorithmException {
    this.signatureAlgName = StringUtil.isBlank(signatureAlgName) ? null
        : AlgorithmUtil.canonicalizeSignatureAlgo(signatureAlgName);
  }

}
