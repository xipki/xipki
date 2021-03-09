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

import org.xipki.security.HashAlgo;
import org.xipki.security.SignAlgo;
import org.xipki.security.X509Cert;
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

  private HashAlgo certhashAlg;

  private SignAlgo signatureAlg;

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

  public HashAlgo getCerthashAlg() {
    return certhashAlg;
  }

  public void setCerthashAlg(HashAlgo certhashAlg) {
    this.certhashAlg = certhashAlg;
  }

  public SignAlgo getSignatureAlg() {
    return signatureAlg;
  }

  public void setSignatureAlg(SignAlgo signatureAlg) {
    this.signatureAlg = signatureAlg;
  }

}
