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

package org.xipki.ca.client;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.xipki.security.AlgorithmValidator;
import org.xipki.util.Args;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.1.0
 */

class SignatureClientCmpResponder implements ClientCmpResponder {

  private final X509Certificate cert;

  private final AlgorithmValidator sigAlgoValidator;

  private final GeneralName name;

  public SignatureClientCmpResponder(X509Certificate cert, AlgorithmValidator sigAlgoValidator) {
    this.cert = Args.notNull(cert, "cert");
    this.sigAlgoValidator = Args.notNull(sigAlgoValidator, "sigAlgoValidator");
    this.name = new GeneralName(X500Name.getInstance(cert.getSubjectX500Principal().getEncoded()));
  }

  public X509Certificate getCert() {
    return cert;
  }

  public AlgorithmValidator getSigAlgoValidator() {
    return sigAlgoValidator;
  }

  @Override
  public GeneralName getName() {
    return name;
  }

}
