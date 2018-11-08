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
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.SecurityFactory;
import org.xipki.util.ParamUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class SignatureClientCmpRequestor implements ClientCmpRequestor {

  private final GeneralName name;

  private final ConcurrentContentSigner signer;

  private final boolean signRequest;

  public SignatureClientCmpRequestor(X509Certificate cert) {
    ParamUtil.requireNonNull("cert", cert);
    X500Name x500Name = X500Name.getInstance(cert.getSubjectX500Principal().getEncoded());
    this.name = new GeneralName(x500Name);
    this.signer = null;
    this.signRequest = false;
  }

  public SignatureClientCmpRequestor(boolean signRequest, ConcurrentContentSigner signer,
      SecurityFactory securityFactory) {
    this.signer = ParamUtil.requireNonNull("signer", signer);
    if (signer.getCertificate() == null) {
      throw new IllegalArgumentException("requestor without certificate is not allowed");
    }

    X500Name x500Name = X500Name.getInstance(signer.getCertificate().getSubjectX500Principal()
        .getEncoded());
    this.name = new GeneralName(x500Name);
    this.signRequest = signRequest;
  }

  @Override
  public GeneralName getName() {
    return name;
  }

  ConcurrentContentSigner getSigner() {
    return signer;
  }

  @Override
  public boolean signRequest() {
    return signRequest;
  }
}
