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

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.xipki.security.AlgorithmValidator;
import org.xipki.security.HashAlgo;
import org.xipki.security.SignAlgo;
import org.xipki.security.X509Cert;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import static org.xipki.util.Args.notNull;

/**
 * CMP responder.
 *
 * @author Lijun Liao
 * @since 2.1.0
 */

abstract class Responder {

  private final GeneralName name;

  private Responder(X500Name name) {
    this.name = new GeneralName(notNull(name, "name"));
  }

  GeneralName getName() {
    return name;
  }

  static class PbmMacCmpResponder extends Responder {

    private final List<HashAlgo> owfAlgos;

    private final List<SignAlgo> macAlgos;

    PbmMacCmpResponder(X500Name x500Name, List<String> owfs, List<String> macs)
        throws NoSuchAlgorithmException {
      super(x500Name);

      this.owfAlgos = new ArrayList<>(owfs.size());

      for (String owf : owfs) {
        owfAlgos.add(HashAlgo.getInstance(owf));
      }

      this.macAlgos = new ArrayList<>(macs.size());
      for (String mac : macs) {
        macAlgos.add(SignAlgo.getInstance(mac));
      }

    }

    public boolean isPbmOwfPermitted(HashAlgo pbmOwf) {
      return owfAlgos.contains(pbmOwf);
    }

    public boolean isPbmMacPermitted(SignAlgo pbmMac) {
      return macAlgos.contains(pbmMac);
    }

  } // class PbmMacCmpResponder

  static class SignatureCmpResponder extends Responder {

    private final X509Cert cert;

    private final AlgorithmValidator sigAlgoValidator;

    SignatureCmpResponder(X509Cert cert, AlgorithmValidator sigAlgoValidator) {
      super(notNull(cert, "cert").getSubject());
      this.cert = cert;
      this.sigAlgoValidator = notNull(sigAlgoValidator, "sigAlgoValidator");
    }

    X509Cert getCert() {
      return cert;
    }

    AlgorithmValidator getSigAlgoValidator() {
      return sigAlgoValidator;
    }

  } // class SignatureCmpResponder

}
