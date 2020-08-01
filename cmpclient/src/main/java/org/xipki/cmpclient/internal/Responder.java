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

import static org.xipki.util.Args.notNull;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.xipki.security.AlgorithmValidator;
import org.xipki.security.HashAlgo;
import org.xipki.security.X509Cert;
import org.xipki.security.util.AlgorithmUtil;

/**
 * CMP responder.
 *
 * @author Lijun Liao
 * @since 2.1.0
 */

abstract class Responder {

  private final GeneralName name;

  protected Responder(GeneralName name) {
    this.name = notNull(name, "name");
  }

  protected Responder(X500Name name) {
    this.name = new GeneralName(notNull(name, "name"));
  }

  public GeneralName getName() {
    return name;
  }

  static class PbmMacCmpResponder extends Responder {

    private final List<ASN1ObjectIdentifier> owfAlgos;

    private final List<ASN1ObjectIdentifier> macAlgos;

    PbmMacCmpResponder(X500Name x500Name, List<String> owfs, List<String> macs) {
      super(x500Name);

      this.owfAlgos = new ArrayList<>(owfs.size());

      for (int i = 0; i < owfs.size(); i++) {
        String algo = owfs.get(i);
        HashAlgo ha;
        try {
          ha = HashAlgo.getNonNullInstance(algo);
        } catch (Exception ex) {
          throw new IllegalArgumentException("invalid owf " + algo, ex);
        }
        owfAlgos.add(ha.getOid());
      }

      this.macAlgos = new ArrayList<>(macs.size());
      for (int i = 0; i < macs.size(); i++) {
        String algo = macs.get(i);
        AlgorithmIdentifier algId;
        try {
          algId = AlgorithmUtil.getMacAlgId(algo);
        } catch (NoSuchAlgorithmException ex) {
          throw new IllegalArgumentException("invalid mac" + algo, ex);
        }
        macAlgos.add(algId.getAlgorithm());
      }

    }

    public boolean isPbmOwfPermitted(AlgorithmIdentifier pbmOwf) {
      ASN1ObjectIdentifier owfOid = pbmOwf.getAlgorithm();
      for (ASN1ObjectIdentifier oid : owfAlgos) {
        if (oid.equals(owfOid)) {
          return true;
        }
      }
      return false;
    }

    public boolean isPbmMacPermitted(AlgorithmIdentifier pbmMac) {
      ASN1ObjectIdentifier macOid = pbmMac.getAlgorithm();
      for (ASN1ObjectIdentifier oid : macAlgos) {
        if (oid.equals(macOid)) {
          return true;
        }
      }
      return false;
    }

  } // class PbmMacCmpResponder

  static class SignaturetCmpResponder extends Responder {

    private final X509Cert cert;

    private final AlgorithmValidator sigAlgoValidator;

    public SignaturetCmpResponder(X509Cert cert, AlgorithmValidator sigAlgoValidator) {
      super(notNull(cert, "cert").getSubject());
      this.cert = cert;
      this.sigAlgoValidator = notNull(sigAlgoValidator, "sigAlgoValidator");
    }

    public X509Cert getCert() {
      return cert;
    }

    public AlgorithmValidator getSigAlgoValidator() {
      return sigAlgoValidator;
    }

  } // class SignaturetCmpResponder

}
