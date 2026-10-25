// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp.client.internal;

import org.xipki.pkix.asn1.x500.X500Name;
import org.xipki.pkix.asn1.x509.GeneralName;
import org.xipki.codec.util.Args;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.verify.AlgorithmValidator;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 * CMP responder.
 *
 * @author Lijun Liao (xipki)
 */
abstract class Responder {

  private final GeneralName name;

  private Responder(X500Name name) {
    this.name = GeneralName.ofDirectoryName(Args.notNull(name, "name"));
  }

  GeneralName name() {
    return name;
  }

  static class PbmMacCmpResponder extends Responder {

    private final List<HashAlgo> owfAlgos;

    private final List<SignAlgo> macAlgos;

    PbmMacCmpResponder(List<String> owfs, List<String> macs) throws NoSuchAlgorithmException {
      super(new X500Name());

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
      super(Args.notNull(cert, "cert").subject());
      this.cert = cert;
      this.sigAlgoValidator = Args.notNull(sigAlgoValidator, "sigAlgoValidator");
    }

    X509Cert getCert() {
      return cert;
    }

    AlgorithmValidator getSigAlgoValidator() {
      return sigAlgoValidator;
    }

  } // class SignatureCmpResponder

}
