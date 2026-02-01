// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp.client;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.xipki.security.X509Cert;
import org.xipki.security.cmp.PkiStatusInfo;
import org.xipki.util.codec.Args;

import java.util.Map;
import java.util.Set;

/**
 * Certificate enrollment result.
 *
 * @author Lijun Liao (xipki)
 */

public class EnrollCertResult {

  public static class CertifiedKeyPairOrError {

    private final X509Cert certificate;

    private final PrivateKeyInfo privateKeyInfo;

    private final PkiStatusInfo error;

    public CertifiedKeyPairOrError(X509Cert certificate,
                                   PrivateKeyInfo privateKeyInfo) {
      this.certificate = Args.notNull(certificate, "certificate");
      this.privateKeyInfo = privateKeyInfo;
      this.error = null;
    }

    public CertifiedKeyPairOrError(PkiStatusInfo error) {
      this.certificate = null;
      this.privateKeyInfo = null;
      this.error = Args.notNull(error, "error");
    }

    public X509Cert certificate() {
      return certificate;
    }

    public PrivateKeyInfo privateKeyInfo() {
      return privateKeyInfo;
    }

    public PkiStatusInfo error() {
      return error;
    }

  } // class CertifiedKeyPairOrError

  private final X509Cert[] caCertChain;

  private final Map<String, CertifiedKeyPairOrError> certsOrErrors;

  public EnrollCertResult(X509Cert[] caCertChain,
                          Map<String, CertifiedKeyPairOrError> certsOrErrors) {
    this.certsOrErrors = Args.notEmpty(certsOrErrors, "certsOrErrors");
    this.caCertChain = caCertChain;
  }

  public X509Cert[] caCertChain() {
    return caCertChain;
  }

  public CertifiedKeyPairOrError getCertOrError(String id) {
    return certsOrErrors.get(Args.notBlank(id, "id"));
  }

  public Set<String> allIds() {
    return certsOrErrors.keySet();
  }

}
