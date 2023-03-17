// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.xipki.util.Args;
import org.xipki.util.exception.ObjectCreationException;

import java.security.InvalidKeyException;
import java.security.PublicKey;

/**
 * Abstract implementation of {@link SecurityFactory}. It provides some common
 * methods.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public abstract class AbstractSecurityFactory implements SecurityFactory {

  @Override
  public ConcurrentContentSigner createSigner(String type, SignerConf conf, X509Cert cert)
      throws ObjectCreationException {
    X509Cert[] certs = (cert == null) ? null : new X509Cert[]{cert};
    return createSigner(type, conf, certs);
  }

  @Override
  public ContentVerifierProvider getContentVerifierProvider(X509Cert cert)
      throws InvalidKeyException {
    Args.notNull(cert, "cert");
    return getContentVerifierProvider(cert.getPublicKey());
  }

  @Override
  public ContentVerifierProvider getContentVerifierProvider(PublicKey publicKey)
      throws InvalidKeyException {
    return getContentVerifierProvider(publicKey, null);
  }

  @Override
  public boolean verifyPop(CertificationRequest csr, AlgorithmValidator algoValidator) {
    return verifyPop(new PKCS10CertificationRequest(csr), algoValidator, null);
  }

  @Override
  public boolean verifyPop(CertificationRequest csr, AlgorithmValidator algoValidator,
      DHSigStaticKeyCertPair ownerKeyAndCert) {
    return verifyPop(new PKCS10CertificationRequest(csr), algoValidator, ownerKeyAndCert);
  }

  @Override
  public boolean verifyPop(PKCS10CertificationRequest csr, AlgorithmValidator algoValidator) {
    return verifyPop(csr, algoValidator, null);
  }

}
