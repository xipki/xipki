// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.jce;

import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.DfltConcurrentContentSigner;
import org.xipki.security.SignAlgo;
import org.xipki.security.X509Cert;
import org.xipki.security.XiContentSigner;
import org.xipki.security.XiSecurityException;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.CertPathBuilderException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Builder of {@link ConcurrentContentSigner} for PKCS#11 token.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class JceSignerBuilder {

  private final PrivateKey privateKey;

  private final PublicKey publicKey;

  private final String providerName;

  private final Provider provider;

  private final X509Cert[] certificateChain;

  public JceSignerBuilder(PrivateKey privateKey, PublicKey publicKey, X509Cert[] certificateChain, String providerName)
      throws XiSecurityException {
    this(privateKey, publicKey, certificateChain, providerName, null);
  }

  public JceSignerBuilder(PrivateKey privateKey, PublicKey publicKey, X509Cert[] certificateChain, Provider provider)
      throws XiSecurityException {
    this(privateKey, publicKey, certificateChain, null, provider);
  }

  private JceSignerBuilder(PrivateKey privateKey, PublicKey publicKey, X509Cert[] certificateChain,
                           String providerName, Provider provider)
      throws XiSecurityException {
    this.privateKey = Args.notNull(privateKey, "privateKey");
    this.publicKey = Args.notNull(publicKey, "publicKey");
    this.providerName = providerName;
    this.provider = provider;

    X509Cert[] chain = null;
    X509Cert cert;
    if (certificateChain != null && certificateChain.length > 0) {
      final int n = certificateChain.length;
      cert = certificateChain[0];
      if (n > 1) {
        Set<X509Cert> caCerts = new HashSet<>(Arrays.asList(certificateChain).subList(1, n));

        try {
          chain = X509Util.buildCertPath(cert, caCerts);
        } catch (CertPathBuilderException ex) {
          throw new XiSecurityException(ex);
        }
      }
    }

    this.certificateChain = chain;
  } // constructor

  public ConcurrentContentSigner createSigner(SignAlgo signAlgo, int parallelism)
      throws XiSecurityException {
    List<XiContentSigner> signers = new ArrayList<>(Args.positive(parallelism, "parallelism"));

    for (int i = 0; i < parallelism; i++) {
      XiContentSigner signer = new JceSigner(privateKey, signAlgo, providerName, provider);
      signers.add(signer);
    }

    DfltConcurrentContentSigner concurrentSigner;
    try {
      concurrentSigner = new DfltConcurrentContentSigner(false, signers, privateKey);
    } catch (NoSuchAlgorithmException ex) {
      throw new XiSecurityException(ex.getMessage(), ex);
    }

    if (certificateChain != null) {
      concurrentSigner.setCertificateChain(certificateChain);
    } else {
      concurrentSigner.setPublicKey(publicKey);
    }

    return concurrentSigner;
  } // method createSigner

}
