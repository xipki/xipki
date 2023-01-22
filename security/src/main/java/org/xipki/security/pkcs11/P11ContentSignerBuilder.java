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

package org.xipki.security.pkcs11;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.jcajce.interfaces.EdDSAKey;
import org.xipki.security.*;
import org.xipki.security.util.GMUtil;
import org.xipki.security.util.X509Util;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertPathBuilderException;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

import static org.xipki.util.Args.notNull;
import static org.xipki.util.Args.positive;

/**
 * Builder of {@link ConcurrentContentSigner} for PKCS#11 token.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11ContentSignerBuilder {

  private final PublicKey publicKey;

  private final X509Cert[] certificateChain;

  private final P11CryptService cryptService;

  private final SecurityFactory securityFactory;

  private final P11IdentityId identityId;

  public P11ContentSignerBuilder(P11CryptService cryptService, SecurityFactory securityFactory,
                                 P11IdentityId identityId, X509Cert[] certificateChain)
      throws XiSecurityException, P11TokenException {
    this.cryptService = notNull(cryptService, "cryptService");
    this.securityFactory = notNull(securityFactory, "securityFactory");
    this.identityId = notNull(identityId, "identityId");

    P11Identity identity = cryptService.getIdentity(identityId);
    PublicKey publicKeyInP11 = identity.getPublicKey();

    if (publicKeyInP11 == null) {
      throw new XiSecurityException("public key with " + identityId + " does not exist");
    }

    Set<X509Cert> caCerts = new HashSet<>();

    X509Cert cert;
    if (certificateChain != null && certificateChain.length > 0) {
      final int n = certificateChain.length;
      cert = certificateChain[0];
      if (n > 1) {
        caCerts.addAll(Arrays.asList(certificateChain).subList(1, n));
      }
      this.publicKey = cert.getPublicKey();
    } else {
      this.publicKey = publicKeyInP11;
      cert = null;
    }

    if (cert != null) {
      try {
        this.certificateChain = X509Util.buildCertPath(cert, caCerts);
      } catch (CertPathBuilderException ex) {
        throw new XiSecurityException(ex);
      }
    } else {
      this.certificateChain = null;
    }
  } // constructor

  public ConcurrentContentSigner createSigner(SignAlgo signAlgo, int parallelism)
      throws XiSecurityException, P11TokenException {
    positive(parallelism, "parallelism");

    List<XiContentSigner> signers = new ArrayList<>(parallelism);

    Boolean isSm2p256v1 = null;
    for (int i = 0; i < parallelism; i++) {
      XiContentSigner signer;
      if (publicKey instanceof RSAPublicKey) {
        signer = createRSAContentSigner(signAlgo);
      } else if (publicKey instanceof ECPublicKey) {
        ECPublicKey ecKey = (ECPublicKey) publicKey;

        if (i == 0) {
          isSm2p256v1 = GMUtil.isSm2primev2Curve(ecKey.getParams().getCurve());
        }

        if (isSm2p256v1) {
          java.security.spec.ECPoint w = ecKey.getW();
          signer = createSM2ContentSigner(signAlgo, GMObjectIdentifiers.sm2p256v1, w.getAffineX(), w.getAffineY());
        } else {
          signer = createECContentSigner(signAlgo);
        }
      } else if (publicKey instanceof DSAPublicKey) {
        signer = createDSAContentSigner(signAlgo);
      } else if (publicKey instanceof EdDSAKey) {
        signer = createEdDSAContentSigner(signAlgo);
      } else {
        throw new XiSecurityException("unsupported key " + publicKey.getClass().getName());
      }
      signers.add(signer);
    } // end for

    final boolean mac = false;
    PrivateKey privateKey = new P11PrivateKey(cryptService, identityId);
    DfltConcurrentContentSigner concurrentSigner;
    try {
      concurrentSigner = new DfltConcurrentContentSigner(mac, signers, privateKey);
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

  private XiContentSigner createRSAContentSigner(SignAlgo signAlgo) throws XiSecurityException, P11TokenException {
    return  signAlgo.isRSAPSSSigAlgo()
      ? new P11ContentSigner.RSAPSS(cryptService, identityId, signAlgo, securityFactory.getRandom4Sign())
      : new P11ContentSigner.RSA(cryptService, identityId, signAlgo);
  }

  private XiContentSigner createECContentSigner(SignAlgo signAlgo) throws XiSecurityException, P11TokenException {
    return new P11ContentSigner.ECDSA(cryptService, identityId, signAlgo);
  }

  private XiContentSigner createSM2ContentSigner(
      SignAlgo signAlgo, ASN1ObjectIdentifier curveOid, BigInteger pubPointX, BigInteger pubPointy)
      throws XiSecurityException, P11TokenException {
    return new P11ContentSigner.SM2(cryptService, identityId, signAlgo, curveOid, pubPointX, pubPointy);
  }

  private XiContentSigner createDSAContentSigner(SignAlgo signAlgo) throws XiSecurityException, P11TokenException {
    return new P11ContentSigner.DSA(cryptService, identityId, signAlgo);
  }

  private XiContentSigner createEdDSAContentSigner(SignAlgo signAlgo) throws XiSecurityException, P11TokenException {
    return new P11ContentSigner.EdDSA(cryptService, identityId, signAlgo);
  }

}
