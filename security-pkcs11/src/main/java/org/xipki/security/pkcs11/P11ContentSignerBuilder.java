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

package org.xipki.security.pkcs11;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.DfltConcurrentContentSigner;
import org.xipki.security.SecurityFactory;
import org.xipki.security.XiContentSigner;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.pkcs11.exception.P11TokenException;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.GMUtil;
import org.xipki.security.util.X509Util;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11ContentSignerBuilder {

  private final PublicKey publicKey;

  private final X509Certificate[] certificateChain;

  private final P11CryptService cryptService;

  private final SecurityFactory securityFactory;

  private final P11EntityIdentifier identityId;

  public P11ContentSignerBuilder(P11CryptService cryptService, SecurityFactory securityFactory,
      P11EntityIdentifier identityId, X509Certificate[] certificateChain)
      throws XiSecurityException, P11TokenException {
    this.cryptService = ParamUtil.requireNonNull("cryptService", cryptService);
    this.securityFactory = ParamUtil.requireNonNull("securityFactory", securityFactory);
    this.identityId = ParamUtil.requireNonNull("identityId", identityId);

    P11Identity identity = cryptService.getIdentity(identityId);
    X509Certificate signerCertInP11 = identity.getCertificate();
    PublicKey publicKeyInP11 = (signerCertInP11 != null) ? signerCertInP11.getPublicKey()
        : identity.getPublicKey();

    if (publicKeyInP11 == null) {
      throw new XiSecurityException("public key with " + identityId + " does not exist");
    }

    Set<Certificate> caCerts = new HashSet<>();

    X509Certificate cert;
    if (certificateChain != null && certificateChain.length > 0) {
      final int n = certificateChain.length;
      cert = certificateChain[0];
      if (n > 1) {
        for (int i = 1; i < n; i++) {
          caCerts.add(certificateChain[i]);
        }
      }
      this.publicKey = cert.getPublicKey();
    } else {
      this.publicKey = publicKeyInP11;
      cert = signerCertInP11;
    }

    if (cert != null) {
      Certificate[] certsInKeystore = identity.certificateChain();
      if (certsInKeystore != null && certsInKeystore.length > 1) {
        for (int i = 1; i < certsInKeystore.length; i++) {
          caCerts.add(certsInKeystore[i]);
        }
      }

      this.certificateChain = X509Util.buildCertPath(cert, caCerts);
    } else {
      this.certificateChain = null;
    }
  } // constructor

  public ConcurrentContentSigner createSigner(AlgorithmIdentifier signatureAlgId,
      int parallelism) throws XiSecurityException, P11TokenException {
    ParamUtil.requireMin("parallelism", parallelism, 1);

    List<XiContentSigner> signers = new ArrayList<>(parallelism);

    Boolean isSm2p256v1 = null;
    for (int i = 0; i < parallelism; i++) {
      XiContentSigner signer;
      if (publicKey instanceof RSAPublicKey) {
        if (i == 0 && !AlgorithmUtil.isRSASigAlgId(signatureAlgId)) {
          throw new XiSecurityException(
              "the given algorithm is not a valid RSA signature algorithm '"
              + signatureAlgId.getAlgorithm().getId() + "'");
        }
        signer = createRSAContentSigner(signatureAlgId);
      } else if (publicKey instanceof ECPublicKey) {
        ECPublicKey ecKey = (ECPublicKey) publicKey;

        if (i == 0) {
          isSm2p256v1 = GMUtil.isSm2primev2Curve(ecKey.getParams().getCurve());
          if (isSm2p256v1) {
            if (!AlgorithmUtil.isSM2SigAlg(signatureAlgId)) {
              throw new XiSecurityException(
                "the given algorithm is not a valid SM2 signature algorithm '"
                + signatureAlgId.getAlgorithm().getId() + "'");
            }
          } else {
            if (!AlgorithmUtil.isECSigAlg(signatureAlgId)) {
              throw new XiSecurityException(
                "the given algorithm is not a valid EC signature algorithm '"
                + signatureAlgId.getAlgorithm().getId() + "'");
            }
          }
        }

        if (isSm2p256v1) {
          java.security.spec.ECPoint w = ecKey.getW();
          signer = createSM2ContentSigner(signatureAlgId, GMObjectIdentifiers.sm2p256v1,
              w.getAffineX(), w.getAffineY());
        } else {
          signer = createECContentSigner(signatureAlgId);
        }
      } else if (publicKey instanceof DSAPublicKey) {
        if (i == 0 && !AlgorithmUtil.isDSASigAlg(signatureAlgId)) {
          throw new XiSecurityException(
              "the given algorithm is not a valid DSA signature algorithm '"
              + signatureAlgId.getAlgorithm().getId() + "'");
        }
        signer = createDSAContentSigner(signatureAlgId);
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

  // CHECKSTYLE:SKIP
  private XiContentSigner createRSAContentSigner(AlgorithmIdentifier signatureAlgId)
      throws XiSecurityException, P11TokenException {
    if (PKCSObjectIdentifiers.id_RSASSA_PSS.equals(signatureAlgId.getAlgorithm())) {
      return new P11RSAPSSContentSigner(cryptService, identityId, signatureAlgId,
          securityFactory.getRandom4Sign());
    } else {
      return new P11RSAContentSigner(cryptService, identityId, signatureAlgId);
    }
  }

  // CHECKSTYLE:SKIP
  private XiContentSigner createECContentSigner(AlgorithmIdentifier signatureAlgId)
      throws XiSecurityException, P11TokenException {
    return new P11ECDSAContentSigner(cryptService, identityId, signatureAlgId,
        AlgorithmUtil.isDSAPlainSigAlg(signatureAlgId));
  }

  // CHECKSTYLE:SKIP
  private XiContentSigner createSM2ContentSigner(AlgorithmIdentifier signatureAlgId,
      ASN1ObjectIdentifier curveOid, BigInteger pubPointX, BigInteger pubPointy)
      throws XiSecurityException, P11TokenException {
    return new P11SM2ContentSigner(cryptService, identityId, signatureAlgId,
        curveOid, pubPointX, pubPointy);
  }

  // CHECKSTYLE:SKIP
  private XiContentSigner createDSAContentSigner(AlgorithmIdentifier signatureAlgId)
      throws XiSecurityException, P11TokenException {
    return new P11DSAContentSigner(cryptService, identityId, signatureAlgId,
        AlgorithmUtil.isDSAPlainSigAlg(signatureAlgId));
  }

}
