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
import org.xipki.pkcs11.TokenException;
import org.xipki.security.*;
import org.xipki.security.util.X509Util;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertPathBuilderException;
import java.security.interfaces.ECPublicKey;
import java.util.*;

import static org.xipki.pkcs11.PKCS11Constants.*;
import static org.xipki.util.Args.notNull;
import static org.xipki.util.Args.positive;

/**
 * Builder of {@link ConcurrentContentSigner} for PKCS#11 token.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11ContentSignerBuilder {

  private final X509Cert[] certificateChain;

  private final SecurityFactory securityFactory;

  private final P11Identity identity;

  public P11ContentSignerBuilder(SecurityFactory securityFactory, P11Identity identity, X509Cert[] certificateChain)
      throws XiSecurityException, TokenException {
    this.securityFactory = notNull(securityFactory, "securityFactory");
    this.identity = notNull(identity, "identity");

    Set<X509Cert> caCerts = new HashSet<>();

    X509Cert cert;
    if (certificateChain != null && certificateChain.length > 0) {
      final int n = certificateChain.length;
      cert = certificateChain[0];
      if (n > 1) {
        caCerts.addAll(Arrays.asList(certificateChain).subList(1, n));
      }
    } else {
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
      throws XiSecurityException, TokenException {
    positive(parallelism, "parallelism");

    List<XiContentSigner> signers = new ArrayList<>(parallelism);

    long keyType = identity.getKeyType();

    Boolean isSm2p256v1 = null;
    BigInteger wx = null;
    BigInteger wy = null;

    for (int i = 0; i < parallelism; i++) {
      XiContentSigner signer;
      if (keyType == CKK_RSA) {
        signer = createRSAContentSigner(signAlgo);
      } else if (keyType == CKK_EC || keyType == CKK_VENDOR_SM2) {
        if (i == 0) {
          isSm2p256v1 = (keyType == CKK_VENDOR_SM2) || GMObjectIdentifiers.sm2p256v1.equals(identity.getEcParams());

          if (isSm2p256v1) {
            PublicKey publicKey = (certificateChain != null)
                ? certificateChain[0].getPublicKey()
                : identity.getPublicKey();

            java.security.spec.ECPoint w = ((ECPublicKey) publicKey).getW();
            wx = w.getAffineX();
            wy = w.getAffineY();
          }
        }

        signer = isSm2p256v1  ? createSM2ContentSigner(signAlgo, GMObjectIdentifiers.sm2p256v1, wx, wy)
                              : createECContentSigner(signAlgo);
      } else if (keyType == CKK_DSA) {
        signer = createDSAContentSigner(signAlgo);
      } else if (keyType == CKK_EC_EDWARDS) {
        signer = createEdDSAContentSigner(signAlgo);
      } else {
        throw new XiSecurityException("unsupported key type " + ckkCodeToName(keyType));
      }
      signers.add(signer);
    } // end for

    final boolean mac = false;
    DfltConcurrentContentSigner concurrentSigner;
    try {
      concurrentSigner = new DfltConcurrentContentSigner(mac, signers);
    } catch (NoSuchAlgorithmException ex) {
      throw new XiSecurityException(ex.getMessage(), ex);
    }

    if (certificateChain != null) {
      concurrentSigner.setCertificateChain(certificateChain);
    } else {
      concurrentSigner.setPublicKey(identity.getPublicKey());
    }

    return concurrentSigner;
  } // method createSigner

  private XiContentSigner createRSAContentSigner(SignAlgo signAlgo) throws XiSecurityException {
    return  signAlgo.isRSAPSSSigAlgo()
      ? new P11ContentSigner.RSAPSS(identity, signAlgo, securityFactory.getRandom4Sign())
      : new P11ContentSigner.RSA(identity, signAlgo);
  }

  private XiContentSigner createECContentSigner(SignAlgo signAlgo) throws XiSecurityException {
    return new P11ContentSigner.ECDSA(identity, signAlgo);
  }

  private XiContentSigner createSM2ContentSigner(
      SignAlgo signAlgo, ASN1ObjectIdentifier curveOid, BigInteger pubPointX, BigInteger pubPointy)
      throws XiSecurityException {
    return new P11ContentSigner.SM2(identity, signAlgo, curveOid, pubPointX, pubPointy);
  }

  private XiContentSigner createDSAContentSigner(SignAlgo signAlgo) throws XiSecurityException {
    return new P11ContentSigner.DSA(identity, signAlgo);
  }

  private XiContentSigner createEdDSAContentSigner(SignAlgo signAlgo) throws XiSecurityException {
    return new P11ContentSigner.EdDSA(identity, signAlgo);
  }

}
