// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.sign;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.security.KeySpec;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignAlgo;
import org.xipki.security.encap.KemEncapKey;
import org.xipki.security.exception.XiSecurityException;

import java.security.NoSuchAlgorithmException;

/**
 * @author Lijun Liao (xipki)
 */
public interface CreateSignerCallback {

  CreateSignerCallback DEFAULT = new DefaultCallback();

  KemEncapKey generateKemEncapKey(SecurityFactory securityFactory,
                                  SubjectPublicKeyInfo publicKeyInfo)
      throws XiSecurityException;

  SignAlgo getSignAlgo(KeySpec keyspec, SignAlgoMode mode);

  class DefaultCallback implements CreateSignerCallback {

    private DefaultCallback() {
    }

    @Override
    public KemEncapKey generateKemEncapKey(
        SecurityFactory securityFactory, SubjectPublicKeyInfo publicKeyInfo)
        throws XiSecurityException {
      return securityFactory.csrControl().generateKemEncapKey(
          publicKeyInfo, securityFactory.random4Sign());
    }

    @Override
    public SignAlgo getSignAlgo(KeySpec keyspec, SignAlgoMode mode) {
      switch (keyspec) {
        case RSA2048:
        case RSA3072:
        case RSA4096:
          return (mode == SignAlgoMode.RSAPKCS1)
              ? SignAlgo.RSA_SHA256 : SignAlgo.RSAPSS_SHA256;
        case SECP256R1:
        case BRAINPOOLP256R1:
        case FRP256V1:
          return SignAlgo.ECDSA_SHA256;
        case SECP384R1:
        case BRAINPOOLP384R1:
          return SignAlgo.ECDSA_SHA384;
        case SECP521R1:
        case BRAINPOOLP512R1:
          return SignAlgo.ECDSA_SHA512;
        case SM2P256V1:
          return SignAlgo.SM2_SM3;
        case ED25519:
          return SignAlgo.ED25519;
        case ED448:
          return SignAlgo.ED448;
        case MLDSA44:
          return SignAlgo.MLDSA44;
        case MLDSA65:
          return SignAlgo.MLDSA65;
        case MLDSA87:
          return SignAlgo.MLDSA87;
        case X25519:
          return SignAlgo.DHPOP_X25519;
        case X448:
          return SignAlgo.DHPOP_X448;
      }

      if (keyspec.isCompositeMLDSA()) {
        try {
          return SignAlgo.getInstance(
              keyspec.algorithmIdentifier());
        } catch (NoSuchAlgorithmException e) {
          return null;
        }
      } else if (keyspec.isMlkem() || keyspec.isCompositeMLKEM()) {
        return SignAlgo.KEM_HMAC_SHA256;
      }

      return null;
    }
  }

}
