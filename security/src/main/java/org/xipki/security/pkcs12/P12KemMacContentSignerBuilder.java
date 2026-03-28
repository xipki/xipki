// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs12;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.security.SignAlgo;
import org.xipki.security.composite.CompositeMLKEMPublicKey;
import org.xipki.security.encap.KEMUtil;
import org.xipki.security.encap.KemEncapKey;
import org.xipki.security.encap.KemEncapsulation;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.sign.ConcurrentSigner;
import org.xipki.security.sign.DfltConcurrentSigner;
import org.xipki.security.sign.KemHmacSigner;
import org.xipki.security.sign.Signer;
import org.xipki.security.util.Asn1Util;
import org.xipki.util.codec.Args;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

/**
 * P12 Kem Mac Content Signer Builder.
 *
 * @author Lijun Liao (xipki)
 */
public class P12KemMacContentSignerBuilder {

  private final KeypairWithCert keypairWithCert;

  private final SecretKey macKey;

  private final String id;

  public P12KemMacContentSignerBuilder(KeypairWithCert keypairWithCert, KemEncapKey encapKey)
      throws XiSecurityException {
    this.keypairWithCert = Args.notNull(keypairWithCert, "keypairWithCert");
    Args.notNull(encapKey, "encapKey");

    // decrypt the kemCiphertext
    byte algCode = encapKey.encapulation().alg();
    byte[] macKeyValue;
    if (algCode == KemEncapsulation.ALG_KMAC_MLKEM_HMAC) {
      macKeyValue = KEMUtil.mlkemDecryptSecret(
          keypairWithCert.getKey(), encapKey.encapulation());
    } else if (algCode == KemEncapsulation.ALG_KMAC_COMPOSITE_MLKEM_HMAC) {
      PublicKey publicKey = keypairWithCert.publicKey();
      byte[] publicKeyData;
      if (publicKey instanceof CompositeMLKEMPublicKey) {
        publicKeyData = ((CompositeMLKEMPublicKey) publicKey).keyValue();
      } else if (publicKey != null) {
        publicKeyData = Asn1Util.getPublicKeyData(
            SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
      } else {
        publicKeyData = Asn1Util.getPublicKeyData(
                          keypairWithCert.x509CertChain()[0].subjectPublicKeyInfo());
      }

      macKeyValue = KEMUtil.compositeMlKemDecryptSecret(
                      keypairWithCert.getKey(), publicKeyData, encapKey.encapulation());
    } else {
      throw new XiSecurityException("unknown wrap mechanism " + algCode);
    }

    this.macKey = new SecretKeySpec(macKeyValue, "HMAC-SHA256");
    this.id = encapKey.id();
  }

  public ConcurrentSigner createSigner(SignAlgo signAlgo, int parallelism)
      throws XiSecurityException {
    Args.notNull(signAlgo, "signAlgo");
    if (signAlgo != SignAlgo.KEM_HMAC_SHA256) {
      throw new XiSecurityException("unknown signAlgo " + signAlgo);
    }

    List<Signer> signers = new ArrayList<>(Args.positive(parallelism, "parallelism"));
    for (int i = 0; i < parallelism; i++) {
      signers.add(new KemHmacSigner(this.id, macKey));
    }

    final boolean mac = true;
    DfltConcurrentSigner concurrentSigner;
    try {
      concurrentSigner = new DfltConcurrentSigner(mac, signers, keypairWithCert.getKey());
    } catch (NoSuchAlgorithmException ex) {
      throw new XiSecurityException(ex.getMessage(), ex);
    }

    if (keypairWithCert.x509CertChain() != null) {
      concurrentSigner.setX509CertChain(keypairWithCert.x509CertChain());
    }

    return concurrentSigner;
  } // method createSigner

  public PrivateKey getKey() {
    return keypairWithCert.getKey();
  }

}
