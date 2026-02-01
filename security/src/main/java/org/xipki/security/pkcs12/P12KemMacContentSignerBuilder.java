// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs12;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.DfltConcurrentContentSigner;
import org.xipki.security.OIDs;
import org.xipki.security.SignAlgo;
import org.xipki.security.XiContentSigner;
import org.xipki.security.bc.compositekem.CompositeMLKEMPublicKey;
import org.xipki.security.encap.KEMUtil;
import org.xipki.security.encap.KemEncapKey;
import org.xipki.security.encap.KemEncapsulation;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.util.codec.Args;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

/**
 * Builder of PKCS#12 KEM MAC signers.
 *
 * @author Lijun Liao (xipki)
 */
public class P12KemMacContentSignerBuilder {

  private final KeypairWithCert keypairWithCert;

  private final SecretKey macKey;

  private final DERUTF8String utf8Id;

  private final AlgorithmIdentifier sigAlgId;

  private final byte[] encodedSigAlgId;

  public P12KemMacContentSignerBuilder(
      KeypairWithCert keypairWithCert, KemEncapKey encapKey)
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
        publicKeyData = SubjectPublicKeyInfo.getInstance(
            publicKey.getEncoded()).getPublicKeyData().getOctets();
      } else {
        publicKeyData = keypairWithCert.certificateChain()[0]
            .subjectPublicKeyInfo().getPublicKeyData().getOctets();
      }

      macKeyValue = KEMUtil.compositeMlKemDecryptSecret(
        keypairWithCert.getKey(), publicKeyData,
        encapKey.encapulation());
    } else {
      throw new XiSecurityException("unknown wrap mechanism " + algCode);
    }

    this.macKey = new SecretKeySpec(macKeyValue, "HMAC-SHA256");
    this.utf8Id = new DERUTF8String(encapKey.id());

    try {
      this.sigAlgId = new AlgorithmIdentifier(
          OIDs.Xipki.id_alg_KEM_HMAC_SHA256);
      this.encodedSigAlgId = sigAlgId.getEncoded();
    } catch (IOException ex) {
      throw new XiSecurityException("error encoding AlgorithmIdentifier", ex);
    }
  }

  public ConcurrentContentSigner createSigner(
      SignAlgo signAlgo, int parallelism) throws XiSecurityException {
    Args.notNull(signAlgo, "signAlgo");
    if (signAlgo != SignAlgo.KEM_HMAC_SHA256) {
      throw new XiSecurityException("unknown signAlgo " + signAlgo);
    }

    List<XiContentSigner> signers = new ArrayList<>(
        Args.positive(parallelism, "parallelism"));

    for (int i = 0; i < parallelism; i++) {
      XiContentSigner signer = buildContentSigner();
      signers.add(signer);
    }

    final boolean mac = true;
    DfltConcurrentContentSigner concurrentSigner;
    try {
      concurrentSigner = new DfltConcurrentContentSigner(
          mac, signers, keypairWithCert.getKey());
    } catch (NoSuchAlgorithmException ex) {
      throw new XiSecurityException(ex.getMessage(), ex);
    }

    if (keypairWithCert.certificateChain() != null) {
      concurrentSigner.setCertificateChain(
          keypairWithCert.certificateChain());
    }

    return concurrentSigner;
  } // method createSigner

  private XiContentSigner buildContentSigner() throws XiSecurityException {

    HmacContentSigner macSigner =
        new HmacContentSigner(SignAlgo.HMAC_SHA256, macKey);

    return new XiContentSigner() {
      @Override
      public byte[] getEncodedAlgorithmIdentifier() {
        return encodedSigAlgId.clone();
      }

      @Override
      public AlgorithmIdentifier getAlgorithmIdentifier() {
        return sigAlgId;
      }

      @Override
      public OutputStream getOutputStream() {
        return macSigner.getOutputStream();
      }

      /**
       * X509 Signature Value
       * <pre>
       * SEQUENCE ::= {
       *   id         UTF8String,
       *   signature  OCTET STRING
       * }
       * </pre>
       * @return the encoded signature value.
       */
      @Override
      public byte[] getSignature() {
        byte[] rawSignature = macSigner.getSignature();
        try {
          return new DERSequence(new ASN1Encodable[]{utf8Id,
              new DEROctetString(rawSignature)}).getEncoded();
        } catch (IOException e) {
          throw new IllegalStateException("error encoding the DER signature");
        }
      }

    };
  }

  public PrivateKey getKey() {
    return keypairWithCert.getKey();
  }

}
