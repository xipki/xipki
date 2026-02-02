// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs12;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.ContentSigner;
import org.xipki.security.OIDs;
import org.xipki.security.SignAlgo;
import org.xipki.security.composite.kem.CompositeMLKEMPublicKey;
import org.xipki.security.encap.KEMUtil;
import org.xipki.security.encap.KemEncapKey;
import org.xipki.security.encap.KemEncapsulation;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.sign.ConcurrentSigner;
import org.xipki.security.sign.DfltConcurrentSigner;
import org.xipki.security.sign.Signer;
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

  private final byte[] encodedX509SigAlgId;

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
        publicKeyData = keypairWithCert.x509CertChain()[0]
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
      this.encodedX509SigAlgId = sigAlgId.getEncoded();
    } catch (IOException ex) {
      throw new XiSecurityException("error encoding AlgorithmIdentifier", ex);
    }
  }

  public ConcurrentSigner createSigner(SignAlgo signAlgo, int parallelism)
      throws XiSecurityException {
    Args.notNull(signAlgo, "signAlgo");
    if (signAlgo != SignAlgo.KEM_HMAC_SHA256) {
      throw new XiSecurityException("unknown signAlgo " + signAlgo);
    }

    List<Signer> signers = new ArrayList<>(
        Args.positive(parallelism, "parallelism"));

    for (int i = 0; i < parallelism; i++) {
      HmacSigner macSigner = new HmacSigner(SignAlgo.HMAC_SHA256, macKey);
      Signer signer = new MyX509Signer(macSigner);
      signers.add(signer);
    }

    final boolean mac = true;
    DfltConcurrentSigner concurrentSigner;
    try {
      concurrentSigner = new DfltConcurrentSigner(
          mac, signers, keypairWithCert.getKey());
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

  private class MyX509Signer implements Signer {

    private final HmacSigner macSigner;

    public MyX509Signer(HmacSigner macSigner) {
      this.macSigner = macSigner;
    }

    @Override
    public ContentSigner x509Signer() {
      return new ContentSigner() {
        @Override
        public AlgorithmIdentifier getAlgorithmIdentifier() {
          return sigAlgId;
        }

        @Override
        public OutputStream getOutputStream() {
          return macSigner.x509Signer().getOutputStream();
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
          byte[] rawSignature = macSigner.x509Signer().getSignature();
          try {
            return new DERSequence(new ASN1Encodable[]{utf8Id,
                new DEROctetString(rawSignature)}).getEncoded();
          } catch (IOException e) {
            throw new IllegalStateException("error encoding the DER signature");
          }
        }
      };
    }

    @Override
    public byte[] getEncodedX509AlgId() {
      return encodedX509SigAlgId.clone();
    }
  }

}
