// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs12;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.interfaces.MLKEMPrivateKey;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.DfltConcurrentContentSigner;
import org.xipki.security.KemEncapKey;
import org.xipki.security.OIDs;
import org.xipki.security.SignAlgo;
import org.xipki.security.XiContentSigner;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.util.codec.Args;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;

/**
 * Builder of PKCS#12 KEM MAC signers.
 *
 * @author Lijun Liao (xipki)
 *
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
    if (keypairWithCert.getKey() instanceof MLKEMPrivateKey) {
      try {
        Cipher unwrapper = Cipher.getInstance("ML-KEM", "BC");
        KTSParameterSpec spec;
        if (encapKey.getAlg() == KemEncapKey.ALG_AES_KWP_256) {
          spec = new KTSParameterSpec.Builder("AES-KWP", 256)
              .withNoKdf().build();
        } else {
          throw new XiSecurityException(
              "unknown wrap mechanism " + encapKey.getAlg());
        }

        unwrapper.init(Cipher.UNWRAP_MODE, keypairWithCert.getKey(), spec);
        macKey = (SecretKey) unwrapper.unwrap(encapKey.getEncapKey(),
            "AES", Cipher.SECRET_KEY);

        utf8Id = new DERUTF8String(encapKey.getId());

        byte[] nonce = new byte[AESGmacContentSigner.nonceLen];
        int tagByteLen = AESGmacContentSigner.tagByteLen;
        GCMParameters params = new GCMParameters(nonce, tagByteLen);
        try {
          this.sigAlgId = new AlgorithmIdentifier(
              OIDs.Xipki.id_alg_sig_KEM_GMAC_256);
          this.encodedSigAlgId = sigAlgId.getEncoded();
        } catch (IOException ex) {
          throw new XiSecurityException("could not encode AlgorithmIdentifier",
              ex);
        }
      } catch (GeneralSecurityException ex) {
        throw new XiSecurityException("could not decrypt the kemCiphertext",
            ex);
      }
    } else {
      throw new XiSecurityException("unknown key");
    }
  }

  public ConcurrentContentSigner createSigner(
      SignAlgo signAlgo, int parallelism) throws XiSecurityException {
    Args.notNull(signAlgo, "signAlgo");
    if (signAlgo != SignAlgo.KEM_GMAC_256) {
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

    if (keypairWithCert.getCertificateChain() != null) {
      concurrentSigner.setCertificateChain(
          keypairWithCert.getCertificateChain());
    }

    return concurrentSigner;
  } // method createSigner

  private XiContentSigner buildContentSigner() throws XiSecurityException {

    AESGmacContentSigner macSigner =
        new AESGmacContentSigner(SignAlgo.GMAC_AES256, macKey);

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
       *   gcmParams  GCMParameters,
       *   signature  OCTET STRING
       * }
       * </pre>
       * @return the encoded signature value.
       */
      @Override
      public byte[] getSignature() {
        byte[] rawSignature = macSigner.getSignature();
        GCMParameters gcmParams = (GCMParameters)
            macSigner.getAlgorithmIdentifier().getParameters();
        try {
          return new DERSequence(new ASN1Encodable[]{utf8Id, gcmParams,
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
