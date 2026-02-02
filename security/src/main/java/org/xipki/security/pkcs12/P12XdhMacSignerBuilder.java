// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs12;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.RuntimeOperatorException;
import org.xipki.security.HashAlgo;
import org.xipki.security.SignAlgo;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.pkix.X509Cert;
import org.xipki.security.sign.ConcurrentSigner;
import org.xipki.security.sign.DfltConcurrentSigner;
import org.xipki.security.sign.Signer;
import org.xipki.security.util.EcCurveEnum;
import org.xipki.util.codec.Args;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Builder of PKCS#12 XDH (e.g. X25519, X448) MAC signer.
 *s
 * @author Lijun Liao (xipki)
 */
public class P12XdhMacSignerBuilder {

  private static class XdhMacContentSigner extends HmacSigner {

    private final byte[] prefix;

    private final int hashLen;

    private final ContentSigner x509Signer;

    private XdhMacContentSigner(SignAlgo signAlgo, SecretKey signingKey,
                                IssuerAndSerialNumber peerIssuerAndSerial)
        throws XiSecurityException {
      super(signAlgo, signingKey);
      this.hashLen = signAlgo.hashAlgo().length();

      ASN1EncodableVector vec = new ASN1EncodableVector();
      if (peerIssuerAndSerial != null) {
        vec.add(peerIssuerAndSerial);
      }

      vec.add(new DEROctetString(new byte[hashLen]));

      byte[] encodedSig;
      try {
        encodedSig = new DERSequence(vec).getEncoded();
      } catch (IOException ex) {
        throw new XiSecurityException(
            "exception initializing ContentSigner: " + ex.getMessage(), ex);
      }
      this.prefix = Arrays.copyOfRange(encodedSig, 0,
          encodedSig.length - hashLen);

      final ContentSigner superX509Signer = super.x509Signer();

      this.x509Signer = new ContentSigner() {
        @Override
        public AlgorithmIdentifier getAlgorithmIdentifier() {
          return superX509Signer.getAlgorithmIdentifier();
        }

        @Override
        public OutputStream getOutputStream() {
          return superX509Signer.getOutputStream();
        }

        /**
         * Signature has the following format.
         * <pre>
         * DhSigStatic ::= SEQUENCE {
         *   issuerAndSerial IssuerAndSerialNumber OPTIONAL,
         *   hashValue       MessageDigest
         * }
         *
         * MessageDigest ::= OCTET STRING
         * </pre>
         */
        @Override
        public byte[] getSignature() {
          byte[] hashValue = superX509Signer.getSignature();
          if (hashValue.length != hashLen) {
            throw new RuntimeOperatorException(
                "exception obtaining signature: invalid signature length");
          }
          byte[] sigValue = new byte[prefix.length + hashLen];
          System.arraycopy(prefix, 0, sigValue, 0, prefix.length);
          System.arraycopy(hashValue, 0, sigValue, prefix.length, hashLen);
          return sigValue;
        }
      };
    }

    @Override
    public ContentSigner x509Signer() {
      return this.x509Signer;
    }

  } // class XdhMacContentSigner

  private SecretKey key;

  private SignAlgo algo;

  private IssuerAndSerialNumber peerIssuerAndSerial;

  private final PublicKey publicKey;

  private final X509Cert[] certificateChain;

  public P12XdhMacSignerBuilder(
      X509Cert peerCert, PrivateKey privateKey, PublicKey publicKey)
      throws XiSecurityException {
    this.publicKey = Args.notNull(publicKey, "publicKey");
    this.certificateChain = null;
    init(Args.notNull(privateKey, "privateKey"),
        Args.notNull(peerCert, "peerCert"));
  }

  public P12XdhMacSignerBuilder(
      KeypairWithCert keypairWithCert, X509Cert peerCert)
      throws XiSecurityException {
    this.publicKey = Args.notNull(keypairWithCert, "keypairWithCert")
        .publicKey();

    this.certificateChain = keypairWithCert.x509CertChain();
    init(keypairWithCert.getKey(), Args.notNull(peerCert, "peerCert"));
  }

  private void init(PrivateKey privateKey, X509Cert peerCert)
      throws XiSecurityException {
    String algorithm = privateKey.getAlgorithm();
    EcCurveEnum curve = EcCurveEnum.ofAlias(algorithm);
    if (EcCurveEnum.X25519 == curve) {
      this.algo = SignAlgo.DHPOP_X25519;
    } else if (EcCurveEnum.X448 == curve) {
      this.algo = SignAlgo.DHPOP_X448;
    } else {
      throw new IllegalArgumentException(
          "unsupported key.getAlgorithm(): " + algorithm);
    }

    PublicKey peerPubKey = peerCert.publicKey();
    if (!algorithm.equals(peerPubKey.getAlgorithm())) {
      throw new IllegalArgumentException("peerCert and key does not match");
    }

    // compute the secret key
    byte[] zz;
    try {
      KeyAgreement keyAgreement = KeyAgreement.getInstance(algorithm, "BC");
      keyAgreement.init(privateKey);
      keyAgreement.doPhase(peerPubKey, true);
      zz = keyAgreement.generateSecret();
    } catch (GeneralSecurityException | RuntimeException ex) {
      throw new XiSecurityException("KeyChange error", ex);
    }

    // as defined in RFC 6955, raw hash algorithm is used as KDF

    byte[] leadingInfo;
    byte[] trailingInfo;

    try {
      // LeadingInfo := Subject Distinguished Name from certificate
      leadingInfo = peerCert.subject().getEncoded();
      // TrailingInfo ::= Issuer Distinguished Name from certificate
      trailingInfo = peerCert.issuer().getEncoded();
    } catch (IOException ex) {
      throw new XiSecurityException("error encoding certificate", ex);
    }

    byte[] k = this.algo.hashAlgo().hash(leadingInfo, zz, trailingInfo);
    this.key = new SecretKeySpec(k, algo.jceName());
    this.peerIssuerAndSerial = new IssuerAndSerialNumber(
        X500Name.getInstance(trailingInfo), peerCert.serialNumber());
  } // method init

  public ConcurrentSigner createSigner(int parallelism)
      throws XiSecurityException {
    List<Signer> signers = new ArrayList<>(
        Args.positive(parallelism, "parallelism"));

    for (int i = 0; i < parallelism; i++) {
      Signer signer =
          new XdhMacContentSigner(algo, key, peerIssuerAndSerial);
      signers.add(signer);
    }

    final boolean mac = true;
    DfltConcurrentSigner concurrentSigner;
    try {
      concurrentSigner = new DfltConcurrentSigner(mac, signers, key);
    } catch (NoSuchAlgorithmException ex) {
      throw new XiSecurityException(ex.getMessage(), ex);
    }
    concurrentSigner.setSha1DigestOfMacKey(
        HashAlgo.SHA1.hash(key.getEncoded()));

    if (certificateChain != null) {
      concurrentSigner.setX509CertChain(certificateChain);
    } else {
      concurrentSigner.setPublicKey(publicKey);
    }

    return concurrentSigner;
  } // method createSigner

}
