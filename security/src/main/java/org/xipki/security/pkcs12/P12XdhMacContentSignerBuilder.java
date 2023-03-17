// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs12;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.RuntimeOperatorException;
import org.xipki.security.*;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.xipki.util.Args.notNull;
import static org.xipki.util.Args.positive;

/**
 * Builder of PKCS#12 XDH (e.g. X25519, X448) MAC signer.
 *s
 * @author Lijun Liao (xipki)
 */

public class P12XdhMacContentSignerBuilder {

  private static class XdhMacContentSigner extends HmacContentSigner {

    private final byte[] prefix;

    private final int hashLen;

    private XdhMacContentSigner(SignAlgo signAlgo, SecretKey signingKey, IssuerAndSerialNumber peerIssuerAndSerial)
        throws XiSecurityException {
      super(signAlgo, signingKey);
      this.hashLen = signAlgo.getHashAlgo().getLength();

      ASN1EncodableVector vec = new ASN1EncodableVector();
      if (peerIssuerAndSerial != null) {
        vec.add(peerIssuerAndSerial);
      }

      vec.add(new DEROctetString(new byte[hashLen]));

      byte[] encodedSig;
      try {
        encodedSig = new DERSequence(vec).getEncoded();
      } catch (IOException ex) {
        throw new XiSecurityException("exception initializing ContentSigner: " + ex.getMessage(), ex);
      }
      this.prefix = Arrays.copyOfRange(encodedSig, 0, encodedSig.length - hashLen);
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
      byte[] hashValue = super.getSignature();
      if (hashValue.length != hashLen) {
        throw new RuntimeOperatorException("exception obtaining signature: invalid signature length");
      }
      byte[] sigValue = new byte[prefix.length + hashLen];
      System.arraycopy(prefix, 0, sigValue, 0, prefix.length);
      System.arraycopy(hashValue, 0, sigValue, prefix.length, hashLen);
      return sigValue;
    }

  } // class XdhMacContentSigner

  private SecretKey key;

  private SignAlgo algo;

  private IssuerAndSerialNumber peerIssuerAndSerial;

  private final PublicKey publicKey;

  private final X509Cert[] certificateChain;

  public P12XdhMacContentSignerBuilder(X509Cert peerCert, PrivateKey privateKey, PublicKey publicKey)
      throws XiSecurityException {
    notNull(privateKey, "privateKey");
    notNull(peerCert, "peerCert");
    this.publicKey = notNull(publicKey, "publicKey");
    this.certificateChain = null;
    init(privateKey, peerCert);
  }

  public P12XdhMacContentSignerBuilder(KeypairWithCert keypairWithCert, X509Cert peerCert)
      throws XiSecurityException {
    notNull(keypairWithCert, "keypairWithCert");
    notNull(peerCert, "peerCert");
    this.publicKey = keypairWithCert.getPublicKey();
    this.certificateChain = keypairWithCert.getCertificateChain();

    init(keypairWithCert.getKey(), peerCert);
  }

  private void init(PrivateKey privateKey, X509Cert peerCert) throws XiSecurityException {
    String algorithm = privateKey.getAlgorithm();
    if (EdECConstants.X25519.equalsIgnoreCase(algorithm)) {
      this.algo = SignAlgo.DHPOP_X25519;
    } else if (EdECConstants.X448.equalsIgnoreCase(algorithm)) {
      this.algo = SignAlgo.DHPOP_X448;
    } else {
      throw new IllegalArgumentException("unsupported key.getAlgorithm(): " + algorithm);
    }

    PublicKey peerPubKey = peerCert.getPublicKey();
    if (!algorithm.equalsIgnoreCase(peerPubKey.getAlgorithm())) {
      throw new IllegalArgumentException("peerCert and key does not match");
    }

    // compute the secret key
    byte[] zz;
    try {
      KeyAgreement keyAgreement = KeyAgreement.getInstance(algorithm, "BC");
      keyAgreement.init(privateKey);
      keyAgreement.doPhase(peerPubKey, true);
      zz = keyAgreement.generateSecret();
    } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | IllegalStateException ex) {
      throw new XiSecurityException("KeyChange error", ex);
    }

    // as defined in RFC 6955, raw hash algorithm is used as KDF

    byte[] leadingInfo;
    byte[] trailingInfo;

    try {
      // LeadingInfo := Subject Distinguished Name from certificate
      leadingInfo = peerCert.getSubject().getEncoded();
      // TrailingInfo ::= Issuer Distinguished Name from certificate
      trailingInfo = peerCert.getIssuer().getEncoded();
    } catch (IOException ex) {
      throw new XiSecurityException("error encoding certificate", ex);
    }

    byte[] k = this.algo.getHashAlgo().hash(leadingInfo, zz, trailingInfo);
    this.key = new SecretKeySpec(k, algo.getJceName());
    this.peerIssuerAndSerial = new IssuerAndSerialNumber(
        X500Name.getInstance(trailingInfo), peerCert.getSerialNumber());
  } // method init

  public ConcurrentContentSigner createSigner(int parallelism) throws XiSecurityException {
    positive(parallelism, "parallelism");

    List<XiContentSigner> signers = new ArrayList<>(parallelism);

    for (int i = 0; i < parallelism; i++) {
      XiContentSigner signer = new XdhMacContentSigner(algo, key, peerIssuerAndSerial);
      signers.add(signer);
    }

    final boolean mac = true;
    DfltConcurrentContentSigner concurrentSigner;
    try {
      concurrentSigner = new DfltConcurrentContentSigner(mac, signers, key);
    } catch (NoSuchAlgorithmException ex) {
      throw new XiSecurityException(ex.getMessage(), ex);
    }
    concurrentSigner.setSha1DigestOfMacKey(HashAlgo.SHA1.hash(key.getEncoded()));

    if (certificateChain != null) {
      concurrentSigner.setCertificateChain(certificateChain);
    } else {
      concurrentSigner.setPublicKey(publicKey);
    }

    return concurrentSigner;
  } // method createSigner

}
