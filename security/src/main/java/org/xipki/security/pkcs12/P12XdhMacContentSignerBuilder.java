/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

package org.xipki.security.pkcs12;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.RuntimeOperatorException;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.DfltConcurrentContentSigner;
import org.xipki.security.EdECConstants;
import org.xipki.security.HashAlgo;
import org.xipki.security.ObjectIdentifiers.Xipki;
import org.xipki.security.XiContentSigner;
import org.xipki.security.XiSecurityException;
import org.xipki.util.Args;

/**
 * TODO.
 * @author Lijun Liao
 */

public class P12XdhMacContentSignerBuilder {

  private static class XdhMacContentSigner extends HmacContentSigner {

    private final byte[] prefix;

    private final int hashLen;

    private XdhMacContentSigner(HashAlgo hashAlgo, AlgorithmIdentifier algorithmIdentifier,
        SecretKey signingKey, IssuerAndSerialNumber peerIssuerAndSerial)
            throws XiSecurityException {
      super(hashAlgo, algorithmIdentifier, signingKey);
      this.hashLen = hashAlgo.getLength();

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
        throw new RuntimeOperatorException(
            "exception obtaining signature: invalid signature length");
      }
      byte[] sigValue = new byte[prefix.length + hashLen];
      System.arraycopy(prefix, 0, sigValue, 0, prefix.length);
      System.arraycopy(hashValue, 0, sigValue, prefix.length, hashLen);
      return sigValue;
    }

  }

  private SecretKey key;

  private AlgorithmIdentifier algId;

  private HashAlgo hash;

  private IssuerAndSerialNumber peerIssuerAndSerial;

  private final PublicKey publicKey;

  private final X509Certificate[] certificateChain;

  public P12XdhMacContentSignerBuilder(X509Certificate peerCert,
      PrivateKey privateKey, PublicKey publicKey) throws XiSecurityException {
    Args.notNull(privateKey, "privateKey");
    Args.notNull(peerCert, "peerCert");
    this.publicKey = Args.notNull(publicKey, "publicKey");
    this.certificateChain = null;
    init(privateKey, peerCert);
  }

  public P12XdhMacContentSignerBuilder(KeypairWithCert keypairWithCert, X509Certificate peerCert)
      throws XiSecurityException {
    Args.notNull(keypairWithCert, "keypairWithCert");
    Args.notNull(peerCert, "peerCert");
    this.publicKey = keypairWithCert.getPublicKey();
    this.certificateChain = keypairWithCert.getCertificateChain();

    init(keypairWithCert.getKey(), peerCert);
  }

  private void init(PrivateKey privateKey, X509Certificate peerCert) throws XiSecurityException {
    String algorithm = privateKey.getAlgorithm();
    if (EdECConstants.ALG_X25519.equalsIgnoreCase(algorithm)) {
      this.algId = new AlgorithmIdentifier(Xipki.id_alg_dhPop_x25519_sha256);
      this.hash = HashAlgo.SHA256;
    } else if (EdECConstants.ALG_X448.equalsIgnoreCase(algorithm)) {
      this.algId = new AlgorithmIdentifier(Xipki.id_alg_dhPop_x448_sha512);
      this.hash = HashAlgo.SHA512;
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
    } catch (NoSuchAlgorithmException | NoSuchProviderException
        | InvalidKeyException | IllegalStateException ex) {
      throw new XiSecurityException("KeyChange error", ex);
    }

    // as defined in RFC 6955, raw hash algorithm is used as KDF

    // LeadingInfo := Subject Distinguished Name from certificate
    byte[] leadingInfo = peerCert.getSubjectX500Principal().getEncoded();
    // TrailingInfo ::= Issuer Distinguished Name from certificate
    byte[] trailingInfo = peerCert.getIssuerX500Principal().getEncoded();
    byte[] k = this.hash.hash(leadingInfo, zz, trailingInfo);
    this.key = new SecretKeySpec(k, "HMAC-" + this.hash.getName());
    this.peerIssuerAndSerial =
        new IssuerAndSerialNumber(X500Name.getInstance(trailingInfo), peerCert.getSerialNumber());
  }

  public ConcurrentContentSigner createSigner(int parallelism) throws XiSecurityException {
    Args.positive(parallelism, "parallelism");

    List<XiContentSigner> signers = new ArrayList<>(parallelism);

    for (int i = 0; i < parallelism; i++) {
      XiContentSigner signer =
          new XdhMacContentSigner(hash, algId, key, peerIssuerAndSerial);
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
  } // createSigner

}
