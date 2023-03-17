// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.bc;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.crmf.DhSigStatic;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.xipki.security.DHSigStaticKeyCertPair;
import org.xipki.security.EdECConstants;
import org.xipki.security.HashAlgo;
import org.xipki.security.ObjectIdentifiers.Xipki;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.util.Arrays;

import static org.xipki.util.Args.notNull;

/**
 * {@link ContentVerifierProvider} for the algorithm X25519 static HMAC (XiPKI own
 * algorithm, based on RFC 6955).
 *
 * @author Lijun Liao (xipki)
 */

public class XiXDHContentVerifierProvider implements ContentVerifierProvider {

  private static class XDHContentVerifier implements ContentVerifier {

    private class HmacOutputStream extends OutputStream {

      @Override
      public void write(int bb) throws IOException {
        hmac.update((byte) bb);
      }

      @Override
      public void write(byte[] bytes) throws IOException {
        hmac.update(bytes, 0, bytes.length);
      }

      @Override
      public void write(byte[] bytes, int off, int len) throws IOException {
        hmac.update(bytes, off, len);
      }

    } // class HmacOutputStream

    private final AlgorithmIdentifier algId;

    private final HmacOutputStream outputStream;

    private final Mac hmac;

    private final SecretKey macKey;

    private XDHContentVerifier(AlgorithmIdentifier algId, Mac hmac, SecretKey macKey) {
      this.algId = algId;
      this.hmac = hmac;
      this.macKey = macKey;
      this.outputStream = new HmacOutputStream();
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
      return algId;
    }

    @Override
    public OutputStream getOutputStream() {
      try {
        hmac.init(macKey);
      } catch (InvalidKeyException ex) {
        throw new RuntimeCryptoException("could not init MAC: " + ex.getMessage());
      }
      return outputStream;
    }

    @Override
    public boolean verify(byte[] expected) {
      DhSigStatic dhsig = DhSigStatic.getInstance(expected);
      byte[] expectedHashValue = dhsig.getHashValue();

      // compute the hashvalue
      byte[] hashValue = hmac.doFinal();
      return Arrays.equals(expectedHashValue, hashValue);
    }

  } // class XDHContentVerifier

  private final SecretKey hmacKey;

  private final String hmacAlgoithm;

  private final ASN1ObjectIdentifier sigAlgOid;

  public XiXDHContentVerifierProvider(PublicKey verifyKey, DHSigStaticKeyCertPair ownerKeyAndCert)
      throws InvalidKeyException {
    notNull(verifyKey, "verifyKey");
    notNull(ownerKeyAndCert, "ownerKeyAndCert");

    String keyAlgName = verifyKey.getAlgorithm();

    HashAlgo hash;
    if (EdECConstants.X25519.equalsIgnoreCase(keyAlgName)) {
      this.sigAlgOid = Xipki.id_alg_dhPop_x25519;
      this.hmacAlgoithm = "HMAC-SHA512";
      hash = HashAlgo.SHA512;
    } else if (EdECConstants.X448.equalsIgnoreCase(keyAlgName)) {
      this.sigAlgOid = Xipki.id_alg_dhPop_x448;
      this.hmacAlgoithm = "HMAC-SHA512";
      hash = HashAlgo.SHA512;
    }  else {
      throw new InvalidKeyException("unsupported verifyKey.getAlgorithm(): " + keyAlgName);
    }

    if (!keyAlgName.equals(ownerKeyAndCert.getPrivateKey().getAlgorithm())) {
      throw new InvalidKeyException("verifyKey and ownerKeyAndCert does not match");
    }

    // compute the secret key
    byte[] zz;
    try {
      KeyAgreement keyAgreement = KeyAgreement.getInstance(keyAlgName, "BC");
      keyAgreement.init(ownerKeyAndCert.getPrivateKey());
      keyAgreement.doPhase(verifyKey, true);
      zz = keyAgreement.generateSecret();
    } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | IllegalStateException ex) {
      throw new InvalidKeyException("KeyChange error", ex);
    }

    // as defined in RFC 6955, raw hash algorithm is used as KDF

    // LeadingInfo := Subject Distinguished Name from certificate
    byte[] leadingInfo = ownerKeyAndCert.getEncodedSubject();
    // TrailingInfo ::= Issuer Distinguished Name from certificate
    byte[] trailingInfo = ownerKeyAndCert.getEncodedIssuer();
    byte[] k = hash.hash(leadingInfo, zz, trailingInfo);
    this.hmacKey = new SecretKeySpec(k, hmacAlgoithm);
  } // constructor

  @Override
  public boolean hasAssociatedCertificate() {
    return false;
  }

  @Override
  public X509CertificateHolder getAssociatedCertificate() {
    return null;
  }

  @Override
  public ContentVerifier get(AlgorithmIdentifier verifierAlgorithmIdentifier) throws OperatorCreationException {
    ASN1ObjectIdentifier oid = verifierAlgorithmIdentifier.getAlgorithm();
    if (!this.sigAlgOid.equals(oid)) {
      throw new OperatorCreationException("given public key is not suitable for the alogithm " + oid.getId());
    }

    Mac hmac;
    try {
      hmac = Mac.getInstance(hmacAlgoithm);
    } catch (NoSuchAlgorithmException ex) {
      throw new OperatorCreationException(ex.getMessage());
    }

    return new XDHContentVerifier(verifierAlgorithmIdentifier, hmac, hmacKey);
  } // method get

}
