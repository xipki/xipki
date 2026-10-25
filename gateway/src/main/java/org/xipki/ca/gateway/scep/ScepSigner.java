// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.scep;

import org.xipki.pkix.pkcs12.KeypairWithCert;
import org.xipki.pkix.cert.KeyUsage;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.scep.message.EnvelopedDataDecryptor;
import org.xipki.pkix.sign.ConcurrentSigner;

import java.security.Key;
import java.security.PrivateKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPublicKey;

/**
 * SCEP Signer definition.
 * <p>
 * Without decryptor, the signing key is also used to decrypt the requests. With a decryptor, the
 * client finds out the certificates for signature and encryption via the keyUsage (RFC 8894):
 * the signing certificate must have the keyUsage digitalSignature but not keyEncipherment, the
 * encryption certificate keyEncipherment but neither digitalSignature nor contentCommitment.
 *
 * @author Lijun Liao (xipki)
 */
public class ScepSigner {

  private final PrivateKey key;

  private final X509Cert cert;

  private final X509Cert encryptionCert;

  private final EnvelopedDataDecryptor decryptor;

  public ScepSigner(ConcurrentSigner signer) {
    this(signer, null);
  }

  /**
   * Constructor.
   * @param signer the signer.
   * @param decryptor the key and certificate to decrypt the requests. If null, the signing key
   *                  is used.
   */
  public ScepSigner(ConcurrentSigner signer, KeypairWithCert decryptor) {
    Key signingKey = signer.signingKey();
    if (!(signingKey instanceof PrivateKey)) {
      throw new IllegalArgumentException(
          "Unsupported signer type: the signing key is not a PrivateKey");
    }

    if (!(signer.x509Cert().publicKey() instanceof RSAPublicKey)) {
      throw new IllegalArgumentException("The SCEP responder key is not RSA key");
    }

    this.key = (PrivateKey) signingKey;
    this.cert = signer.x509Cert();

    PrivateKey decryptionKey;
    if (decryptor == null) {
      this.encryptionCert = cert;
      decryptionKey = key;
    } else {
      this.encryptionCert = decryptor.x509CertChain()[0];
      decryptionKey = decryptor.getKey();
      checkDecryptor(cert, encryptionCert, decryptionKey);
    }

    this.decryptor = new EnvelopedDataDecryptor(
        new EnvelopedDataDecryptor.EnvelopedDataDecryptorInstance(encryptionCert, decryptionKey));
  }

  private static void checkDecryptor(
      X509Cert signerCert, X509Cert encCert, PrivateKey decryptionKey) {
    if (!(encCert.publicKey() instanceof RSAPublicKey)) {
      throw new IllegalArgumentException("The SCEP decryption key is not RSA key");
    }

    if (decryptionKey instanceof RSAKey && !((RSAKey) decryptionKey).getModulus().equals(
        ((RSAPublicKey) encCert.publicKey()).getModulus())) {
      throw new IllegalArgumentException(
          "The SCEP decryption key does not match the certificate " + encCert.subjectText());
    }

    if (signerCert.subjectPublicKeyInfo().equals(encCert.subjectPublicKeyInfo())) {
      throw new IllegalArgumentException("The SCEP decryption key is the signing key, "
          + "remove the decryptor to use one key for both");
    }

    // The client selects the certificates via the keyUsage.
    if (signerCert.keyUsage() == null
        || !(signerCert.hasKeyusage(KeyUsage.digitalSignature)
            || signerCert.hasKeyusage(KeyUsage.contentCommitment))
        || signerCert.hasKeyusage(KeyUsage.keyEncipherment)) {
      throw new IllegalArgumentException("The SCEP signer certificate "
          + signerCert.subjectText() + " must have the keyUsage digitalSignature "
          + "but not keyEncipherment if a separate decryptor is configured");
    }

    if (encCert.keyUsage() == null
        || !encCert.hasKeyusage(KeyUsage.keyEncipherment)
        || encCert.hasKeyusage(KeyUsage.digitalSignature)
        || encCert.hasKeyusage(KeyUsage.contentCommitment)) {
      throw new IllegalArgumentException("The SCEP decryptor certificate "
          + encCert.subjectText() + " must have the keyUsage keyEncipherment "
          + "but neither digitalSignature nor contentCommitment");
    }
  }

  public PrivateKey key() {
    return key;
  }

  /**
   * Returns the certificate of the signing key.
   * @return the certificate of the signing key.
   */
  public X509Cert cert() {
    return cert;
  }

  /**
   * Returns the certificate to which the client encrypts the requests. It is
   * {@link #cert()} if no separate decryptor is configured.
   * @return the certificate of the decryption key.
   */
  public X509Cert encryptionCert() {
    return encryptionCert;
  }

  public EnvelopedDataDecryptor decryptor() {
    return decryptor;
  }

}
