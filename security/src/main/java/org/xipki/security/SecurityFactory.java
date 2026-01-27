// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.xipki.util.codec.Args;
import org.xipki.util.extra.exception.ObjectCreationException;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Set;

/**
 * This is the core interface. It specifies the method to create
 * {@link ConcurrentContentSigner}, {@link ContentVerifierProvider},
 * to verify POP, to the random, etc.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public interface SecurityFactory {

  /**
   * Retrieves the types of supported signers.
   * @return lower-case types of supported signers, never {@code null}.
   */
  Set<String> getSupportedSignerTypes();

  /**
   * Creates signer.
   *
   * @param type
   *        Type of the signer. Must not be {@code null}.
   * @param conf
   *        Configuration of the signer. Could be {@code null}.
   * @param cert
   *        Certificate of the signer. If not {@code null}, it will be used;
   *        otherwise the certificates contained in the token will be used.
   * @return the new signer
   * @throws ObjectCreationException
   *         if could not create the signer
   */
  default ConcurrentContentSigner createSigner(
      String type, SignerConf conf, X509Cert cert)
      throws ObjectCreationException {
    X509Cert[] certs = (cert == null) ? null : new X509Cert[]{cert};
    return createSigner(type, conf, certs);
  }

  /**
   * Creates signer.
   *
   * @param type
   *        Type of the signer. Must not be {@code null}.
   * @param conf
   *        Configuration of the signer. Could be {@code null}.
   * @param certs
   *        Certificates of the signer. If not {@code null}, it will be used;
   *        otherwise the certificates contained in the token will be used.
   * @return the new signer
   * @throws ObjectCreationException
   *         if could not create the signer
   */
  ConcurrentContentSigner createSigner(
      String type, SignerConf conf, X509Cert[] certs)
      throws ObjectCreationException;

  /**
   * Gets the ContentVerifierProvider from the public key.
   *
   * @param publicKey
   *        Signature verification key. Must not be {@code null}.
   * @return the ContentVerifierProvider
   * @throws InvalidKeyException
   *         If the publicKey is invalid or unsupported.
   */
  default ContentVerifierProvider getContentVerifierProvider(
      PublicKey publicKey) throws InvalidKeyException {
    return getContentVerifierProvider(publicKey, null, null);
  }

  /**
   * Gets the ContentVerifierProvider from the public key.
   *
   * @param publicKey
   *        Signature verification key. Must not be {@code null}.
   * @param ownerKeyAndCert
   *        The owner's key and certificate for the CSR with Diffie-Hellman PoP.
   *        May be {@code null}.
   * @param ownerMasterKey
   *        The owner's master key and certificate for the CSR with KEM PoP.
   *        May be {@code null}.
   * @return the ContentVerifierProvider
   * @throws InvalidKeyException
   *         If the publicKey is invalid or unsupported.
   */
  ContentVerifierProvider getContentVerifierProvider(
      PublicKey publicKey, DHSigStaticKeyCertPair ownerKeyAndCert,
      SecretKey ownerMasterKey) throws InvalidKeyException;

  /**
   * Gets the ContentVerifierProvider from the certificate.
   *
   * @param cert
   *        Certificate that contains the signature verification key. Must not
   *        be {@code null}.
   * @return the ContentVerifierProvider
   * @throws InvalidKeyException
   *         If the publicKey contained in the certificate is invalid or
   *         unsupported.
   */
  default ContentVerifierProvider getContentVerifierProvider(X509Cert cert)
      throws InvalidKeyException {
    return getContentVerifierProvider(
        Args.notNull(cert, "cert").getPublicKey());
  }

  /**
   * Verifies the signature of CSR.
   * @param csr
   *        CSR to be verified. Must not be {@code null}.
   * @param algoValidator
   *        Signature algorithms validator. null to accept all
   *        algorithms
   * @return true if the signature is valid and the signature
   *         algorithm is accepted, false otherwise.
   */
  default boolean verifyPop(PKCS10CertificationRequest csr,
                            AlgorithmValidator algoValidator) {
    return verifyPop(csr, algoValidator, null, null);
  }

  /**
   * Verifies the signature of CSR.
   *
   * @param csr
   *        CSR to be verified. Must not be {@code null}.
   * @param algoValidator
   *        Signature algorithms validator. null to accept all
   *        algorithms
   * @param ownerKeyAndCert
   *        The owner's key and certificate for the CSR with Diffie-Hellman PoP.
   *        May be {@code null}.
   * @param ownerMasterKey
   *        The ower's secret key for the CSR with KEM-MAC PoP.
   *        May be {@code null}.
   * @return true if the signature is valid and the signature
   *         algorithm is accepted, false otherwise.
   */
  boolean verifyPop(PKCS10CertificationRequest csr,
                    AlgorithmValidator algoValidator,
                    DHSigStaticKeyCertPair ownerKeyAndCert,
                    SecretKey ownerMasterKey);

  /**
   * Verifies the signature of CSR.
   *
   * @param csr
   *        CSR to be verified. Must not be {@code null}.
   * @param algoValidator
   *        Signature algorithms validator. null to accept all algorithms
   * @return true if the signature is valid and the signature algorithm is
   *         accepted, false otherwise.
   */
  default boolean verifyPop(CertificationRequest csr,
                            AlgorithmValidator algoValidator) {
    return verifyPop(csr, algoValidator, null, null);
  }

  /**
   * Verifies the signature of CSR.
   *
   * @param csr
   *          CSR to be verified. Must not be {@code null}.
   * @param algoValidator
   *          Signature algorithms validator. null to accept all algorithms
   * @param ownerKeyAndCert
   *          The owner's key and certificate for the CSR with Diffie-Hellman
   *          PoP. May be {@code null}.
   * @param ownerMasterKey
   *          The owner's secret key for the CSR with KEM-MAC PoP.
   *          May be {@code null}.
   * @return true if the signature is valid and the signature algorithm is
   *         accepted, false otherwise.
   */
  default boolean verifyPop(
      CertificationRequest csr, AlgorithmValidator algoValidator,
      DHSigStaticKeyCertPair ownerKeyAndCert, SecretKey ownerMasterKey) {
    return verifyPop(new PKCS10CertificationRequest(csr), algoValidator,
        ownerKeyAndCert, ownerMasterKey);
  }

  /**
   * Create PublicKey from the {@code subjectPublicKeyInfo}.
   * @param subjectPublicKeyInfo
   *        From which the public key will be created. Must not be {@code null}.
   * @return the created public key.
   * @throws InvalidKeyException
   *         if could not create public key.
   */
  PublicKey generatePublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo)
      throws InvalidKeyException;

  SecureRandom getRandom4Sign();

  SecureRandom getRandom4Key();

  int getDfltSignerParallelism();

  CsrControl getCsrControl();

}
