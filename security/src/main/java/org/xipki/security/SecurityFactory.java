/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.security;

import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.xipki.common.ObjectCreationException;
import org.xipki.password.PasswordResolver;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public interface SecurityFactory {

    PasswordResolver getPasswordResolver();

    /**
     * Create secret key and certificate pair.
     * @param type
     *          Type of the signer. Must not be {@code null}.
     * @param conf
     *          Configuration of the signer. Could be {@code null}.
     * @param cert
     *          Certificate of the signer. If not {@code null}, it will be used; otherwise
     *          the certificates contained in the token will be used.
     * @return the new pair of key and certificate
     * @throws ObjectCreationException
     *         if could not create the object
     */
    KeyCertPair createPrivateKeyAndCert(String type, SignerConf conf, X509Certificate cert)
            throws ObjectCreationException;

    /**
     * Creates signer.
     *
     * @param type
     *          Type of the signer. Must not be {@code null}.
     * @param conf
     *          Configuration of the signer. Could be {@code null}.
     * @param cert
     *          Certificate of the signer. If not {@code null}, it will be used; otherwise
     *          the certificates contained in the token will be used.
     * @return the new signer
     * @throws ObjectCreationException
     *         if could not create the signer
     */
    ConcurrentContentSigner createSigner(String type, SignerConf conf, X509Certificate cert)
            throws ObjectCreationException;

    /**
     * Creates signer.
     *
     * @param type
     *          Type of the signer. Must not be {@code null}.
     * @param conf
     *          Configuration of the signer. Could be {@code null}.
     * @param certs
     *          Certificates of the signer. If not {@code null}, it will be used; otherwise
     *          the certificates contained in the token will be used.
     * @return the new signer
     * @throws ObjectCreationException
     *         if could not create the signer
     */
    ConcurrentContentSigner createSigner(String type, SignerConf conf, X509Certificate[] certs)
            throws ObjectCreationException;

    /**
     * Gets the ContentVerifierProvider from the public key.
     *
     * @param publicKey
     *          Signature verification key. Must not be {@code null}.
     * @return the ContentVerifierProvider
     * @throws InvalidKeyException
     *         If the publicKey is invalid or unsupported.
     */
    ContentVerifierProvider getContentVerifierProvider(PublicKey publicKey)
            throws InvalidKeyException;

    /**
     * Gets the ContentVerifierProvider from the certificate.
     *
     * @param cert
     *          Certificate that contains the signature verification key. Must not be {@code null}.
     * @return the ContentVerifierProvider
     * @throws InvalidKeyException
     *         If the publicKey contained in the certificate is invalid or unsupported.
     */
    ContentVerifierProvider getContentVerifierProvider(X509Certificate cert)
            throws InvalidKeyException;

    /**
     * Gets the ContentVerifierProvider from the certificate.
     *
     * @param cert
     *          Certificate that contains the signature verification key. Must not be {@code null}.
     * @return the ContentVerifierProvider
     * @throws InvalidKeyException
     *         If the publicKey contained in the certificate is invalid or unsupported.
     */
    ContentVerifierProvider getContentVerifierProvider(X509CertificateHolder cert)
            throws InvalidKeyException;

    /**
     * Verifies the signature of CSR.
     * @param csr
     *          CSR to be verified. Must not be {@code null}.
     * @param algoValidator
     *          Signature algorithms validator. <code>null</code> to accept all algorithms
     * @return <code>true</code> if the signature is valid and the signature algorithm is accepted,
     *         <code>false</code> otherwise.
     */
    boolean verifyPopo(PKCS10CertificationRequest csr, AlgorithmValidator algoValidator);

    /**
     * Verifies the signature of CSR.
     *
     * @param csr
     *          CSR to be verified. Must not be {@code null}.
     * @param algoValidator
     *          Signature algorithms validator. <code>null</code> to accept all algorithms
     * @return <code>true</code> if the signature is valid and the signature algorithm is accepted,
     *         <code>false</code> otherwise.
     */
    boolean verifyPopo(CertificationRequest csr, AlgorithmValidator algoValidator);

    /**
     * Create PublicKey from the {@code subjectPublicKeyInfo}
     * @param subjectPublicKeyInfo
     *          From which the public key will be created. Must not be {@code null}.
     * @return the created public key.
     * @throws InvalidKeyException
     *         if could not create public key.
     */
    PublicKey generatePublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo)
            throws InvalidKeyException;

    /**
     * Extracts the keystore with minimal required information.
     * <ol>
     *   <li>If {@code keyname} is set, and its associated entry is a key entry, then only this
     *   entry is remained.</li>
     *   <li>if {@code keyname} is {@code null} and there exists at least one key entry, then only
     *   the first entry is remained.</li>
     *   <li>otherwise, {@link KeyStoreException} will be thrown.</li>
     * </ol>
     *
     * @param keystoreType
     *          Type of the keystore. Must not be {@code null}.
     * @param keystoreBytes
     *          Content of the keystpre. Must not be {@code null}.
     * @param keyname
     *          Name (alias) of the key. Could be {@code null}.
     * @param password
     *          Password of the keystore and key. Must not be {@code null}.
     * @param newCertChain
     *          New certificates. If not {@code null}, the certificates in the keystore will be
     *          replaced.
     * @return the minimal keystore
     * @throws KeyStoreException
     *          If case 3 occurs.
     */
    byte[] extractMinimalKeyStore(String keystoreType, byte[] keystoreBytes, String keyname,
            char[] password, X509Certificate[] newCertChain) throws KeyStoreException;

    SecureRandom getRandom4Sign();

    SecureRandom getRandom4Key();

    int getDefaultSignerParallelism();

}
