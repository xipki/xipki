/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
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
     *
     * @param type
     *          Type of the signer. Must not be {@code null}.
     * @param conf
     *          Configuration of the signer. Could be {@code null}.
     * @param cert
     *          Certificate of the signer. If not {@code null}, it will be used; otherwise
     *          the certificates contained in the token will be used.
     * @return the new pair of key and certificate
     */
    KeyCertPair createPrivateKeyAndCert(String type, SignerConf conf,
            X509Certificate cert) throws ObjectCreationException;

    /**
     *
     * @param type
     *          Type of the signer. Must not be {@code null}.
     * @param conf
     *          Configuration of the signer. Could be {@code null}.
     * @param cert
     *          Certificate of the signer. If not {@code null}, it will be used; otherwise
     *          the certificates contained in the token will be used.
     * @return the new signer
     */
    ConcurrentContentSigner createSigner(String type, SignerConf conf, X509Certificate cert)
            throws ObjectCreationException;

    /**
     *
     * @param type
     *          Type of the signer. Must not be {@code null}.
     * @param conf
     *          Configuration of the signer. Could be {@code null}.
     * @param certs
     *          Certificates of the signer. If not {@code null}, it will be used; otherwise
     *          the certificates contained in the token will be used.
     * @return the new signer
     */
    ConcurrentContentSigner createSigner(String type, SignerConf conf, X509Certificate[] certs)
            throws ObjectCreationException;

    /**
     *
     * @param publicKey
     *          Signature verification key. Must not be {@code null}.
     */
    ContentVerifierProvider getContentVerifierProvider(PublicKey publicKey)
            throws InvalidKeyException;

    /**
     *
     * @param cert
     *          Certificate that contains the signature verification key. Must not be {@code null}.
     */
    ContentVerifierProvider getContentVerifierProvider(X509Certificate cert)
            throws InvalidKeyException;

    /**
     *
     * @param cert
     *          Certificate that contains the signature verification key. Must not be {@code null}.
     */
    ContentVerifierProvider getContentVerifierProvider(X509CertificateHolder cert)
            throws InvalidKeyException;

    /**
     *
     * @param csr
     *          CSR to be verified. Must not be {@code null}.
     * @param algoValidator
     *          Signature algorithms validator. <code>null</null> to accept all algorithms
     * @return <code>true</code> if the signature is valid and the signature algorithm is accepted,
     *         <code>false</code> otherwise.
     */
    boolean verifyPopo(PKCS10CertificationRequest csr, AlgorithmValidator algoValidator);

    /**
     *
     * @param csr
     *          CSR to be verified. Must not be {@code null}.
     * @param algoValidator
     *          Signature algorithms validator. <code>null</null> to accept all algorithms
     * @return <code>true</code> if the signature is valid and the signature algorithm is accepted,
     *         <code>false</code> otherwise.
     */
    boolean verifyPopo(CertificationRequest csr, AlgorithmValidator algoValidator);

    /**
     *
     * @param subjectPublicKeyInfo
     *          From which the public key will be created. Must not be {@code null}.
     */
    PublicKey generatePublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo)
            throws InvalidKeyException;

    /**
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
     */
    byte[] extractMinimalKeyStore(String keystoreType, byte[] keystoreBytes, String keyname,
            char[] password, X509Certificate[] newCertChain)
            throws KeyStoreException;

    SecureRandom getRandom4Sign();

    SecureRandom getRandom4Key();

    int getDefaultSignerParallelism();

}
