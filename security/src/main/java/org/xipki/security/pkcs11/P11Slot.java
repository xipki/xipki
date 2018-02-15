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

package org.xipki.security.pkcs11;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Set;

import org.xipki.security.exception.P11TokenException;
import org.xipki.security.exception.P11UnknownEntityException;
import org.xipki.security.exception.P11UnsupportedMechanismException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public interface P11Slot {

    String moduleName();

    boolean isReadOnly();

    P11SlotIdentifier slotId();

    Set<P11ObjectIdentifier> identityIdentifiers();

    Set<P11ObjectIdentifier> certIdentifiers();

    boolean hasIdentity(P11ObjectIdentifier objectId);

    void close();

    Set<Long> mechanisms();

    boolean supportsMechanism(long mechanism);

    void assertMechanismSupported(long mechanism) throws P11UnsupportedMechanismException;

    P11Identity getIdentity(P11ObjectIdentifier objectId) throws P11UnknownEntityException;

    void refresh() throws P11TokenException;

    P11ObjectIdentifier getObjectIdForId(byte[] id);

    P11ObjectIdentifier getObjectIdForLabel(String label);

    /**
     * Updates the certificate associated with the given {@code objectId} with the given certificate
     * {@code newCert}.
     *
     * @param objectId
     *          Object identifier. Must not be {@code null}.
     * @param newCert
     *          Certificate to be added. Must not be {@code null}.
     * @throws CertificateException
     *         if process with certificate fails.
     * @throws P11TokenException
     *         if PKCS#11 token exception occurs.
     */
    void updateCertificate(P11ObjectIdentifier objectId, X509Certificate newCert)
            throws P11TokenException, CertificateException;

    /**
     *
     * @param id
     *         Id of the objects to be deleted. At least one of id and label must not be
     *         {@code null}.
     * @param label
     *         Label of the objects to be deleted
     * @return how many objects have been deleted
     * @throws P11TokenException
     *           If PKCS#11 error happens.
     */
    int removeObjects(byte[] id, String label) throws P11TokenException;

    /**
     * Removes the key (private key, public key, secret key, and certificates) associated with
     * the given identifier {@code objectId}.
     *
     * @param objectId
     *          Object identifier. Must not be {@code null}.
     * @throws P11TokenException
     *         if PKCS#11 token exception occurs.
     */
    void removeIdentity(P11ObjectIdentifier objectId) throws P11TokenException;

    /**
     *
     * @param objectId
     *          Object identifier. Must not be {@code null}.
     * @throws P11TokenException
     *         if PKCS#11 token exception occurs.
     */
    void removeCerts(P11ObjectIdentifier objectId) throws P11TokenException;

    /**
     * Adds the certificate to the PKCS#11 token.
     *
     * @param cert
     *          Certificate to be added. Must not be {@code null}.
     * @return the identifier of the certificate within the PKCS#11 token.
     * @throws CertificateException
     *         if process with certificate fails.
     * @throws P11TokenException
     *         if PKCS#11 token exception occurs.
     */
    P11ObjectIdentifier addCert(X509Certificate cert)
            throws P11TokenException, CertificateException;

    /**
     *
     * Adds the certificate to the PKCS#11 token under the given identifier {@code objectId}.
     *
     * @param objectId
     *          Object identifier. Must not be {@code null}.
     * @param cert
     *          Certificate to be added. Must not be {@code null}.
     * @throws CertificateException
     *         if process with certificate fails.
     * @throws P11TokenException
     *         if PKCS#11 token exception occurs.
     */
    void addCert(P11ObjectIdentifier objectId, X509Certificate cert)
            throws P11TokenException, CertificateException;

    /**
     * Generates an RSA keypair.
     *
     * @param keysize
     *          key size
     * @param publicExponent
     *          RSA public exponent. Could be {@code null}.
     * @param label
     *          Label of the generated keys. Must not be {@code null}.
     * @param control
     *          Control of the key generation process. Must not be {@code null}.
     * @return the identifier of the key within the PKCS#P11 token.
     * @throws P11TokenException
     *         if PKCS#11 token exception occurs.
     */
    // CHECKSTYLE:SKIP
    P11ObjectIdentifier generateRSAKeypair(int keysize, BigInteger publicExponent,
            String label, P11NewKeyControl control) throws P11TokenException;

    /**
     * Generates an RSA keypair.
     *
     * @param plength
     *          bit length of P
     * @param qlength
     *          bit lenght of Q
     * @param label
     *          Label of the generated keys. Must not be {@code null}.
     * @param control
     *          Control of the key generation process. Must not be {@code null}.
     * @return the identifier of the key within the PKCS#P11 token.
     * @throws P11TokenException
     *         if PKCS#11 token exception occurs.
     */
    // CHECKSTYLE:SKIP
    P11ObjectIdentifier generateDSAKeypair(int plength, int qlength, String label,
            P11NewKeyControl control) throws P11TokenException;

    /**
     * Generates a DSA keypair.
     *
     * @param p
     *          p of DSA. Must not be {@code null}.
     * @param q
     *          q of DSA. Must not be {@code null}.
     * @param g
     *          g of DSA. Must not be {@code null}.
     * @param label
     *          Label of the generated keys. Must not be {@code null}.
     * @param control
     *          Control of the key generation process. Must not be {@code null}.
     * @return the identifier of the key within the PKCS#P11 token.
     * @throws P11TokenException
     *         if PKCS#11 token exception occurs.
     */
    // CHECKSTYLE:OFF
    P11ObjectIdentifier generateDSAKeypair(BigInteger p, BigInteger q, BigInteger g,
            String label, P11NewKeyControl control) throws P11TokenException;
    // CHECKSTYLE:ON

    /**
     * Generates an EC keypair.
     *
     * @param curveNameOrOid
     *         Object identifier or name of the EC curve. Must not be {@code null}.
     * @param label
     *          Label of the generated keys. Must not be {@code null}.
     * @param control
     *          Control of the key generation process. Must not be {@code null}.
     * @return the identifier of the key within the PKCS#P11 token.
     * @throws P11TokenException
     *         if PKCS#11 token exception occurs.
     */
    // CHECKSTYLE:SKIP
    P11ObjectIdentifier generateECKeypair(String curveNameOrOid, String label,
            P11NewKeyControl control) throws P11TokenException;

    /**
     * Generates an SM2 keypair.
     *
     * @param label
     *          Label of the generated keys. Must not be {@code null}.
     * @param control
     *          Control of the key generation process. Must not be {@code null}.
     * @return the identifier of the key within the PKCS#P11 token.
     * @throws P11TokenException
     *         if PKCS#11 token exception occurs.
     */
    // CHECKSTYLE:SKIP
    P11ObjectIdentifier generateSM2Keypair(String label, P11NewKeyControl control)
            throws P11TokenException;

    /**
     * Generates a secret key in the PKCS#11 token.
     *
     * @param keyType
     *          Key type
     * @param keysize
     *          Key size
     * @param label
     *          Label of the generated key. Must not be {@code null}.
     * @param control
     *          Control of the key generation process. Must not be {@code null}.
     * @return the identifier of the key within the PKCS#11 token.
     * @throws P11TokenException
     *         if PKCS#11 token exception occurs.
     */
    P11ObjectIdentifier generateSecretKey(long keyType, int keysize, String label,
            P11NewKeyControl control) throws P11TokenException;

    /**
     * Imports secret key object in the PKCS#11 token. The key itself will not be generated
     * within the PKCS#11 token.
     *
     * @param keyType
     *          Key type
     * @param keyValue
     *          Key value. Must not be {@code null}.
     * @param label
     *          Label of the generated key. Must not be {@code null}.
     * @param control
     *          Control of the key generation process. Must not be {@code null}.
     * @return the identifier of the key within the PKCS#11 token.
     * @throws P11TokenException
     *         if PKCS#11 token exception occurs.
     */
    P11ObjectIdentifier importSecretKey(long keyType, byte[] keyValue, String label,
            P11NewKeyControl control) throws P11TokenException;

    /**
     * Exports the certificate of the given identifier {@code objectId}.
     *
     * @param objectId
     *          Object identifier. Must not be {@code null}.
     * @return the exported certificate
     * @throws CertificateException
     *         if process with certificate fails.
     * @throws P11TokenException
     *         if PKCS#11 token exception occurs.
     */
    X509Certificate exportCert(P11ObjectIdentifier objectId)
            throws P11TokenException, CertificateException;

    /**
     * Writes the token details to the given {@code stream}.
     * @param stream
     *          Output stream. Must not be {@code null}.
     * @param verbose
     *          Whether to show the details verbosely.
     * @throws P11TokenException
     *         if PKCS#11 token exception occurs.
     * @throws IOException
     *         if IO error occurs.
     */
    void showDetails(OutputStream stream, boolean verbose)
            throws P11TokenException, IOException;

}
