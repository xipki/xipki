/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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
     *
     * @param objectId
     *          Object identifier. Must not be {@code null}.
     * @param newCert
     *          Certificate to be added. Must not be {@code null}.
     * @throws P11TokenException
     * @throws CertificateException
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
     * @throws P11TokenException
     */
    int removeObjects(byte[] id, String label) throws P11TokenException;

    /**
     *
     * @param objectId
     *          Object identifier. Must not be {@code null}.
     * @throws P11TokenException
     */
    void removeIdentity(P11ObjectIdentifier objectId) throws P11TokenException;

    /**
     *
     * @param objectId
     *          Object identifier. Must not be {@code null}.
     * @throws P11TokenException
     */
    void removeCerts(P11ObjectIdentifier objectId) throws P11TokenException;

    /**
     *
     * @param cert
     *          Certificate to be added. Must not be {@code null}.
     * @throws P11TokenException
     * @throws CertificateException
     */
    P11ObjectIdentifier addCert(X509Certificate cert)
            throws P11TokenException, CertificateException;

    /**
     *
     * @param objectId
     *          Object identifier. Must not be {@code null}.
     * @param cert
     *          Certificate to be added. Must not be {@code null}.
     * @throws P11TokenException
     * @throws CertificateException
     */
    void addCert(P11ObjectIdentifier objectId, X509Certificate cert)
            throws P11TokenException, CertificateException;

    /**
     *
     * @param publicExponent
     *          RSA public exponent. Could be {@code null}.
     * @param label
     *          Label of the generated keys. Must not be {@code null}.
     * @param control
     *          Control of the key generation process. Must not be {@code null}.
     * @throws P11TokenException
     */
    // CHECKSTYLE:SKIP
    P11ObjectIdentifier generateRSAKeypair(int keysize, BigInteger publicExponent,
            String label, P11NewKeyControl control)
            throws P11TokenException;

    /**
     *
     * @param label
     *          Label of the generated keys. Must not be {@code null}.
     * @param control
     *          Control of the key generation process. Must not be {@code null}.
     * @throws P11TokenException
     */
    // CHECKSTYLE:SKIP
    P11ObjectIdentifier generateDSAKeypair(int plength, int qlength, String label,
            P11NewKeyControl control)
            throws P11TokenException;

    /**
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
     * @throws P11TokenException
     */
    // CHECKSTYLE:OFF
    P11ObjectIdentifier generateDSAKeypair(BigInteger p, BigInteger q, BigInteger g,
            String label, P11NewKeyControl control)
            throws P11TokenException;
    // CHECKSTYLE:ON

    /**
     *
     * @param curveNameOrOid
     *         Object identifier or name of the EC curve. Must not be {@code null}.
     * @param label
     *          Label of the generated keys. Must not be {@code null}.
     * @param control
     *          Control of the key generation process. Must not be {@code null}.
     * @throws P11TokenException
     */
    // CHECKSTYLE:SKIP
    P11ObjectIdentifier generateECKeypair(String curveNameOrOid, String label,
            P11NewKeyControl control)
            throws P11TokenException;

    /**
     *
     * @param label
     *          Label of the generated key. Must not be {@code null}.
     * @param control
     *          Control of the key generation process. Must not be {@code null}.
     */
    P11ObjectIdentifier generateSecretKey(long keyType, int keysize, String label,
            P11NewKeyControl control)
            throws P11TokenException;

    /**
     *
     * @param keyValue
     *          Key value. Must not be {@code null}.
     * @param label
     *          Label of the generated key. Must not be {@code null}.
     * @param control
     *          Control of the key generation process. Must not be {@code null}.
     * @throws P11TokenException
     */
    P11ObjectIdentifier createSecretKey(long keyType, byte[] keyValue, String label,
            P11NewKeyControl control)
            throws P11TokenException;

    /**
     *
     * @param objectId
     *          Object identifier. Must not be {@code null}.
     * @throws P11TokenException
     * @throws CertificateException
     */
    X509Certificate exportCert(P11ObjectIdentifier objectId)
            throws P11TokenException, CertificateException;

    /**
     *
     * @param stream
     *          Output stream. Must not be {@code null}.
     * @throws P11TokenException
     * @throws IOException
     */
    void showDetails(OutputStream stream, boolean verbose)
            throws P11TokenException, IOException;

}
