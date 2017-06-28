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
     * @param cert
     *          Certificate to be added. Must not be {@code null}.
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
     *
     * @param objectId
     *          Object identifier. Must not be {@code null}.
     */
    void removeIdentity(P11ObjectIdentifier objectId) throws P11TokenException;

    /**
     *
     * @param objectId
     *          Object identifier. Must not be {@code null}.
     */
    void removeCerts(P11ObjectIdentifier objectId) throws P11TokenException;

    /**
     *
     * @param cert
     *          Certificate to be added. Must not be {@code null}.
     */
    P11ObjectIdentifier addCert(X509Certificate cert)
            throws P11TokenException, CertificateException;

    /**
     *
     * @param objectId
     *          Object identifier. Must not be {@code null}.
     * @param cert
     *          Certificate to be added. Must not be {@code null}.
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
     */
    // CHECKSTYLE:OFF
    P11ObjectIdentifier generateDSAKeypair(BigInteger p, BigInteger q, BigInteger g,
            String label, P11NewKeyControl control)
            throws P11TokenException;
    // CHECKSTYLE:ON

    /**
     *
     * @param curveId
     *         Object identifier of the EC curve. Must not be {@code null}.
     * @param label
     *          Label of the generated keys. Must not be {@code null}.
     * @param control
     *          Control of the key generation process. Must not be {@code null}.
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
     */
    P11ObjectIdentifier createSecretKey(long keyType, byte[] keyValue, String label,
            P11NewKeyControl control)
            throws P11TokenException;

    /**
     *
     * @param objectId
     *          Object identifier. Must not be {@code null}.
     */
    X509Certificate exportCert(P11ObjectIdentifier objectId)
            throws P11TokenException, CertificateException;

    /**
     *
     * @param stream
     *          Output stream. Must not be {@code null}.
     */
    void showDetails(OutputStream stream, boolean verbose)
            throws P11TokenException, IOException;

}
