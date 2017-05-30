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

package org.xipki.commons.security.pkcs11;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Set;

import org.eclipse.jdt.annotation.NonNull;
import org.eclipse.jdt.annotation.Nullable;
import org.xipki.commons.security.exception.P11TokenException;
import org.xipki.commons.security.exception.P11UnknownEntityException;
import org.xipki.commons.security.exception.P11UnsupportedMechanismException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public interface P11Slot {

    String getModuleName();

    boolean isReadOnly();

    P11SlotIdentifier getSlotId();

    Set<P11ObjectIdentifier> getIdentityIdentifiers();

    Set<P11ObjectIdentifier> getCertIdentifiers();

    boolean hasIdentity(P11ObjectIdentifier objectId);

    void close();

    Set<Long> getMechanisms();

    boolean supportsMechanism(long mechanism);

    void assertMechanismSupported(long mechanism) throws P11UnsupportedMechanismException;

    P11Identity getIdentity(P11ObjectIdentifier objectId) throws P11UnknownEntityException;

    void refresh() throws P11TokenException;

    P11ObjectIdentifier getObjectIdForId(byte[] id);

    P11ObjectIdentifier getObjectIdForLabel(String label);

    void updateCertificate(@NonNull P11ObjectIdentifier objectId, @NonNull X509Certificate newCert)
            throws P11TokenException, CertificateException;

    /**
     *
     * @param id id of the objects to be deleted. At least one of id and label must not be null.
     * @param label label of the objects to be deleted
     * @return how many objects have been deleted
     * @throws P11TokenException if PKCS#11 error happens.
     */
    int removeObjects(@Nullable byte[] id, @Nullable String label) throws P11TokenException;

    void removeIdentity(@NonNull P11ObjectIdentifier objectId) throws P11TokenException;

    void removeCerts(@NonNull P11ObjectIdentifier objectId) throws P11TokenException;

    P11ObjectIdentifier addCert(@NonNull X509Certificate cert)
            throws P11TokenException, CertificateException;

    void addCert(@NonNull P11ObjectIdentifier objectId, @NonNull X509Certificate cert)
            throws P11TokenException, CertificateException;

    // CHECKSTYLE:SKIP
    P11ObjectIdentifier generateRSAKeypair(int keysize, @NonNull BigInteger publicExponent,
            @NonNull String label, @NonNull P11NewKeyControl control)
            throws P11TokenException;

    // CHECKSTYLE:SKIP
    P11ObjectIdentifier generateDSAKeypair(int plength, int qlength, @NonNull String label,
            @NonNull P11NewKeyControl control)
            throws P11TokenException;

    // CHECKSTYLE:OFF
    P11ObjectIdentifier generateDSAKeypair(BigInteger p, BigInteger q, BigInteger g,
            @NonNull String label, @NonNull P11NewKeyControl control)
            throws P11TokenException;
    // CHECKSTYLE:ON

    // CHECKSTYLE:SKIP
    P11ObjectIdentifier generateECKeypair(@NonNull String curveNameOrOid, @NonNull String label,
            @NonNull P11NewKeyControl control)
            throws P11TokenException;

    P11ObjectIdentifier generateSecretKey(long keyType, int keysize, @NonNull String label,
            @NonNull P11NewKeyControl control)
            throws P11TokenException;

    P11ObjectIdentifier createSecretKey(long keyType, byte[] keyValue, @NonNull String label,
            @NonNull P11NewKeyControl control)
            throws P11TokenException;

    X509Certificate exportCert(@NonNull P11ObjectIdentifier objectId)
            throws P11TokenException, CertificateException;

    void showDetails(@NonNull OutputStream stream, boolean verbose)
            throws P11TokenException, IOException;

}
