/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.security.api.p11;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.security.api.SecurityFactory;

/**
 * @author Lijun Liao
 */

public interface P11WritableSlot
{
    P11SlotIdentifier getSlotIdentifier();

    void updateCertificate(
            P11KeyIdentifier keyIdentifier,
            X509Certificate newCert,
            Set<X509Certificate> caCerts,
            SecurityFactory securityFactory)
    throws Exception;

    boolean removeKeyAndCerts(
            P11KeyIdentifier keyIdentifier)
    throws Exception;

    boolean removeKey(
            P11KeyIdentifier keyIdentifier)
    throws Exception;

    void removeCerts(
            P11KeyIdentifier keyIdentifier)
    throws Exception;

    P11KeyIdentifier addCert(
            X509Certificate cert)
    throws Exception;

    P11KeyIdentifier generateRSAKeypair(
            int keySize,
            BigInteger publicExponent,
            String label)
    throws Exception;

    P11KeypairGenerationResult generateRSAKeypairAndCert(
            int keySize,
            BigInteger publicExponent,
            String label,
            String subject,
            Integer keyUsage,
            List<ASN1ObjectIdentifier> extendedKeyusage)
    throws Exception;

    P11KeyIdentifier generateDSAKeypair(
            int pLength,
            int qLength,
            String label)
    throws Exception;

    P11KeypairGenerationResult generateDSAKeypairAndCert(
            int pLength,
            int qLength,
            String label,
            String subject,
            Integer keyUsage,
            List<ASN1ObjectIdentifier> extendedKeyusage)
    throws Exception;

    P11KeyIdentifier generateECKeypair(
            String curveNameOrOid,
            String label)
    throws Exception;

    P11KeypairGenerationResult generateECDSAKeypairAndCert(
            String curveNameOrOid,
            String label,
            String subject,
            Integer keyUsage,
            List<ASN1ObjectIdentifier> extendedKeyusage)
    throws Exception;

    X509Certificate exportCert(
            P11KeyIdentifier keyIdentifier)
    throws Exception;

    List<? extends P11Identity> getP11Identities();

}
