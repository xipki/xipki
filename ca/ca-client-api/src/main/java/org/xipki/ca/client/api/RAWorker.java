/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013-2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License
 * (version 3 or later at your option)
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

package org.xipki.ca.client.api;

import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.ca.cmp.client.type.EnrollCertEntryType;
import org.xipki.ca.cmp.client.type.EnrollCertRequestType;
import org.xipki.ca.cmp.client.type.RevokeCertRequestType;
import org.xipki.ca.cmp.client.type.UnrevokeOrRemoveCertRequestType;
import org.xipki.ca.common.CertIDOrError;
import org.xipki.ca.common.EnrollCertResult;
import org.xipki.ca.common.PKIErrorException;
import org.xipki.ca.common.RAWorkerException;

/**
 * @author Lijun Liao
 */

public interface RAWorker
{
    Set<String> getCaNames();

    Set<String> getCertProfiles(String caName);

    EnrollCertResult requestCert(CertificationRequest p10Request, String profile, String caName,
            String username)
    throws RAWorkerException, PKIErrorException;

    EnrollCertResult requestCerts(EnrollCertRequestType.Type type,
            Map<String, EnrollCertEntryType> enrollCertEntries, String caName, String username)
    throws RAWorkerException, PKIErrorException;

    EnrollCertResult requestCerts(EnrollCertRequestType request, String caName, String username)
    throws RAWorkerException, PKIErrorException;

    CertIDOrError revokeCert(X500Name issuer, BigInteger serial, int reason)
    throws RAWorkerException, PKIErrorException;

    CertIDOrError revokeCert(X509Certificate cert, int reason)
    throws RAWorkerException, PKIErrorException;

    Map<String, CertIDOrError> revokeCerts(RevokeCertRequestType request)
    throws RAWorkerException, PKIErrorException;

    X509CRL downloadCRL(String caName)
    throws RAWorkerException, PKIErrorException;

    X509CRL downloadCRL(String caName, BigInteger crlNumber)
    throws RAWorkerException, PKIErrorException;

    X509CRL generateCRL(String caName)
    throws RAWorkerException, PKIErrorException;

    String getCaNameByIssuer(X500Name issuer)
    throws RAWorkerException;

    byte[] envelope(CertRequest certRequest, ProofOfPossession popo, String profileName,
            String caName, String username)
    throws RAWorkerException;

    byte[] envelopeRevocation(X500Name issuer, BigInteger serial, int reason)
    throws RAWorkerException;

    byte[] envelopeRevocation(X509Certificate cert, int reason)
    throws RAWorkerException;

    CertIDOrError unrevokeCert(X500Name issuer, BigInteger serial)
    throws RAWorkerException, PKIErrorException;

    CertIDOrError unrevokeCert(X509Certificate cert)
    throws RAWorkerException, PKIErrorException;

    Map<String, CertIDOrError> unrevokeCerts(UnrevokeOrRemoveCertRequestType request)
    throws RAWorkerException, PKIErrorException;

    CertIDOrError removeCert(X500Name issuer, BigInteger serial)
    throws RAWorkerException, PKIErrorException;

    CertIDOrError removeCert(X509Certificate cert)
    throws RAWorkerException, PKIErrorException;

    Map<String, CertIDOrError> removeCerts(UnrevokeOrRemoveCertRequestType request)
    throws RAWorkerException, PKIErrorException;

    /**
     * Remove the expired certificates
     * @param caName
     * @param certProfile certificate profile name or 'all' for all certificate profiles
     * @param userLike user name pattern, or 'all' for all users, or {@code null} for those without user info
     * @param overlapSeconds
     */
    RemoveExpiredCertsResult removeExpiredCerts(String caName,
            String certProfile, String userLike, long overlapSeconds)
    throws RAWorkerException, PKIErrorException;

}
