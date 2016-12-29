/*
 *
 * Copyright (c) 2013 - 2016 Lijun Liao
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

package org.xipki.pki.ca.client.api;

import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.eclipse.jdt.annotation.NonNull;
import org.eclipse.jdt.annotation.Nullable;
import org.xipki.commons.common.HealthCheckResult;
import org.xipki.commons.common.RequestResponseDebug;
import org.xipki.pki.ca.client.api.dto.EnrollCertRequest;
import org.xipki.pki.ca.client.api.dto.RevokeCertRequest;
import org.xipki.pki.ca.client.api.dto.UnrevokeOrRemoveCertRequest;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public interface CaClient {

    Set<String> getCaNames();

    Set<CertprofileInfo> getCertprofiles(@NonNull String caName) throws CaClientException;

    EnrollCertResult requestCert(@Nullable String caName, @NonNull CertificationRequest csr,
            @NonNull String profile, @Nullable String username, @Nullable Date notBefore,
            @Nullable Date notAfter, @Nullable RequestResponseDebug debug)
    throws CaClientException, PkiErrorException;

    EnrollCertResult requestCerts(@Nullable String caName, @NonNull EnrollCertRequest request,
            @Nullable String username, @Nullable RequestResponseDebug debug)
    throws CaClientException, PkiErrorException;

    CertIdOrError revokeCert(@Nullable String caName, @NonNull BigInteger serial, int reason,
            @Nullable Date invalidityTime, @Nullable RequestResponseDebug debug)
    throws CaClientException, PkiErrorException;

    CertIdOrError revokeCert(@Nullable String caName, @NonNull X509Certificate cert, int reason,
            @Nullable Date invalidityTime, @Nullable RequestResponseDebug debug)
    throws CaClientException, PkiErrorException;

    Map<String, CertIdOrError> revokeCerts(@NonNull RevokeCertRequest request,
            @Nullable RequestResponseDebug debug) throws CaClientException, PkiErrorException;

    X509CRL downloadCrl(@NonNull String caName, @Nullable RequestResponseDebug debug)
    throws CaClientException, PkiErrorException;

    X509CRL downloadCrl(@NonNull String caName, @Nullable BigInteger crlNumber,
            @Nullable RequestResponseDebug debug) throws CaClientException, PkiErrorException;

    X509CRL generateCrl(@NonNull String caName, @Nullable RequestResponseDebug debug)
    throws CaClientException, PkiErrorException;

    String getCaNameByIssuer(@NonNull X500Name issuer) throws CaClientException;

    byte[] envelope(@NonNull CertRequest certRequest, @NonNull ProofOfPossession popo,
            @NonNull String profileName, @Nullable String caName, @Nullable String username)
    throws CaClientException;

    byte[] envelopeRevocation(@NonNull X500Name issuer, @NonNull BigInteger serial, int reason)
    throws CaClientException;

    byte[] envelopeRevocation(@NonNull X509Certificate cert, int reason) throws CaClientException;

    CertIdOrError unrevokeCert(@Nullable String caName, @NonNull BigInteger serial,
            @Nullable RequestResponseDebug debug) throws CaClientException, PkiErrorException;

    CertIdOrError unrevokeCert(@Nullable String caName, @NonNull X509Certificate cert,
            @Nullable RequestResponseDebug debug) throws CaClientException, PkiErrorException;

    Map<String, CertIdOrError> unrevokeCerts(@NonNull UnrevokeOrRemoveCertRequest request,
            @Nullable RequestResponseDebug debug) throws CaClientException, PkiErrorException;

    CertIdOrError removeCert(@Nullable String caName, @NonNull BigInteger serial,
            @Nullable RequestResponseDebug debug)
    throws CaClientException, PkiErrorException;

    CertIdOrError removeCert(@Nullable String caName, @NonNull X509Certificate cert,
            @Nullable RequestResponseDebug debug) throws CaClientException, PkiErrorException;

    Map<String, CertIdOrError> removeCerts(@NonNull UnrevokeOrRemoveCertRequest request,
            @Nullable RequestResponseDebug debug)
    throws CaClientException, PkiErrorException;

    HealthCheckResult getHealthCheckResult(@NonNull String caName) throws CaClientException;

}
