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

package org.xipki.pki.ocsp.client.api;

import java.math.BigInteger;
import java.net.URL;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.xipki.common.RequestResponseDebug;

/**
 * @author Lijun Liao
 */

public interface OCSPRequestor
{
    ASN1ObjectIdentifier id_pkix_ocsp_prefSigAlgs
            = OCSPObjectIdentifiers.id_pkix_ocsp.branch("8");
    ASN1ObjectIdentifier id_pkix_ocsp_extendedRevoke
            = OCSPObjectIdentifiers.id_pkix_ocsp.branch("9");

    OCSPResp ask(
            X509Certificate issuerCert,
            X509Certificate cert,
            URL responderUrl,
            RequestOptions requestOptions,
            RequestResponseDebug debug)
    throws OCSPResponseException, OCSPRequestorException;

    OCSPResp ask(
            X509Certificate issuerCert,
            X509Certificate[] certs,
            URL responderUrl,
            RequestOptions requestOptions,
            RequestResponseDebug debug)
    throws OCSPResponseException, OCSPRequestorException;

    OCSPResp ask(
            X509Certificate issuerCert,
            BigInteger serialNumber,
            URL responderUrl,
            RequestOptions requestOptions,
            RequestResponseDebug debug)
    throws OCSPResponseException, OCSPRequestorException;

    OCSPResp ask(
            X509Certificate issuerCert,
            BigInteger[] serialNumbers,
            URL responderUrl,
            RequestOptions requestOptions,
            RequestResponseDebug debug)
    throws OCSPResponseException, OCSPRequestorException;

}
