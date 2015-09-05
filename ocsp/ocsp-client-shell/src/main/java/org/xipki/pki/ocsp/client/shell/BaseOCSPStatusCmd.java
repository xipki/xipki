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

package org.xipki.pki.ocsp.client.shell;

import java.math.BigInteger;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.apache.karaf.shell.commands.Option;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.xipki.common.RequestResponseDebug;
import org.xipki.common.RequestResponsePair;
import org.xipki.common.util.IoUtil;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.pki.ocsp.client.api.OCSPRequestor;
import org.xipki.pki.ocsp.client.api.RequestOptions;
import org.xipki.security.api.util.X509Util;

/**
 * @author Lijun Liao
 */

public abstract class BaseOCSPStatusCmd extends AbstractOCSPStatusCmd
{
    @Option(name = "--resp-issuer",
            description = "certificate file of the responder's issuer")
    private String respIssuerFile;

    @Option(name = "--url",
            description = "OCSP responder URL")
    private String serverURL;

    @Option(name = "--req-out",
            description = "where to save the request")
    private String reqout;

    @Option(name = "--resp-out",
            description = "where to save the response")
    private String respout;

    @Option(name = "--serial", aliases = "-s",
            multiValued = true,
            description = "serial number\n"
                    + "(multi-valued)")
    private List<String> serialNumbers;

    @Option(name = "--cert", aliases = "-c",
            multiValued = true,
            description = "certificate\n"
                    + "(multi-valued)")
    private List<String> certFiles;

    @Option(name = "--verbose", aliases="-v",
            description = "show status verbosely")
    protected Boolean verbose = Boolean.FALSE;

    protected static final Map<ASN1ObjectIdentifier, String> extensionOidNameMap = new HashMap<>();
    static
    {
        extensionOidNameMap.put(OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff, "ArchiveCutoff");
        extensionOidNameMap.put(OCSPObjectIdentifiers.id_pkix_ocsp_crl, "CrlID");
        extensionOidNameMap.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, "Nonce");
        extensionOidNameMap.put(OCSPRequestor.id_pkix_ocsp_extendedRevoke, "ExtendedRevoke");
    }

    protected abstract void checkParameters(
            X509Certificate respIssuer,
            List<BigInteger> serialNumbers,
            Map<BigInteger, byte[]> encodedCerts)
    throws Exception;

    protected abstract Object processResponse(
            OCSPResp response,
            X509Certificate respIssuer,
            X509Certificate issuer,
            List<BigInteger> serialNumbers,
            Map<BigInteger, byte[]> encodedCerts)
    throws Exception;

    @Override
    protected final Object _doExecute()
    throws Exception
    {
        if(isEmpty(serialNumbers) && isEmpty(certFiles))
        {
            throw new IllegalCmdParamException("Neither serialNumbers nor certFiles is set");
        }

        X509Certificate issuerCert = X509Util.parseCert(issuerCertFile);

        Map<BigInteger, byte[]> encodedCerts = null;
        List<BigInteger> sns = new LinkedList<>();
        if(isNotEmpty(certFiles))
        {
            encodedCerts = new HashMap<>(certFiles.size());

            String ocspUrl = null;
            for(String certFile : certFiles)
            {
                byte[] encodedCert = IoUtil.read(certFile);
                X509Certificate cert = X509Util.parseCert(certFile);

                if(X509Util.issues(issuerCert, cert) == false)
                {
                    throw new IllegalCmdParamException("certificate " + certFile + " is not issued by the given issuer");
                }

                if(isBlank(serverURL))
                {
                    List<String> ocspUrls = X509Util.extractOCSPUrls(cert);
                    if(ocspUrls.size() > 0)
                    {
                        String url = ocspUrls.get(0);
                        if(ocspUrl != null && ocspUrl.equals(url) == false)
                        {
                            throw new IllegalCmdParamException(
                                    "given certificates have different OCSP responder URL in certificate");
                        } else
                        {
                            ocspUrl = url;
                        }
                    }
                }

                BigInteger sn = cert.getSerialNumber();
                sns.add(sn);
                encodedCerts.put(sn, encodedCert);
            }

            if(isBlank(serverURL))
            {
                serverURL = ocspUrl;
            }
        }
        else
        {
            for(String serialNumber : serialNumbers)
            {
                BigInteger sn = toBigInt(serialNumber);
                sns.add(sn);
            }
        }

        if(isBlank(serverURL))
        {
            throw new IllegalCmdParamException("could not get URL for the OCSP responder");
        }

        X509Certificate respIssuer  = null;
        if(respIssuerFile != null)
        {
            respIssuer = X509Util.parseCert(IoUtil.expandFilepath(respIssuerFile));
        }

        URL serverUrl = new URL(serverURL);

        RequestOptions options = getRequestOptions();

        checkParameters(respIssuer, sns, encodedCerts);

        boolean saveReq = isNotBlank(reqout);
        boolean saveResp = isNotBlank(respout);
        RequestResponseDebug debug = null;
        if(saveReq || saveResp)
        {
            debug = new RequestResponseDebug();
        }

        OCSPResp response;
        try
        {
            response = requestor.ask(issuerCert, sns.toArray(new BigInteger[0]), serverUrl,
                options, debug);
        }finally
        {
            if(debug != null && debug.size() > 0)
            {
                RequestResponsePair reqResp = debug.get(0);
                if(saveReq)
                {
                    byte[] bytes = reqResp.getRequest();
                    if(bytes != null)
                    {
                        IoUtil.save(reqout, bytes);
                    }
                }

                if(saveResp)
                {
                    byte[] bytes = reqResp.getResponse();
                    if(bytes != null)
                    {
                        IoUtil.save(respout, bytes);
                    }
                }
            }
        }

        return processResponse(response, respIssuer, issuerCert, sns, encodedCerts);
    }

}
