/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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

package org.xipki.pki.ocsp.client.shell;

import java.math.BigInteger;
import java.net.URL;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.xipki.commons.common.RequestResponseDebug;
import org.xipki.commons.common.RequestResponsePair;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.console.karaf.IllegalCmdParamException;
import org.xipki.commons.console.karaf.completer.FilePathCompleter;
import org.xipki.commons.security.api.HashAlgoType;
import org.xipki.commons.security.api.IssuerHash;
import org.xipki.commons.security.api.ObjectIdentifiers;
import org.xipki.commons.security.api.util.X509Util;
import org.xipki.pki.ocsp.client.api.RequestOptions;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class BaseOcspStatusCommandSupport extends OcspStatusCommandSupport {

    protected static final Map<ASN1ObjectIdentifier, String> EXTENSION_OIDNAME_MAP
            = new HashMap<>();

    @Option(name = "--verbose", aliases = "-v",
            description = "show status verbosely")
    protected Boolean verbose = Boolean.FALSE;

    @Option(name = "--resp-issuer",
            description = "certificate file of the responder's issuer")
    @Completion(FilePathCompleter.class)
    private String respIssuerFile;

    @Option(name = "--url",
            description = "OCSP responder URL")
    private String serverUrl;

    @Option(name = "--req-out",
            description = "where to save the request")
    @Completion(FilePathCompleter.class)
    private String reqout;

    @Option(name = "--resp-out",
            description = "where to save the response")
    @Completion(FilePathCompleter.class)
    private String respout;

    @Option(name = "--serial", aliases = "-s",
            multiValued = true,
            description = "serial number\n"
                    + "(multi-valued)")
    private List<String> serialNumberList;

    @Option(name = "--cert", aliases = "-c",
            multiValued = true,
            description = "certificate\n"
                    + "(multi-valued)")
    @Completion(FilePathCompleter.class)
    private List<String> certFiles;

    static {
        EXTENSION_OIDNAME_MAP.put(OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff,
                "ArchiveCutoff");
        EXTENSION_OIDNAME_MAP.put(OCSPObjectIdentifiers.id_pkix_ocsp_crl, "CrlID");
        EXTENSION_OIDNAME_MAP.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, "Nonce");
        EXTENSION_OIDNAME_MAP.put(ObjectIdentifiers.id_pkix_ocsp_extendedRevoke,
                "ExtendedRevoke");
    }

    protected abstract void checkParameters(
            @Nullable X509Certificate respIssuer,
            @Nonnull List<BigInteger> serialNumbers,
            @Nullable Map<BigInteger, byte[]> encodedCerts)
    throws Exception;

    protected abstract Object processResponse(
            @Nonnull OCSPResp response,
            @Nullable X509Certificate respIssuer,
            @Nonnull IssuerHash issuerHash,
            @Nonnull List<BigInteger> serialNumbers,
            @Nullable Map<BigInteger, byte[]> encodedCerts)
    throws Exception;

    @Override
    protected final Object doExecute()
    throws Exception {
        if (isEmpty(serialNumberList) && isEmpty(certFiles)) {
            throw new IllegalCmdParamException("Neither serialNumbers nor certFiles is set");
        }

        X509Certificate issuerCert = X509Util.parseCert(issuerCertFile);

        Map<BigInteger, byte[]> encodedCerts = null;
        List<BigInteger> sns = new LinkedList<>();
        if (isNotEmpty(certFiles)) {
            encodedCerts = new HashMap<>(certFiles.size());

            String ocspUrl = null;
            for (String certFile : certFiles) {
                X509Certificate cert = X509Util.parseCert(certFile);

                if (!X509Util.issues(issuerCert, cert)) {
                    throw new IllegalCmdParamException(
                            "certificate " + certFile + " is not issued by the given issuer");
                }

                if (isBlank(serverUrl)) {
                    List<String> ocspUrls = extractOcspUrls(cert);
                    if (ocspUrls.size() > 0) {
                        String url = ocspUrls.get(0);
                        if (ocspUrl != null && !ocspUrl.equals(url)) {
                            throw new IllegalCmdParamException("given certificates have different"
                                    + " OCSP responder URL in certificate");
                        } else {
                            ocspUrl = url;
                        }
                    }
                } // end if

                BigInteger sn = cert.getSerialNumber();
                sns.add(sn);

                byte[] encodedCert = IoUtil.read(certFile);
                encodedCerts.put(sn, encodedCert);
            } // end for

            if (isBlank(serverUrl)) {
                serverUrl = ocspUrl;
            }
        } else {
            for (String serialNumber : serialNumberList) {
                BigInteger sn = toBigInt(serialNumber);
                sns.add(sn);
            }
        }

        if (isBlank(serverUrl)) {
            throw new IllegalCmdParamException("could not get URL for the OCSP responder");
        }

        X509Certificate respIssuer = null;
        if (respIssuerFile != null) {
            respIssuer = X509Util.parseCert(IoUtil.expandFilepath(respIssuerFile));
        }

        URL serverUrlObj = new URL(serverUrl);

        RequestOptions options = getRequestOptions();

        checkParameters(respIssuer, sns, encodedCerts);

        boolean saveReq = isNotBlank(reqout);
        boolean saveResp = isNotBlank(respout);
        RequestResponseDebug debug = null;
        if (saveReq || saveResp) {
            debug = new RequestResponseDebug();
        }

        IssuerHash issuerHash = new IssuerHash(
                HashAlgoType.getHashAlgoType(options.getHashAlgorithmId()),
                Certificate.getInstance(issuerCert.getEncoded()));
        OCSPResp response;
        try {
            response = requestor.ask(issuerCert, sns.toArray(new BigInteger[0]), serverUrlObj,
                options, debug);
        } finally {
            if (debug != null && debug.size() > 0) {
                RequestResponsePair reqResp = debug.get(0);
                if (saveReq) {
                    byte[] bytes = reqResp.getRequest();
                    if (bytes != null) {
                        IoUtil.save(reqout, bytes);
                    }
                }

                if (saveResp) {
                    byte[] bytes = reqResp.getResponse();
                    if (bytes != null) {
                        IoUtil.save(respout, bytes);
                    }
                }
            } // end if
        } // end finally

        return processResponse(response, respIssuer, issuerHash, sns, encodedCerts);
    } // method doExecute

    public static List<String> extractOcspUrls(
            final X509Certificate cert)
    throws CertificateEncodingException {
        byte[] extValue = X509Util.getCoreExtValue(cert, Extension.authorityInfoAccess);
        if (extValue == null) {
            return Collections.emptyList();
        }

        AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(extValue);

        AccessDescription[] accessDescriptions = aia.getAccessDescriptions();
        List<AccessDescription> ocspAccessDescriptions = new LinkedList<>();
        for (AccessDescription accessDescription : accessDescriptions) {
            if (accessDescription.getAccessMethod().equals(X509ObjectIdentifiers.id_ad_ocsp)) {
                ocspAccessDescriptions.add(accessDescription);
            }
        }

        final int n = ocspAccessDescriptions.size();
        List<String> ocspUris = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            GeneralName accessLocation = ocspAccessDescriptions.get(i).getAccessLocation();
            if (accessLocation.getTagNo() == GeneralName.uniformResourceIdentifier) {
                String ocspUri = ((ASN1String) accessLocation.getName()).getString();
                ocspUris.add(ocspUri);
            }
        }

        return ocspUris;
    }

}
