/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
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

package org.xipki.pki.ocsp.client.impl;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import javax.annotation.Nonnull;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.operator.DigestCalculator;
import org.xipki.commons.common.RequestResponseDebug;
import org.xipki.commons.common.RequestResponsePair;
import org.xipki.commons.common.util.CollectionUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.security.api.ConcurrentContentSigner;
import org.xipki.commons.security.api.HashAlgoType;
import org.xipki.commons.security.api.ObjectIdentifiers;
import org.xipki.commons.security.api.SecurityFactory;
import org.xipki.commons.security.api.SignerConf;
import org.xipki.commons.security.api.exception.NoIdleSignerException;
import org.xipki.commons.security.api.util.X509Util;
import org.xipki.pki.ocsp.client.api.InvalidOcspResponseException;
import org.xipki.pki.ocsp.client.api.OcspNonceUnmatchedException;
import org.xipki.pki.ocsp.client.api.OcspRequestor;
import org.xipki.pki.ocsp.client.api.OcspRequestorException;
import org.xipki.pki.ocsp.client.api.OcspResponseException;
import org.xipki.pki.ocsp.client.api.OcspTargetUnmatchedException;
import org.xipki.pki.ocsp.client.api.RequestOptions;
import org.xipki.pki.ocsp.client.api.ResponderUnreachableException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class AbstractOcspRequestor implements OcspRequestor {

    private SecurityFactory securityFactory;

    private final Object signerLock = new Object();

    private ConcurrentContentSigner signer;

    private String signerType;

    private String signerConf;

    private String signerCertFile;

    private SecureRandom random = new SecureRandom();

    protected AbstractOcspRequestor() {
    }

    protected abstract byte[] send(
            @Nonnull byte[] request,
            @Nonnull URL responderUrl,
            @Nonnull RequestOptions requestOptions)
    throws IOException;

    @Override
    public OCSPResp ask(
            final X509Certificate issuerCert,
            final X509Certificate cert,
            final URL responderUrl,
            final RequestOptions requestOptions,
            final RequestResponseDebug debug)
    throws OcspResponseException, OcspRequestorException {
        ParamUtil.requireNonNull("issuerCert", issuerCert);
        ParamUtil.requireNonNull("cert", cert);

        try {
            if (!X509Util.issues(issuerCert, cert)) {
                throw new IllegalArgumentException("cert and issuerCert do not match");
            }
        } catch (CertificateEncodingException ex) {
            throw new OcspRequestorException(ex.getMessage(), ex);
        }

        return ask(issuerCert, new BigInteger[]{cert.getSerialNumber()}, responderUrl,
                requestOptions, debug);
    }

    @Override
    public OCSPResp ask(
            final X509Certificate issuerCert,
            final X509Certificate[] certs,
            final URL responderUrl,
            final RequestOptions requestOptions,
            final RequestResponseDebug debug)
    throws OcspResponseException, OcspRequestorException {
        ParamUtil.requireNonNull("issuerCert", issuerCert);
        ParamUtil.requireNonNull("certs", certs);
        ParamUtil.requireMin("certs.length", certs.length, 1);

        BigInteger[] serialNumbers = new BigInteger[certs.length];
        for (int i = 0; i < certs.length; i++) {
            X509Certificate cert = certs[i];
            try {
                if (!X509Util.issues(issuerCert, cert)) {
                    throw new IllegalArgumentException(
                            "cert at index " + i + " and issuerCert do not match");
                }
            } catch (CertificateEncodingException ex) {
                throw new OcspRequestorException(ex.getMessage(), ex);
            }
            serialNumbers[i] = cert.getSerialNumber();
        }

        return ask(issuerCert, serialNumbers, responderUrl, requestOptions, debug);
    }

    @Override
    public OCSPResp ask(
            final X509Certificate issuerCert,
            final BigInteger serialNumber,
            final URL responderUrl,
            final RequestOptions requestOptions,
            final RequestResponseDebug debug)
    throws OcspResponseException, OcspRequestorException {
        return ask(issuerCert, new BigInteger[]{serialNumber}, responderUrl, requestOptions, debug);
    }

    @Override
    public OCSPResp ask(
            final X509Certificate issuerCert,
            final BigInteger[] serialNumbers,
            final URL responderUrl,
            final RequestOptions requestOptions,
            final RequestResponseDebug debug)
    throws OcspResponseException, OcspRequestorException {
        ParamUtil.requireNonNull("issuerCert", issuerCert);
        ParamUtil.requireNonNull("requestOptions", requestOptions);
        ParamUtil.requireNonNull("responderUrl", responderUrl);

        byte[] nonce = null;
        if (requestOptions.isUseNonce()) {
            nonce = nextNonce(requestOptions.getNonceLen());
        }

        OCSPReq ocspReq = buildRequest(issuerCert, serialNumbers, nonce, requestOptions);
        byte[] encodedReq;
        try {
            encodedReq = ocspReq.getEncoded();
        } catch (IOException ex) {
            throw new OcspRequestorException("could not encode OCSP request: " + ex.getMessage(),
                    ex);
        }

        RequestResponsePair msgPair = null;
        if (debug != null) {
            msgPair = new RequestResponsePair();
            debug.add(msgPair);
            msgPair.setRequest(encodedReq);
        }

        byte[] encodedResp;
        try {
            encodedResp = send(encodedReq, responderUrl, requestOptions);
        } catch (IOException ex) {
            throw new ResponderUnreachableException("IOException: " + ex.getMessage(), ex);
        }

        if (debug != null) {
            msgPair.setRequest(encodedResp);
        }

        OCSPResp ocspResp;
        try {
            ocspResp = new OCSPResp(encodedResp);
        } catch (IOException ex) {
            throw new InvalidOcspResponseException("IOException: " + ex.getMessage(), ex);
        }

        Object respObject;
        try {
            respObject = ocspResp.getResponseObject();
        } catch (OCSPException ex) {
            throw new InvalidOcspResponseException("responseObject is invalid");
        }

        if (ocspResp.getStatus() != 0) {
            return ocspResp;
        }

        if (!(respObject instanceof BasicOCSPResp)) {
            return ocspResp;
        }

        BasicOCSPResp basicOcspResp = (BasicOCSPResp) respObject;

        if (nonce != null) {
            Extension nonceExtn = basicOcspResp.getExtension(
                    OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            if (nonceExtn == null) {
                throw new OcspNonceUnmatchedException(nonce, null);
            }
            byte[] receivedNonce = nonceExtn.getExtnValue().getOctets();
            if (!Arrays.equals(nonce, receivedNonce)) {
                throw new OcspNonceUnmatchedException(nonce, receivedNonce);
            }
        }

        SingleResp[] singleResponses = basicOcspResp.getResponses();
        final int countSingleResponses = (singleResponses == null)
                ? 0
                : singleResponses.length;

        if (countSingleResponses != serialNumbers.length) {
            StringBuilder sb = new StringBuilder(100);
            sb.append("response with ").append(countSingleResponses).append(" singleRessponse");
            if (countSingleResponses > 1) {
                sb.append("s");
            }
            sb.append(" is returned, expected is ").append(serialNumbers.length);
            throw new OcspTargetUnmatchedException(sb.toString());
        }

        CertificateID certId = ocspReq.getRequestList()[0].getCertID();
        ASN1ObjectIdentifier issuerHashAlg = certId.getHashAlgOID();
        byte[] issuerKeyHash = certId.getIssuerKeyHash();
        byte[] issuerNameHash = certId.getIssuerNameHash();

        if (serialNumbers.length == 1) {
            SingleResp singleResp = singleResponses[0];
            CertificateID cid = singleResp.getCertID();
            boolean issuerMatch = issuerHashAlg.equals(cid.getHashAlgOID())
                    && Arrays.equals(issuerKeyHash, cid.getIssuerKeyHash())
                    && Arrays.equals(issuerNameHash, cid.getIssuerNameHash());

            if (!issuerMatch) {
                throw new OcspTargetUnmatchedException("the issuer is not requested");
            }

            BigInteger serialNumber = cid.getSerialNumber();
            if (!serialNumbers[0].equals(serialNumber)) {
                throw new OcspTargetUnmatchedException("the serialNumber is not requested");
            }
        } else {
            List<BigInteger> tmpSerials1 = Arrays.asList(serialNumbers);
            List<BigInteger> tmpSerials2 = new ArrayList<>(tmpSerials1);

            for (int i = 0; i < singleResponses.length; i++) {
                SingleResp singleResp = singleResponses[i];
                CertificateID cid = singleResp.getCertID();
                boolean issuerMatch = issuerHashAlg.equals(cid.getHashAlgOID())
                        && Arrays.equals(issuerKeyHash, cid.getIssuerKeyHash())
                        && Arrays.equals(issuerNameHash, cid.getIssuerNameHash());

                if (!issuerMatch) {
                    throw new OcspTargetUnmatchedException(
                            "the issuer specified in singleResponse[" + i + "] is not requested");
                }

                BigInteger serialNumber = cid.getSerialNumber();
                if (!tmpSerials2.remove(serialNumber)) {
                    if (tmpSerials1.contains(serialNumber)) {
                        throw new OcspTargetUnmatchedException("serialNumber " + serialNumber
                                + "is contained in at least two singleResponses");
                    } else {
                        throw new OcspTargetUnmatchedException(
                                "the serialNumber specified in singleResponse[" + i
                                + "] is not requested");
                    }
                }
            } // end for
        } // end if

        return ocspResp;
    } // method ask

    private OCSPReq buildRequest(
            final X509Certificate caCert,
            final BigInteger[] serialNumbers,
            final byte[] nonce,
            final RequestOptions requestOptions)
    throws OcspRequestorException {
        HashAlgoType hashAlgo = HashAlgoType.getHashAlgoType(requestOptions.getHashAlgorithmId());
        if (hashAlgo == null) {
            throw new OcspRequestorException("unknown HashAlgo "
                    + requestOptions.getHashAlgorithmId().getId());
        }
        List<AlgorithmIdentifier> prefSigAlgs = requestOptions.getPreferredSignatureAlgorithms();

        DigestCalculator digestCalculator;
        switch (hashAlgo) {
        case SHA1:
            digestCalculator = new SHA1DigestCalculator();
            break;
        case SHA224:
            digestCalculator = new SHA224DigestCalculator();
            break;
        case SHA256:
            digestCalculator = new SHA256DigestCalculator();
            break;
        case SHA384:
            digestCalculator = new SHA384DigestCalculator();
            break;
        case SHA512:
            digestCalculator = new SHA512DigestCalculator();
            break;
        default:
            throw new RuntimeException("unknown HashAlgoType: " + hashAlgo);
        }

        OCSPReqBuilder reqBuilder = new OCSPReqBuilder();
        List<Extension> extensions = new LinkedList<>();
        if (nonce != null) {
            Extension extn = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false,
                    new DEROctetString(nonce));
            extensions.add(extn);
        }

        if (prefSigAlgs != null && prefSigAlgs.size() > 0) {
            ASN1EncodableVector vec = new ASN1EncodableVector();
            for (AlgorithmIdentifier algId : prefSigAlgs) {
                ASN1Sequence prefSigAlgObj = new DERSequence(algId);
                vec.add(prefSigAlgObj);
            }

            ASN1Sequence extnValue = new DERSequence(vec);
            Extension extn;
            try {
                extn = new Extension(ObjectIdentifiers.id_pkix_ocsp_prefSigAlgs, false,
                        new DEROctetString(extnValue));
            } catch (IOException ex) {
                throw new OcspRequestorException(ex.getMessage(), ex);
            }
            extensions.add(extn);
        }

        if (CollectionUtil.isNonEmpty(extensions)) {
            reqBuilder.setRequestExtensions(
                    new Extensions(extensions.toArray(new Extension[0])));
        }

        try {
            for (BigInteger serialNumber : serialNumbers) {
                CertificateID certId = new CertificateID(
                        digestCalculator,
                        new X509CertificateHolder(caCert.getEncoded()),
                        serialNumber);

                reqBuilder.addRequest(certId);
            }

            if (requestOptions.isSignRequest()) {
                synchronized (signerLock) {
                    if (signer == null) {
                        if (StringUtil.isBlank(signerType)) {
                            throw new OcspRequestorException("signerType is not configured");
                        }

                        if (StringUtil.isBlank(signerConf)) {
                            throw new OcspRequestorException("signerConf is not configured");
                        }

                        X509Certificate cert = null;
                        if (StringUtil.isNotBlank(signerCertFile)) {
                            try {
                                cert = X509Util.parseCert(signerCertFile);
                            } catch (CertificateException ex) {
                                throw new OcspRequestorException("could not parse certificate "
                                        + signerCertFile + ": " + ex.getMessage());
                            }
                        }

                        try {
                            signer = getSecurityFactory().createSigner(signerType,
                                    new SignerConf(signerConf), cert);
                        } catch (Exception ex) {
                            throw new OcspRequestorException("could not create signer: "
                                    + ex.getMessage());
                        }
                    } // end if
                } // end synchronized

                reqBuilder.setRequestorName(signer.getCertificateAsBcObject().getSubject());
                try {
                    return signer.build(reqBuilder, signer.getCertificateChainAsBcObjects());
                } catch (NoIdleSignerException ex) {
                    throw new OcspRequestorException("NoIdleSignerException: " + ex.getMessage());
                }
            } else {
                return reqBuilder.build();
            } // end if
        } catch (OCSPException | CertificateEncodingException | IOException ex) {
            throw new OcspRequestorException(ex.getMessage(), ex);
        }
    } // method buildRequest

    private byte[] nextNonce(
            final int nonceLen) {
        byte[] nonce = new byte[nonceLen];
        random.nextBytes(nonce);
        return nonce;
    }

    public String getSignerConf() {
        return signerConf;
    }

    public void setSignerConf(
            final String signerConf) {
        this.signer = null;
        this.signerConf = signerConf;
    }

    public String getSignerCertFile() {
        return signerCertFile;
    }

    public void setSignerCertFile(
            final String signerCertFile) {
        if (StringUtil.isBlank(signerCertFile)) {
            return;
        }

        this.signer = null;
        this.signerCertFile = signerCertFile;
    }

    public String getSignerType() {
        return signerType;
    }

    public void setSignerType(
            final String signerType) {
        this.signer = null;
        this.signerType = ParamUtil.requireNonBlank("signerType", signerType);
    }

    public SecurityFactory getSecurityFactory() {
        return securityFactory;
    }

    public void setSecurityFactory(
            final SecurityFactory securityFactory) {
        this.securityFactory = securityFactory;
    }

}
