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

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
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
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.xipki.common.RequestResponseDebug;
import org.xipki.common.RequestResponsePair;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.pki.ocsp.client.api.InvalidOCSPResponseException;
import org.xipki.pki.ocsp.client.api.OCSPNonceUnmatchedException;
import org.xipki.pki.ocsp.client.api.OCSPRequestor;
import org.xipki.pki.ocsp.client.api.OCSPRequestorException;
import org.xipki.pki.ocsp.client.api.OCSPResponseException;
import org.xipki.pki.ocsp.client.api.OCSPTargetUnmatchedException;
import org.xipki.pki.ocsp.client.api.RequestOptions;
import org.xipki.pki.ocsp.client.api.ResponderUnreachableException;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.NoIdleSignerException;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.util.X509Util;

/**
 * @author Lijun Liao
 */

public abstract class AbstractOCSPRequestor implements OCSPRequestor {

    private SecurityFactory securityFactory;

    private final Object signerLock = new Object();

    private ConcurrentContentSigner signer;

    private String signerType;

    private String signerConf;

    private String signerCertFile;

    private SecureRandom random = new SecureRandom();

    protected abstract byte[] send(
            byte[] request,
            URL responderUrl,
            RequestOptions requestOptions)
    throws IOException;

    protected AbstractOCSPRequestor() {
    }

    @Override
    public OCSPResp ask(
            final X509Certificate issuerCert,
            final X509Certificate cert,
            final URL responderUrl,
            final RequestOptions requestOptions,
            final RequestResponseDebug debug)
    throws OCSPResponseException, OCSPRequestorException {
        try {
            if (!X509Util.issues(issuerCert, cert)) {
                throw new IllegalArgumentException("cert and issuerCert do not match");
            }
        } catch (CertificateEncodingException e) {
            throw new OCSPRequestorException(e.getMessage(), e);
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
    throws OCSPResponseException, OCSPRequestorException {
        BigInteger[] serialNumbers = new BigInteger[certs.length];
        for (int i = 0; i < certs.length; i++) {
            X509Certificate cert = certs[i];
            try {
                if (!X509Util.issues(issuerCert, cert)) {
                    throw new IllegalArgumentException(
                            "cert at index " + i + " and issuerCert do not match");
                }
            } catch (CertificateEncodingException e) {
                throw new OCSPRequestorException(e.getMessage(), e);
            }
            serialNumbers[i++] = cert.getSerialNumber();
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
    throws OCSPResponseException, OCSPRequestorException {
        return ask(issuerCert, new BigInteger[]{serialNumber}, responderUrl, requestOptions, debug);
    }

    @Override
    public OCSPResp ask(
            final X509Certificate issuerCert,
            final BigInteger[] serialNumbers,
            final URL responderUrl,
            final RequestOptions requestOptions,
            final RequestResponseDebug debug)
    throws OCSPResponseException, OCSPRequestorException {
        if (requestOptions == null) {
            throw new IllegalArgumentException("requestOptions could not be null");
        }

        byte[] nonce = null;
        if (requestOptions.isUseNonce()) {
            nonce = nextNonce(requestOptions.getNonceLen());
        }

        OCSPReq ocspReq = buildRequest(issuerCert, serialNumbers, nonce, requestOptions);
        byte[] encodedReq;
        try {
            encodedReq = ocspReq.getEncoded();
        } catch (IOException e) {
            throw new OCSPRequestorException("could not encode OCSP request: " + e.getMessage(), e);
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
        } catch (IOException e) {
            throw new ResponderUnreachableException("IOException: " + e.getMessage(), e);
        }

        if (debug != null) {
            msgPair.setRequest(encodedResp);
        }

        OCSPResp ocspResp;
        try {
            ocspResp = new OCSPResp(encodedResp);
        } catch (IOException e) {
            throw new InvalidOCSPResponseException("IOException: " + e.getMessage(), e);
        }

        Object respObject;
        try {
            respObject = ocspResp.getResponseObject();
        } catch (OCSPException e) {
            throw new InvalidOCSPResponseException("responseObject is invalid");
        }

        if (ocspResp.getStatus() != 0) {
            return ocspResp;
        }

        if (!(respObject instanceof BasicOCSPResp)) {
            return ocspResp;
        }

        BasicOCSPResp basicOCSPResp = (BasicOCSPResp) respObject;

        if (nonce != null) {
            Extension nonceExtn = basicOCSPResp.getExtension(
                    OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            if (nonceExtn == null) {
                throw new OCSPNonceUnmatchedException(nonce, null);
            }
            byte[] receivedNonce = nonceExtn.getExtnValue().getOctets();
            if (!Arrays.equals(nonce, receivedNonce)) {
                throw new OCSPNonceUnmatchedException(nonce, receivedNonce);
            }
        }

        SingleResp[] singleResponses = basicOCSPResp.getResponses();
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
            throw new OCSPTargetUnmatchedException(sb.toString());
        }

        CertificateID certID = ocspReq.getRequestList()[0].getCertID();
        ASN1ObjectIdentifier issuerHashAlg = certID.getHashAlgOID();
        byte[] issuerKeyHash = certID.getIssuerKeyHash();
        byte[] issuerNameHash = certID.getIssuerNameHash();

        if (serialNumbers.length == 1) {
            SingleResp m = singleResponses[0];
            CertificateID cid = m.getCertID();
            boolean issuerMatch = issuerHashAlg.equals(cid.getHashAlgOID())
                    && Arrays.equals(issuerKeyHash, cid.getIssuerKeyHash())
                    && Arrays.equals(issuerNameHash, cid.getIssuerNameHash());

            if (!issuerMatch) {
                throw new OCSPTargetUnmatchedException("the issuer is not requested");
            }

            BigInteger serialNumber = cid.getSerialNumber();
            if (!serialNumbers[0].equals(serialNumber)) {
                throw new OCSPTargetUnmatchedException("the serialNumber is not requested");
            }
        } else {
            List<BigInteger> tmpSerials1 = Arrays.asList(serialNumbers);
            List<BigInteger> tmpSerials2 = new ArrayList<>(tmpSerials1);

            for (int i = 0; i < singleResponses.length; i++) {
                SingleResp m = singleResponses[i];
                CertificateID cid = m.getCertID();
                boolean issuerMatch = issuerHashAlg.equals(cid.getHashAlgOID())
                        && Arrays.equals(issuerKeyHash, cid.getIssuerKeyHash())
                        && Arrays.equals(issuerNameHash, cid.getIssuerNameHash());

                if (!issuerMatch) {
                    throw new OCSPTargetUnmatchedException(
                            "the issuer specified in singleResponse[" + i + "] is not requested");
                }

                BigInteger serialNumber = cid.getSerialNumber();
                if (!tmpSerials2.remove(serialNumber)) {
                    if (tmpSerials1.contains(serialNumber)) {
                        throw new OCSPTargetUnmatchedException("serialNumber " + serialNumber
                                + "is contained in at least two singleResponses");
                    } else {
                        throw new OCSPTargetUnmatchedException(
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
    throws OCSPRequestorException {
        ASN1ObjectIdentifier hashAlgId = requestOptions.getHashAlgorithmId();
        List<AlgorithmIdentifier> prefSigAlgs = requestOptions.getPreferredSignatureAlgorithms();

        DigestCalculator digestCalculator;
        if (NISTObjectIdentifiers.id_sha224.equals(hashAlgId)) {
            digestCalculator = new SHA224DigestCalculator();
        } else if (NISTObjectIdentifiers.id_sha256.equals(hashAlgId)) {
            digestCalculator = new SHA256DigestCalculator();
        } else if (NISTObjectIdentifiers.id_sha384.equals(hashAlgId)) {
            digestCalculator = new SHA384DigestCalculator();
        } else if (NISTObjectIdentifiers.id_sha512.equals(hashAlgId)) {
            digestCalculator = new SHA512DigestCalculator();
        } else {
            digestCalculator = new SHA1DigestCalculator();
        }

        OCSPReqBuilder reqBuilder = new OCSPReqBuilder();
        List<Extension> extensions = new LinkedList<>();
        if (nonce != null) {
            Extension extn = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false,
                    new DEROctetString(nonce));
            extensions.add(extn);
        }

        if (prefSigAlgs != null && prefSigAlgs.size() > 0) {
            ASN1EncodableVector v = new ASN1EncodableVector();
            for (AlgorithmIdentifier algId : prefSigAlgs) {
                ASN1Sequence prefSigAlgObj = new DERSequence(algId);
                v.add(prefSigAlgObj);
            }

            ASN1Sequence extnValue = new DERSequence(v);
            Extension extn;
            try {
                extn = new Extension(id_pkix_ocsp_prefSigAlgs, false,
                        new DEROctetString(extnValue));
            } catch (IOException e) {
                throw new OCSPRequestorException(e.getMessage(), e);
            }
            extensions.add(extn);
        }

        if (CollectionUtil.isNotEmpty(extensions)) {
            reqBuilder.setRequestExtensions(
                    new Extensions(extensions.toArray(new Extension[0])));
        }

        try {
            for (BigInteger serialNumber : serialNumbers) {
                CertificateID certID = new CertificateID(
                        digestCalculator,
                        new X509CertificateHolder(caCert.getEncoded()),
                        serialNumber);

                reqBuilder.addRequest(certID);
            }

            if (requestOptions.isSignRequest()) {
                synchronized (signerLock) {
                    if (signer == null) {
                        if (StringUtil.isBlank(signerType)) {
                            throw new OCSPRequestorException("signerType is not configured");
                        }

                        if (StringUtil.isBlank(signerConf)) {
                            throw new OCSPRequestorException("signerConf is not configured");
                        }

                        X509Certificate cert = null;
                        if (StringUtil.isNotBlank(signerCertFile)) {
                            try {
                                cert = X509Util.parseCert(signerCertFile);
                            } catch (CertificateException e) {
                                throw new OCSPRequestorException("could not parse certificate "
                                        + signerCertFile + ": " + e.getMessage());
                            }
                        }

                        try {
                            signer = getSecurityFactory().createSigner(
                                    signerType, signerConf, cert);
                        } catch (Exception e) {
                            throw new OCSPRequestorException("could not create signer: "
                                    + e.getMessage());
                        }
                    } // end if
                } // end synchronized

                ContentSigner singleSigner;
                try {
                    singleSigner = signer.borrowContentSigner();
                } catch (NoIdleSignerException e) {
                    throw new OCSPRequestorException("NoIdleSignerException: " + e.getMessage());
                }

                reqBuilder.setRequestorName(signer.getCertificateAsBCObject().getSubject());
                try {
                    return reqBuilder.build(singleSigner, signer.getCertificateChainAsBCObjects());
                } finally {
                    signer.returnContentSigner(singleSigner);
                }
            } else {
                return reqBuilder.build();
            } // end if
        } catch (OCSPException | CertificateEncodingException | IOException e) {
            throw new OCSPRequestorException(e.getMessage(), e);
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
        this.signer = null;
        this.signerCertFile = signerCertFile;
    }

    public String getSignerType() {
        return signerType;
    }

    public void setSignerType(
            final String signerType) {
        this.signer = null;
        this.signerType = signerType;
    }

    public SecurityFactory getSecurityFactory() {
        return securityFactory;
    }

    public void setSecurityFactory(
            final SecurityFactory securityFactory) {
        this.securityFactory = securityFactory;
    }

}
