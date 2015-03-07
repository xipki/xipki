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

package org.xipki.ocsp.client.impl;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
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
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.xipki.common.CollectionUtil;
import org.xipki.common.RequestResponseDebug;
import org.xipki.common.RequestResponsePair;
import org.xipki.common.SecurityUtil;
import org.xipki.common.StringUtil;
import org.xipki.ocsp.client.api.InvalidOCSPResponseException;
import org.xipki.ocsp.client.api.OCSPNonceUnmatchedException;
import org.xipki.ocsp.client.api.OCSPRequestor;
import org.xipki.ocsp.client.api.OCSPRequestorException;
import org.xipki.ocsp.client.api.OCSPResponseException;
import org.xipki.ocsp.client.api.RequestOptions;
import org.xipki.ocsp.client.api.ResponderUnreachableException;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.NoIdleSignerException;
import org.xipki.security.api.SecurityFactory;

/**
 * @author Lijun Liao
 */

public abstract class AbstractOCSPRequestor implements OCSPRequestor
{
    private SecurityFactory securityFactory;

    private final Object signerLock = new Object();
    private ConcurrentContentSigner signer;
    private String signerType;
    private String signerConf;
    private String signerCertFile;

    private SecureRandom random = new SecureRandom();

    protected abstract byte[] send(byte[] request, URL responderUrl, RequestOptions requestOptions)
    throws IOException;

    protected AbstractOCSPRequestor()
    {
    }

    @Override
    public OCSPResp ask(X509Certificate issuerCert, X509Certificate cert, URL responderUrl,
            RequestOptions requestOptions, RequestResponseDebug debug)
    throws OCSPResponseException, OCSPRequestorException
    {
        try
        {
            if(SecurityUtil.issues(issuerCert, cert) == false)
            {
                throw new IllegalArgumentException("cert and issuerCert do not match");
            }
        } catch (CertificateEncodingException e)
        {
            throw new OCSPRequestorException(e.getMessage(), e);
        }

        return ask(issuerCert, new BigInteger[]{cert.getSerialNumber()}, responderUrl, requestOptions, debug);
    }

    @Override
    public OCSPResp ask(X509Certificate issuerCert, X509Certificate[] certs, URL responderUrl,
            RequestOptions requestOptions, RequestResponseDebug debug)
    throws OCSPResponseException, OCSPRequestorException
    {
        BigInteger[] serialNumbers = new BigInteger[certs.length];
        for(int i = 0; i < certs.length; i++)
        {
            X509Certificate cert = certs[i];
            try
            {
                if(SecurityUtil.issues(issuerCert, cert) == false)
                {
                    throw new IllegalArgumentException("cert at index " + i + " and issuerCert do not match");
                }
            } catch (CertificateEncodingException e)
            {
                throw new OCSPRequestorException(e.getMessage(), e);
            }
            serialNumbers[i++] = cert.getSerialNumber();
        }

        return ask(issuerCert, serialNumbers, responderUrl, requestOptions, debug);
    }

    @Override
    public OCSPResp ask(X509Certificate issuerCert, BigInteger serialNumber, URL responderUrl,
            RequestOptions requestOptions, RequestResponseDebug debug)
    throws OCSPResponseException, OCSPRequestorException
    {
        return ask(issuerCert, new BigInteger[]{serialNumber}, responderUrl, requestOptions, debug);
    }

    @Override
    public OCSPResp ask(X509Certificate issuerCert, BigInteger[] serialNumbers, URL responderUrl,
            RequestOptions requestOptions, RequestResponseDebug debug)
    throws OCSPResponseException, OCSPRequestorException
    {
        if(requestOptions == null)
        {
            throw new IllegalArgumentException("requestOptions could not be null");
        }

        byte[] nonce = null;
        if(requestOptions.isUseNonce())
        {
            nonce = nextNonce(requestOptions.getNonceLen());
        }

        OCSPReq ocspReq = buildRequest(issuerCert, serialNumbers, nonce, requestOptions);
        byte[] encodedReq;
        try
        {
            encodedReq = ocspReq.getEncoded();
        } catch (IOException e)
        {
            throw new OCSPRequestorException("could not encode OCSP request: " + e.getMessage(), e);
        }

        RequestResponsePair msgPair = null;
        if(debug != null)
        {
            msgPair = new RequestResponsePair();
            debug.add(msgPair);
            msgPair.setRequest(encodedReq);
        }

        byte[] encodedResp;
        try
        {
            encodedResp = send(encodedReq, responderUrl, requestOptions);
        } catch (IOException e)
        {
            throw new ResponderUnreachableException("IOException: " + e.getMessage(), e);
        }

        if(debug != null)
        {
            msgPair.setRequest(encodedResp);
        }

        OCSPResp ocspResp;
        try
        {
            ocspResp = new OCSPResp(encodedResp);
        } catch (IOException e)
        {
            throw new InvalidOCSPResponseException("IOException: " + e.getMessage(), e);
        }

        Object respObject;
        try
        {
            respObject = ocspResp.getResponseObject();
        } catch (OCSPException e)
        {
            throw new InvalidOCSPResponseException("responseObject is invalid");
        }

        if(ocspResp.getStatus() != 0)
        {
            return ocspResp;
        }

        if(respObject instanceof BasicOCSPResp == false)
        {
            return ocspResp;
        }

        BasicOCSPResp basicOCSPResp = (BasicOCSPResp) respObject;
        Extension nonceExtn = basicOCSPResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);

        if(nonce != null)
        {
            if(nonceExtn == null)
            {
                throw new OCSPNonceUnmatchedException(nonce, null);
            }
            byte[] receivedNonce = nonceExtn.getExtnValue().getOctets();
            if(Arrays.equals(nonce, receivedNonce) == false)
            {
                throw new OCSPNonceUnmatchedException(nonce, receivedNonce);
            }
        }

        return ocspResp;
    }

    private OCSPReq buildRequest(X509Certificate caCert, BigInteger[] serialNumbers, byte[] nonce,
            RequestOptions requestOptions)
    throws OCSPRequestorException
    {
        ASN1ObjectIdentifier hashAlgId = requestOptions.getHashAlgorithmId();
        List<AlgorithmIdentifier> prefSigAlgs = requestOptions.getPreferredSignatureAlgorithms();

        DigestCalculator digestCalculator;
        if(NISTObjectIdentifiers.id_sha224.equals(hashAlgId))
        {
            digestCalculator = new SHA224DigestCalculator();
        }
        else if(NISTObjectIdentifiers.id_sha256.equals(hashAlgId))
        {
            digestCalculator = new SHA256DigestCalculator();
        }
        else if(NISTObjectIdentifiers.id_sha384.equals(hashAlgId))
        {
            digestCalculator = new SHA384DigestCalculator();
        }
        else if(NISTObjectIdentifiers.id_sha512.equals(hashAlgId))
        {
            digestCalculator = new SHA512DigestCalculator();
        }
        else
        {
            digestCalculator = new SHA1DigestCalculator();
        }

        OCSPReqBuilder reqBuilder = new OCSPReqBuilder();
        List<Extension> extensions = new LinkedList<>();
        if(nonce != null)
        {
            Extension extn = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false,
                    new DEROctetString(nonce));
            extensions.add(extn);
        }

        if(prefSigAlgs != null && prefSigAlgs.size() > 0)
        {
            ASN1EncodableVector v = new ASN1EncodableVector();
            for(AlgorithmIdentifier algId : prefSigAlgs)
            {
                ASN1Sequence prefSigAlgObj = new DERSequence(algId);
                v.add(prefSigAlgObj);
            }

            ASN1Sequence extnValue = new DERSequence(v);
            Extension extn;
            try
            {
                extn = new Extension(id_pkix_ocsp_prefSigAlgs, false, new DEROctetString(extnValue));
            } catch (IOException e)
            {
                throw new OCSPRequestorException(e.getMessage(), e);
            }
            extensions.add(extn);
        }

        if(CollectionUtil.isNotEmpty(extensions))
        {
            reqBuilder.setRequestExtensions(
                    new Extensions(extensions.toArray(new Extension[0])));
        }

        try
        {
            for(BigInteger serialNumber : serialNumbers)
            {
                CertificateID certID = new CertificateID(
                        digestCalculator,
                        new X509CertificateHolder(caCert.getEncoded()),
                        serialNumber);

                reqBuilder.addRequest(certID);
            }

            if(requestOptions.isSignRequest())
            {
                synchronized (signerLock)
                {
                    if(signer == null)
                    {
                        if(StringUtil.isBlank(signerType))
                        {
                            throw new OCSPRequestorException("signerType is not configured");
                        }

                        if(StringUtil.isBlank(signerConf))
                        {
                            throw new OCSPRequestorException("signerConf is not configured");
                        }

                        X509Certificate cert = null;
                        if(StringUtil.isNotBlank(signerCertFile))
                        {
                            try
                            {
                                cert = SecurityUtil.parseCert(signerCertFile);
                            } catch (CertificateException e)
                            {
                                throw new OCSPRequestorException(
                                        "Could not parse certificate " + signerCertFile + ": " + e.getMessage());
                            }
                        }

                        try
                        {
                            signer = getSecurityFactory().createSigner(signerType, signerConf, cert);
                        } catch (Exception e)
                        {
                            throw new OCSPRequestorException("Could not create signer: " + e.getMessage());
                        }
                    }
                }

                ContentSigner singleSigner;
                try
                {
                    singleSigner = signer.borrowContentSigner();
                } catch (NoIdleSignerException e)
                {
                    throw new OCSPRequestorException("NoIdleSignerException: " + e.getMessage());
                }

                reqBuilder.setRequestorName(signer.getCertificateAsBCObject().getSubject());
                try
                {
                    return reqBuilder.build(singleSigner, signer.getCertificateChainAsBCObjects());
                }finally
                {
                    signer.returnContentSigner(singleSigner);
                }
            }
            else
            {
                return reqBuilder.build();
            }
        } catch (OCSPException | CertificateEncodingException | IOException e)
        {
            throw new OCSPRequestorException(e.getMessage(), e);
        }
    }

    private byte[] nextNonce(int nonceLen)
    {
        byte[] nonce = new byte[nonceLen];
        random.nextBytes(nonce);
        return nonce;
    }

    public String getSignerConf()
    {
        return signerConf;
    }

    public void setSignerConf(String signerConf)
    {
        this.signer = null;
        this.signerConf = signerConf;
    }

    public String getSignerCertFile()
    {
        return signerCertFile;
    }

    public void setSignerCertFile(String signerCertFile)
    {
        this.signer = null;
        this.signerCertFile = signerCertFile;
    }

    public String getSignerType()
    {
        return signerType;
    }

    public void setSignerType(String signerType)
    {
        this.signer = null;
        this.signerType = signerType;
    }

    public SecurityFactory getSecurityFactory()
    {
        return securityFactory;
    }

    public void setSecurityFactory(SecurityFactory securityFactory)
    {
        this.securityFactory = securityFactory;
    }

}
