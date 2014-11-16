/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 Lijun Liao
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
import org.xipki.common.SecurityUtil;
import org.xipki.ocsp.client.api.OCSPRequestor;
import org.xipki.ocsp.client.api.OCSPRequestorException;
import org.xipki.ocsp.client.api.RequestOptions;
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
    public OCSPResp ask(X509Certificate caCert, X509Certificate cert, URL responderUrl,
            RequestOptions requestOptions)
    throws OCSPRequestorException
    {
        if(caCert.getSubjectX500Principal().equals(cert.getIssuerX500Principal()) == false)
        {
            throw new IllegalArgumentException("cert and caCert do not match");
        }

        return ask(caCert, cert.getSerialNumber(), responderUrl, requestOptions);
    }

    @Override
    public OCSPResp ask(X509Certificate caCert, BigInteger serialNumber, URL responderUrl,
            RequestOptions requestOptions)
    throws OCSPRequestorException
    {
        if(requestOptions == null)
        {
            throw new IllegalArgumentException("requestOptions could not be null");
        }

        byte[] nonce = null;
        if(requestOptions.isUseNonce())
        {
            nonce = nextNonce();
        }

        OCSPReq ocspReq = buildRequest(caCert, serialNumber, nonce, requestOptions);
        try
        {
            byte[] encodedReq = ocspReq.getEncoded();
            byte[] encodedResp = send(encodedReq, responderUrl, requestOptions);
            OCSPResp ocspResp = new OCSPResp(encodedResp);

            Object respObject = ocspResp.getResponseObject();
            if(ocspResp.getStatus() == 0 && respObject instanceof BasicOCSPResp)
            {
                BasicOCSPResp basicOCSPResp = (BasicOCSPResp) respObject;
                Extension nonceExtn = basicOCSPResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);

                if(nonce != null)
                {
                    if(nonceExtn == null)
                    {
                        throw new OCSPRequestorException("No nonce is contained in response");
                    }
                    if(Arrays.equals(nonce, nonceExtn.getExtnValue().getOctets()) == false)
                    {
                        throw new OCSPRequestorException("The nonce in response does not match the one in request");
                    }
                }
            }

            return ocspResp;
        } catch (IOException | OCSPException e)
        {
            throw new OCSPRequestorException(e);
        }
    }

    private OCSPReq buildRequest(X509Certificate caCert, BigInteger serialNumber, byte[] nonce,
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
                throw new OCSPRequestorException(e);
            }
            extensions.add(extn);
        }

        if(extensions.isEmpty() == false)
        {
            reqBuilder.setRequestExtensions(
                    new Extensions(extensions.toArray(new Extension[0])));
        }

        try
        {
            CertificateID certID = new CertificateID(
                    digestCalculator,
                    new X509CertificateHolder(caCert.getEncoded()),
                    serialNumber);

            reqBuilder.addRequest(certID);

            if(requestOptions.isSignRequest())
            {
                synchronized (signerLock)
                {
                    if(signer == null)
                    {
                        if(signerType == null || signerType.isEmpty())
                        {
                            throw new OCSPRequestorException("signerType is not configured");
                        }

                        if(signerConf == null || signerConf.isEmpty())
                        {
                            throw new OCSPRequestorException("signerConf is not configured");
                        }

                        X509Certificate cert = null;
                        if(signerCertFile != null && signerCertFile.isEmpty() == false)
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
            throw new OCSPRequestorException(e);
        }
    }

    private byte[] nextNonce()
    {
        byte[] nonce = new byte[20];
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
