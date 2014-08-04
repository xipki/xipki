/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
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
import org.xipki.ocsp.client.api.OCSPRequestor;
import org.xipki.ocsp.client.api.OCSPRequestorException;
import org.xipki.ocsp.client.api.OCSPResponseNotSuccessfullException;
import org.xipki.ocsp.client.api.RequestOptions;
import org.xipki.ocsp.client.impl.digest.SHA1DigestCalculator;
import org.xipki.ocsp.client.impl.digest.SHA224DigestCalculator;
import org.xipki.ocsp.client.impl.digest.SHA256DigestCalculator;
import org.xipki.ocsp.client.impl.digest.SHA384DigestCalculator;
import org.xipki.ocsp.client.impl.digest.SHA512DigestCalculator;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.NoIdleSignerException;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.common.IoCertUtil;

/**
 * @author Lijun Liao
 */

public abstract class AbstractOCSPRequestor implements OCSPRequestor
{
    private PasswordResolver passwordResolver;
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
    public BasicOCSPResp ask(X509Certificate caCert, X509Certificate cert, URL responderUrl,
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
    public BasicOCSPResp ask(X509Certificate caCert, BigInteger serialNumber, URL responderUrl,
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

        OCSPReq ocspReq = buildRequest(caCert, serialNumber, nonce,
                requestOptions);
        OCSPResp response;
        try
        {
            byte[] encodedReq = ocspReq.getEncoded();
            byte[] encodedResp = send(encodedReq, responderUrl, requestOptions);
            response = new OCSPResp(encodedResp);
        } catch (IOException e)
        {
            throw new OCSPRequestorException(e);
        }

        int statusCode = response.getStatus();
        if(statusCode == 0)
        {
            BasicOCSPResp basicOCSPResp;
            try
            {
                basicOCSPResp = (BasicOCSPResp) response.getResponseObject();
            } catch (OCSPException e)
            {
                throw new OCSPRequestorException(e);
            }
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

            return basicOCSPResp;
        }
        else
        {
            throw new OCSPResponseNotSuccessfullException(statusCode);
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
                                cert = IoCertUtil.parseCert(signerCertFile);
                            } catch (CertificateException e)
                            {
                                throw new OCSPRequestorException(
                                        "Could not parse certificate " + signerCertFile + ": " + e.getMessage());
                            }
                        }

                        try
                        {
                            signer = getSecurityFactory().createSigner(signerType, signerConf, cert, getPasswordResolver());
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

    public PasswordResolver getPasswordResolver()
    {
        return passwordResolver;
    }

    public void setPasswordResolver(PasswordResolver passwordResolver)
    {
        this.passwordResolver = passwordResolver;
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
