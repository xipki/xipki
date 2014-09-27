/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.client.impl;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.SchemaFactory;

import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.client.api.RAWorker;
import org.xipki.ca.client.impl.jaxb.CAClientType;
import org.xipki.ca.client.impl.jaxb.CAType;
import org.xipki.ca.client.impl.jaxb.FileOrValueType;
import org.xipki.ca.client.impl.jaxb.ObjectFactory;
import org.xipki.ca.client.impl.jaxb.RequestorType;
import org.xipki.ca.cmp.client.AbstractRAWorker;
import org.xipki.ca.cmp.client.CmpRequestorException;
import org.xipki.ca.cmp.client.type.CRLResultType;
import org.xipki.ca.cmp.client.type.CmpResultType;
import org.xipki.ca.cmp.client.type.EnrollCertEntryType;
import org.xipki.ca.cmp.client.type.EnrollCertRequestEntryType;
import org.xipki.ca.cmp.client.type.EnrollCertRequestType;
import org.xipki.ca.cmp.client.type.EnrollCertResultType;
import org.xipki.ca.cmp.client.type.ErrorResultEntryType;
import org.xipki.ca.cmp.client.type.ErrorResultType;
import org.xipki.ca.cmp.client.type.IssuerSerialEntryType;
import org.xipki.ca.cmp.client.type.ResultEntryType;
import org.xipki.ca.cmp.client.type.RevokeCertRequestEntryType;
import org.xipki.ca.cmp.client.type.RevokeCertRequestType;
import org.xipki.ca.cmp.client.type.RevokeCertResultEntryType;
import org.xipki.ca.cmp.client.type.RevokeCertResultType;
import org.xipki.ca.cmp.client.type.UnrevokeOrRemoveCertRequestType;
import org.xipki.ca.common.CertIDOrError;
import org.xipki.ca.common.EnrollCertResult;
import org.xipki.ca.common.PKIErrorException;
import org.xipki.ca.common.RAWorkerException;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.SignerException;
import org.xipki.security.common.ConfigurationException;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.LogUtil;
import org.xipki.security.common.ParamChecker;
import org.xml.sax.SAXException;

/**
 * @author Lijun Liao
 */

public final class RAWorkerImpl extends AbstractRAWorker implements RAWorker
{
    private static final Logger LOG = LoggerFactory.getLogger(RAWorkerImpl.class);

    private static Object jaxbUnmarshallerLock = new Object();
    private static Unmarshaller jaxbUnmarshaller;

    private final Map<String, CAConf> casMap = new HashMap<>();
    private final Map<String, X509CmpRequestor> cmpRequestorsMap = new ConcurrentHashMap<>();

    private String confFile;
    private Map<X509Certificate, Boolean> tryXipkiNSStoVerifyMap = new ConcurrentHashMap<>();

    public RAWorkerImpl()
    {
    }

    public void init()
    throws ConfigurationException, IOException
    {
        ParamChecker.assertNotNull("confFile", confFile);
        ParamChecker.assertNotNull("securityFactory", securityFactory);

        if(Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        CAClientType config;
        File configFile = new File(IoCertUtil.expandFilepath(confFile));
        if(configFile.exists())
        {
            if(confFile.endsWith(".properties"))
            {
                config = LegacyConfConverter.convertConf(new FileInputStream(configFile));
            } else
            {
                config = parse(new FileInputStream(configFile));
            }
        }
        else if(confFile.endsWith(".properties") == false)
        {
            // consider the legacy software
            int idx = confFile.lastIndexOf('.');
            String fn = confFile.substring(0, idx) + ".properties";
            configFile = new File(fn);
            if(configFile.exists())
            {
                config = LegacyConfConverter.convertConf(fn);
            } else
            {
                throw new FileNotFoundException("Cound not find configuration file " + confFile);
            }
        }
        else
        {
            throw new FileNotFoundException("Cound not find configuration file " + confFile);
        }

        int numActiveCAs = 0;

        for(CAType caType : config.getCAs().getCA())
        {
            if(caType.isEnabled() == false)
            {
                LOG.info("CA " + caType.getName() + " is disabled");
                continue;
            }
            numActiveCAs++;
        }

        if(numActiveCAs == 0)
        {
            LOG.warn("No active CA configured");
        }

        Boolean b = config.isDevMode();
        boolean devMode = b != null && b.booleanValue();

        // CA
        Set<String> configuredCaNames = new HashSet<>();

        Set<CAConf> cas = new HashSet<>();
        for(CAType caType : config.getCAs().getCA())
        {
            b = caType.isEnabled();
            if(b.booleanValue() == false)
            {
                continue;
            }

            String caName = caType.getName();
            try
            {
                CAConf ca = new CAConf(caName,
                        caType.getUrl(),
                        IoCertUtil.parseCert(readData(caType.getCert())),
                        caType.getCertProfiles().getCertProfile(),
                        IoCertUtil.parseCert(readData(caType.getResponder())));
                cas.add(ca);

                configuredCaNames.add(caName);
            }catch(IOException | CertificateException e)
            {
                final String message = "Could not configure CA " + caName;
                if(LOG.isWarnEnabled())
                {
                    LOG.warn(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                }
                LOG.debug(message, e);

                if(devMode == false)
                {
                    throw new ConfigurationException(e);
                }
            }
        }

        // requestor
        X509Certificate requestorCert = null;
        RequestorType requestorConf = config.getRequestor();
        if(requestorConf.getCert() != null)
        {
            try
            {
                requestorCert = IoCertUtil.parseCert(readData(requestorConf.getCert()));
            } catch (Exception e)
            {
                throw new ConfigurationException(e);
            }
        }

        // ------------------------------------------------
        ConcurrentContentSigner requestorSigner = null;
        if(requestorConf.getSignerType() != null)
        {
            try
            {
                requestorSigner = securityFactory.createSigner(
                        requestorConf.getSignerType(), requestorConf.getSignerConf(), requestorCert);
            } catch (SignerException e)
            {
                throw new ConfigurationException(e);
            }
        } else
        {
            if(requestorConf.isSignRequest())
            {
                throw new ConfigurationException("Signer of requestor must be configured");
            }
            else if(requestorCert == null)
            {
                throw new ConfigurationException("At least one of certificate and signer of requestor must be configured");
            }
        }

        for(CAConf ca :cas)
        {
            if(null != this.casMap.put(ca.getName(), ca))
            {
                throw new IllegalArgumentException("duplicate CAs with the same name " + ca.getName());
            }

            X509CmpRequestor cmpRequestor;
            if(requestorSigner != null)
            {
                cmpRequestor = new DefaultHttpCmpRequestor(
                        requestorSigner, ca.getResponder(), ca.getCert(), ca.getUrl(),
                        securityFactory, requestorConf.isSignRequest());
            } else
            {
                cmpRequestor = new DefaultHttpCmpRequestor(
                        requestorCert, ca.getResponder(), ca.getCert(), ca.getUrl(),
                        securityFactory);
            }

            cmpRequestorsMap.put(ca.getName(), cmpRequestor);
        }
    }

    private static byte[] readData(FileOrValueType fileOrValue)
    throws IOException
    {
        byte[] data = fileOrValue.getValue();
        if(data == null)
        {
            data = IoCertUtil.read(fileOrValue.getFile());
        }
        return data;
    }

    @Override
    public EnrollCertResult requestCert(CertificationRequest p10Request, String profile, String caName,
            String username)
    throws RAWorkerException, PKIErrorException
    {
        EnrollCertEntryType entry = new EnrollCertEntryType(p10Request, profile);
        Map<String, EnrollCertEntryType> entries = new HashMap<>();

        final String id = "p10-1";
        entries.put(id, entry);
        return requestCerts(EnrollCertRequestType.Type.CERT_REQ, entries, caName, username);
    }

    @Override
    public EnrollCertResult requestCerts(EnrollCertRequestType.Type type,
            Map<String, EnrollCertEntryType> enrollCertEntries,
            String caName, String username)
    throws RAWorkerException, PKIErrorException
    {
        ParamChecker.assertNotNull("enrollCertEntries", enrollCertEntries);

        if(enrollCertEntries.isEmpty())
        {
            return null;
        }

        EnrollCertRequestType enrollCertRequest = new EnrollCertRequestType(type);

        for(String id : enrollCertEntries.keySet())
        {
            EnrollCertEntryType entry = enrollCertEntries.get(id);

            CertTemplateBuilder certTempBuilder = new CertTemplateBuilder();

            CertificationRequestInfo p10ReqInfo = entry.getP10Request().getCertificationRequestInfo();
            certTempBuilder.setPublicKey(p10ReqInfo.getSubjectPublicKeyInfo());
            certTempBuilder.setSubject(p10ReqInfo.getSubject());

            CertTemplate certTemplate = certTempBuilder.build();
            CertRequest certReq = new CertRequest(1, certTemplate, null);

            EnrollCertRequestEntryType requestEntry = new EnrollCertRequestEntryType(
                    id, entry.getProfile(), certReq, raVerified);
            enrollCertRequest.addRequestEntry(requestEntry);
        }

        return requestCerts(enrollCertRequest, caName, username);
    }

    @Override
    public EnrollCertResult requestCerts(EnrollCertRequestType request, String caName, String username)
    throws RAWorkerException, PKIErrorException
    {
        ParamChecker.assertNotNull("request", request);

        List<EnrollCertRequestEntryType> requestEntries = request.getRequestEntries();
        if(requestEntries.isEmpty())
        {
            return null;
        }

        boolean b = (caName != null);
        if(caName == null)
        {
            // detect the CA name
            String profile = requestEntries.get(0).getCertProfile();
            caName = getCANameForProfile(profile);
            if(caName == null)
            {
                throw new RAWorkerException("CertProfile " + profile + " is not supported by any CA");
            }
        }

        if(b || request.getRequestEntries().size() > 1)
        {
            // make sure that all requests are targeted on the same CA
            for(EnrollCertRequestEntryType entry : request.getRequestEntries())
            {
                String profile = entry.getCertProfile();
                checkCertProfileSupportInCA(profile, caName);
            }
        }

        X509CmpRequestor cmpRequestor = cmpRequestorsMap.get(caName);
        if(cmpRequestor == null)
        {
            throw new RAWorkerException("could not find CA named " + caName);
        }

        CmpResultType result;
        try
        {
            result = cmpRequestor.requestCertificate(request, username);
        } catch (CmpRequestorException e)
        {
            throw new RAWorkerException(e);
        }

        if(result instanceof ErrorResultType)
        {
            throw createPKIErrorException((ErrorResultType) result);
        }
        else if(result instanceof EnrollCertResultType)
        {
            return parseEnrollCertResult((EnrollCertResultType) result, caName);
        }
        else
        {
            throw new RuntimeException("Unknown result type: " + result.getClass().getName());
        }
    }

    private void checkCertProfileSupportInCA(String certProfile, String caName)
    throws RAWorkerException
    {
        if(caName == null)
        {
            for(CAConf ca : casMap.values())
            {
                if(ca.getProfiles().contains(certProfile))
                {
                    if(caName == null)
                    {
                        caName = ca.getName();
                    }
                    else
                    {
                        throw new RAWorkerException("Certificate profile " + certProfile +
                                " supported by more than one CA, please specify the CA name.");
                    }
                }
            }

            if(caName == null)
            {
                throw new RAWorkerException("Unsupported certificate profile " + certProfile);
            }
        }
        else if(casMap.containsKey(caName) == false)
        {
            throw new RAWorkerException("unknown ca: " + caName);
        }
        else
        {
            CAConf ca = casMap.get(caName);
            if(ca.getProfiles().contains(certProfile) == false)
            {
                throw new RAWorkerException("cert profile " + certProfile + " is not supported by the CA " + caName);
            }
        }
    }

    @Override
    public CertIDOrError revokeCert(X509Certificate cert, int reason)
    throws RAWorkerException, PKIErrorException
    {
        X500Name issuer = X500Name.getInstance(cert.getIssuerX500Principal().getEncoded());
        return revokeCert(issuer, cert.getSerialNumber(), reason);
    }

    @Override
    public CertIDOrError revokeCert(X500Name issuer, BigInteger serial, int reason)
    throws RAWorkerException, PKIErrorException
    {
        final String id = "cert-1";
        RevokeCertRequestEntryType entry =
                new RevokeCertRequestEntryType(id, issuer, serial, reason, null);
        RevokeCertRequestType request = new RevokeCertRequestType();
        request.addRequestEntry(entry);
        Map<String, CertIDOrError> result = revokeCerts(request);
        return result == null ? null : result.get(id);
    }

    @Override
    public Map<String, CertIDOrError> revokeCerts(RevokeCertRequestType request)
    throws RAWorkerException, PKIErrorException
    {
        ParamChecker.assertNotNull("request", request);

        List<RevokeCertRequestEntryType> requestEntries = request.getRequestEntries();
        if(requestEntries.isEmpty())
        {
            return Collections.emptyMap();
        }

        X500Name issuer = requestEntries.get(0).getIssuer();
        for(int i = 1; i < requestEntries.size(); i++)
        {
            if(issuer.equals(requestEntries.get(i).getIssuer()))
            {
                throw new IllegalArgumentException(
                        "Revocating certificates issued by more than one CA is not allowed");
            }
        }

        final String caName = getCaNameByIssuer(issuer);
        X509CmpRequestor cmpRequestor = cmpRequestorsMap.get(caName);
        CmpResultType result;
        try
        {
            result = cmpRequestor.revokeCertificate(request);
        } catch (CmpRequestorException e)
        {
            throw new RAWorkerException(e);
        }

        return parseRevokeCertResult(result);
    }

    private Map<String, CertIDOrError> parseRevokeCertResult(CmpResultType result)
    throws RAWorkerException, PKIErrorException
    {
        if(result instanceof ErrorResultType)
        {
            throw createPKIErrorException((ErrorResultType) result);
        }
        else if(result instanceof RevokeCertResultType)
        {
            Map<String, CertIDOrError> ret = new HashMap<>();

            RevokeCertResultType _result = (RevokeCertResultType) result;
            for(ResultEntryType _entry : _result.getResultEntries())
            {
                CertIDOrError certIdOrError;
                if(_entry instanceof RevokeCertResultEntryType)
                {
                    RevokeCertResultEntryType entry = (RevokeCertResultEntryType) _entry;
                    certIdOrError = new CertIDOrError(entry.getCertID());
                }
                else if(_entry instanceof ErrorResultEntryType)
                {
                    ErrorResultEntryType entry = (ErrorResultEntryType) _entry;
                    certIdOrError = new CertIDOrError(entry.getStatusInfo());
                }
                else
                {
                    throw new RAWorkerException("unknwon type " + _entry);
                }

                ret.put(_entry.getId(), certIdOrError);
            }

            return ret;
        }
        else
        {
            throw new RuntimeException("Unknown result type: " + result.getClass().getName());
        }
    }

    @Override
    public X509CRL downloadCRL(String caName)
    throws RAWorkerException, PKIErrorException
    {
        return downloadCRL(caName, null);
    }

    @Override
    public X509CRL downloadCRL(String caName, BigInteger crlNumber)
    throws RAWorkerException, PKIErrorException
    {
        ParamChecker.assertNotNull("caName", caName);

        if(casMap.containsKey(caName) == false)
        {
            throw new IllegalArgumentException("Unknown CAConf " + caName);
        }

        X509CmpRequestor requestor = cmpRequestorsMap.get(caName);
        CmpResultType result;
        try
        {
            result = crlNumber == null ? requestor.downloadCurrentCRL() : requestor.downloadCRL(crlNumber);
        } catch (CmpRequestorException e)
        {
            throw new RAWorkerException(e);
        }

        if(result instanceof ErrorResultType)
        {
            throw createPKIErrorException((ErrorResultType) result);
        }
        else if(result instanceof CRLResultType)
        {
            CRLResultType downloadCRLResult = (CRLResultType) result;
            return downloadCRLResult.getCRL();
        }
        else
        {
            throw new RuntimeException("Unknown result type: " + result.getClass().getName());
        }
    }

    @Override
    public X509CRL generateCRL(String caName)
    throws RAWorkerException, PKIErrorException
    {
        ParamChecker.assertNotNull("caName", caName);

        if(casMap.containsKey(caName) == false)
        {
            throw new IllegalArgumentException("Unknown CAConf " + caName);
        }

        X509CmpRequestor requestor = cmpRequestorsMap.get(caName);
        CmpResultType result;
        try
        {
            result = requestor.generateCRL();
        } catch (CmpRequestorException e)
        {
            throw new RAWorkerException(e);
        }

        if(result instanceof ErrorResultType)
        {
            throw createPKIErrorException((ErrorResultType) result);
        }
        else if(result instanceof CRLResultType)
        {
            CRLResultType downloadCRLResult = (CRLResultType) result;
            return downloadCRLResult.getCRL();
        }
        else
        {
            throw new RuntimeException("Unknown result type: " + result.getClass().getName());
        }
    }

    @Override
    public String getCaNameByIssuer(final X500Name issuer)
    throws RAWorkerException
    {

        if(issuer ==null )
        {
            throw new RAWorkerException("Invalid issuer");
        }

        for(String name : casMap.keySet())
        {
            final CAConf ca = casMap.get(name);
            if(ca.getSubject().equals(issuer))
            {
                return name;
            }
        }

        throw new RAWorkerException("Unknown CA for issuer: " + issuer);
    }

    private String getCANameForProfile(String certProfile)
    throws RAWorkerException
    {
        String caName = null;
        for(CAConf ca : casMap.values())
        {
            if(ca.getProfiles().contains(certProfile))
            {
                if(caName == null)
                {
                    caName = ca.getName();
                }
                else
                {
                    throw new RAWorkerException("Certificate profile " + certProfile +
                            " supported by more than one CA, please specify the CA name.");
                }
            }
        }

        return caName;
    }

    @Override
    protected java.security.cert.Certificate getCertificate(CMPCertificate cmpCert)
    throws CertificateException
    {
        Certificate bcCert = cmpCert.getX509v3PKCert();
        return (bcCert == null) ? null : new X509CertificateObject(bcCert);
    }

    public String getConfFile()
    {
        return confFile;
    }

    public void setConfFile(String confFile)
    {
        this.confFile = confFile;
    }

    @Override
    public Set<String> getCaNames()
    {
        return casMap.keySet();
    }

    @Override
    public byte[] envelope(CertRequest certRequest, ProofOfPossession pop, String profileName,
            String caName, String username)
    throws RAWorkerException
    {
        if(caName == null)
        {
            // detect the CA name
            caName = getCANameForProfile(profileName);
            if(caName == null)
            {
                throw new RAWorkerException("CertProfile " + profileName + " is not supported by any CA");
            }
        }
        else
        {
            checkCertProfileSupportInCA(profileName, caName);
        }

        X509CmpRequestor cmpRequestor = cmpRequestorsMap.get(caName);
        if(cmpRequestor == null)
        {
            throw new RAWorkerException("could not find CA named " + caName);
        }

        PKIMessage pkiMessage;
        try
        {
            pkiMessage = cmpRequestor.envelope(certRequest, pop, profileName, username);
        } catch (CmpRequestorException e)
        {
            throw new RAWorkerException("CmpRequestorException: " + e.getMessage(), e);
        }

        try
        {
            return pkiMessage.getEncoded();
        } catch (IOException e)
        {
            throw new RAWorkerException("IOException: " + e.getMessage(), e);
        }
    }

    @Override
    protected boolean verify(java.security.cert.Certificate caCert,
            java.security.cert.Certificate cert)
    {
        if(caCert instanceof X509Certificate == false)
        {
            return false;
        }
        if(cert instanceof X509Certificate == false)
        {
            return false;
        }

        X509Certificate _caCert = (X509Certificate) caCert;
        X509Certificate _cert = (X509Certificate) cert;

        if(_cert.getIssuerX500Principal().equals(_caCert.getSubjectX500Principal()) == false)
        {
            return false;
        }

        boolean inLoadTest = Boolean.getBoolean("org.xipki.loadtest");
        if(inLoadTest)
        {
            return true;
        }

        final String provider = "XipkiNSS";
        Boolean tryXipkiNSStoVerify = tryXipkiNSStoVerifyMap.get(_caCert);
        PublicKey caPublicKey = _caCert.getPublicKey();
        try
        {
            if(tryXipkiNSStoVerify == null)
            {
                if(caPublicKey instanceof ECPublicKey)
                {
                    tryXipkiNSStoVerify = Boolean.FALSE;
                    tryXipkiNSStoVerifyMap.put(_caCert, tryXipkiNSStoVerify);
                }
                else
                {
                    if(Security.getProvider(provider) == null)
                    {
                        tryXipkiNSStoVerify = Boolean.FALSE;
                        tryXipkiNSStoVerifyMap.put(_caCert, tryXipkiNSStoVerify);
                    }
                    else
                    {
                        byte[] tbs = _cert.getTBSCertificate();
                        byte[] signatureValue = _cert.getSignature();
                        String sigAlgName = _cert.getSigAlgName();
                        try
                        {
                            Signature verifier = Signature.getInstance(sigAlgName, provider);
                            verifier.initVerify(caPublicKey);
                            verifier.update(tbs);
                            boolean sigValid = verifier.verify(signatureValue);

                            LOG.info("Use {} to verify {} signature", provider, sigAlgName);
                            tryXipkiNSStoVerify = Boolean.TRUE;
                            tryXipkiNSStoVerifyMap.put(_caCert, tryXipkiNSStoVerify);
                            return sigValid;
                        }catch(Exception e)
                        {
                            LOG.info("Could not use {} to verify {} signature", provider, sigAlgName);
                            tryXipkiNSStoVerify = Boolean.FALSE;
                            tryXipkiNSStoVerifyMap.put(_caCert, tryXipkiNSStoVerify);
                        }
                    }
                }
            }

            if(tryXipkiNSStoVerify)
            {
                byte[] tbs = _cert.getTBSCertificate();
                byte[] signatureValue = _cert.getSignature();
                String sigAlgName = _cert.getSigAlgName();
                Signature verifier = Signature.getInstance(sigAlgName, provider);
                verifier.initVerify(caPublicKey);
                verifier.update(tbs);
                return verifier.verify(signatureValue);
            }
            else
            {
                _cert.verify(caPublicKey);
                return true;
            }
        } catch (SignatureException | InvalidKeyException | CertificateException |
                NoSuchAlgorithmException | NoSuchProviderException e)
        {
            LOG.debug("{} while verifying signature: {}", e.getClass().getName(), e.getMessage());
            return false;
        }
    }

    @Override
    public byte[] envelopeRevocation(X500Name issuer, BigInteger serial, int reason)
    throws RAWorkerException
    {
        final String id = "cert-1";
        RevokeCertRequestEntryType entry =
                new RevokeCertRequestEntryType(id, issuer, serial, reason, null);
        RevokeCertRequestType request = new RevokeCertRequestType();
        request.addRequestEntry(entry);

        String caName = getCaNameByIssuer(issuer);
        X509CmpRequestor cmpRequestor = cmpRequestorsMap.get(caName);

        try
        {
            PKIMessage pkiMessage = cmpRequestor.envelopeRevocation(request);
            return pkiMessage.getEncoded();
        } catch (CmpRequestorException | IOException e)
        {
            throw new RAWorkerException(e);
        }
    }

    @Override
    public byte[] envelopeRevocation(X509Certificate cert, int reason)
    throws RAWorkerException
    {
        X500Name issuer = X500Name.getInstance(cert.getIssuerX500Principal().getEncoded());
        return envelopeRevocation(issuer, cert.getSerialNumber(), reason);
    }

    @Override
    public CertIDOrError unrevokeCert(X500Name issuer, BigInteger serial)
    throws RAWorkerException, PKIErrorException
    {
        final String id = "cert-1";
        IssuerSerialEntryType entry =
                new IssuerSerialEntryType(id, issuer, serial);
        UnrevokeOrRemoveCertRequestType request = new UnrevokeOrRemoveCertRequestType();
        request.addRequestEntry(entry);
        Map<String, CertIDOrError> result = unrevokeCerts(request);
        return result == null ? null : result.get(id);
    }

    @Override
    public CertIDOrError unrevokeCert(X509Certificate cert)
    throws RAWorkerException, PKIErrorException
    {
        X500Name issuer = X500Name.getInstance(cert.getIssuerX500Principal().getEncoded());
        return unrevokeCert(issuer, cert.getSerialNumber());
    }

    @Override
    public Map<String, CertIDOrError> unrevokeCerts(UnrevokeOrRemoveCertRequestType request)
    throws RAWorkerException, PKIErrorException
    {
        ParamChecker.assertNotNull("request", request);

        List<IssuerSerialEntryType> requestEntries = request.getRequestEntries();
        if(requestEntries.isEmpty())
        {
            return Collections.emptyMap();
        }

        X500Name issuer = requestEntries.get(0).getIssuer();
        for(int i = 1; i < requestEntries.size(); i++)
        {
            if(issuer.equals(requestEntries.get(i).getIssuer()))
            {
                throw new IllegalArgumentException(
                        "Revocating certificates issued by more than one CA is not allowed");
            }
        }

        final String caName = getCaNameByIssuer(issuer);
        X509CmpRequestor cmpRequestor = cmpRequestorsMap.get(caName);
        CmpResultType result;
        try
        {
            result = cmpRequestor.unrevokeCertificate(request);
        } catch (CmpRequestorException e)
        {
            throw new RAWorkerException(e);
        }

        return parseRevokeCertResult(result);
    }

    @Override
    public CertIDOrError removeCert(X500Name issuer, BigInteger serial)
    throws RAWorkerException, PKIErrorException
    {
        final String id = "cert-1";
        IssuerSerialEntryType entry =
                new IssuerSerialEntryType(id, issuer, serial);
        UnrevokeOrRemoveCertRequestType request = new UnrevokeOrRemoveCertRequestType();
        request.addRequestEntry(entry);
        Map<String, CertIDOrError> result = removeCerts(request);
        return result == null ? null : result.get(id);
    }

    @Override
    public CertIDOrError removeCert(X509Certificate cert)
    throws RAWorkerException, PKIErrorException
    {
        X500Name issuer = X500Name.getInstance(cert.getIssuerX500Principal().getEncoded());
        return removeCert(issuer, cert.getSerialNumber());
    }

    @Override
    public Map<String, CertIDOrError> removeCerts(UnrevokeOrRemoveCertRequestType request)
    throws RAWorkerException, PKIErrorException
    {
        ParamChecker.assertNotNull("request", request);

        List<IssuerSerialEntryType> requestEntries = request.getRequestEntries();
        if(requestEntries.isEmpty())
        {
            return Collections.emptyMap();
        }

        X500Name issuer = requestEntries.get(0).getIssuer();
        for(int i = 1; i < requestEntries.size(); i++)
        {
            if(issuer.equals(requestEntries.get(i).getIssuer()))
            {
                throw new IllegalArgumentException(
                        "Revocating certificates issued by more than one CA is not allowed");
            }
        }

        final String caName = getCaNameByIssuer(issuer);
        X509CmpRequestor cmpRequestor = cmpRequestorsMap.get(caName);
        CmpResultType result;
        try
        {
            result = cmpRequestor.removeCertificate(request);
        } catch (CmpRequestorException e)
        {
            throw new RAWorkerException(e);
        }

        return parseRevokeCertResult(result);
    }

    @Override
    public Set<String> getCertProfiles(String caName)
    {
        CAConf ca = casMap.get(caName);
        return ca == null ? null : ca.getProfiles();
    }

    private static CAClientType parse(InputStream configStream)
    throws ConfigurationException
    {
        synchronized (jaxbUnmarshallerLock)
        {
            Object root;
            try
            {
                if(jaxbUnmarshaller == null)
                {
                    JAXBContext context = JAXBContext.newInstance(ObjectFactory.class);
                    jaxbUnmarshaller = context.createUnmarshaller();

                    final SchemaFactory schemaFact = SchemaFactory.newInstance(
                            javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI);
                    URL url = CAClientType.class.getResource("/xsd/caclient-conf.xsd");
                    jaxbUnmarshaller.setSchema(schemaFact.newSchema(url));
                }

                root = jaxbUnmarshaller.unmarshal(configStream);
            }
            catch(JAXBException | SAXException e)
            {
                throw new ConfigurationException("parse configuration failed, message: " + e.getMessage(), e);
            }

            if(root instanceof JAXBElement)
            {
                return (CAClientType) ((JAXBElement<?>)root).getValue();
            }
            else
            {
                throw new ConfigurationException("invalid root element type");
            }
        }
    }

}
