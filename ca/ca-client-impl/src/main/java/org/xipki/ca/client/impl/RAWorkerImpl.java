/*
 * Copyright (c) 2014 xipki.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.ca.client.impl;

import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
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
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.concurrent.ConcurrentHashMap;

import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CertReqMsg;
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
import org.xipki.ca.cmp.CmpUtil;
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
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.api.SignerException;
import org.xipki.security.common.CmpUtf8Pairs;
import org.xipki.security.common.ConfigurationException;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;

public final class RAWorkerImpl extends AbstractRAWorker implements RAWorker
{
    public static final String DEV_MODE = "dev.mode";

    public static final String SIGN_REQUEST = "sign.request";

    /**
     * The certificate of the responder.
     */
    public static final String REQUESTOR_CERT = "requestor.cert";

    /**
     * The type of requestorSigner signer
     */
    public static final String REQUESTOR_SIGNER_TYPE = "requestor.signer.type";

    /**
     * The configuration of the requestorSigner signer
     */
    public static final String REQUESTOR_SIGNER_CONF = "requestor.signer.conf";

    public static final String CA_PREFIX = "ca.";

    public static final String CA_ENABLED_SUFFIX = ".enabled";

    /**
     * certificate of the given CA
     */
    public static final String CA_CERT_SUFFIX = ".cert";

    /**
     * URL of the given CA
     */
    public static final String CA_URL_SUFFIX = ".url";

    public static final String CA_RESPONDER_SUFFIX = ".responder";

    /**
     * Certificate profiles supported by the given CA
     */
    public static final String CA_PROFILES_SUFFIX = ".profiles";

    private static final Logger LOG = LoggerFactory.getLogger(RAWorkerImpl.class);

    public static long DAY = 24L * 60 * 60 * 1000;

    private final Map<String, CAConf> casMap = new HashMap<String, CAConf>();
    private final Map<String, X509CmpRequestor> cmpRequestorsMap = new ConcurrentHashMap<String, X509CmpRequestor>();

    private String            confFile;
    private Map<X509Certificate, Boolean> tryXipkiNSStoVerifyMap = new ConcurrentHashMap<>();

    public RAWorkerImpl()
    {
    }

    public void init()
    throws ConfigurationException, IOException
    {
        ParamChecker.assertNotNull("confFile", confFile);
        ParamChecker.assertNotNull("passwordResolver", passwordResolver);
        ParamChecker.assertNotNull("securityFactory", securityFactory);

        if(Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        Properties props = new Properties();
        FileInputStream configStream = new FileInputStream(confFile);
        try
        {
            props.load(configStream);
        }finally
        {
            try
            {
                configStream.close();
            }catch(IOException e)
            {
            }
        }

        boolean dev_mode = Boolean.parseBoolean(props.getProperty(DEV_MODE, "false"));

        boolean signRequest = Boolean.parseBoolean(props.getProperty(SIGN_REQUEST, "true"));

        X509Certificate requestorCert = null;
        String s = props.getProperty(REQUESTOR_CERT);
        if(isEmpty(s) == false)
        {
            try
            {
                requestorCert = IoCertUtil.parseCert(s);
            } catch (Exception e)
            {
                throw new ConfigurationException(e);
            }
        }

        String requestorSignerType = props.getProperty(REQUESTOR_SIGNER_TYPE);
        String requestorSignerConf = props.getProperty(REQUESTOR_SIGNER_CONF);

        Set<String> caNames = new HashSet<String>();
        Set<String> disabledCaNames = new HashSet<String>();

        for(Object _propKey : props.keySet())
        {
            String propKey = (String) _propKey;
            if(propKey.startsWith(CA_PREFIX) && propKey.endsWith(CA_CERT_SUFFIX))
            {
                String caName = propKey.substring(CA_PREFIX.length(),
                        propKey.length() - CA_CERT_SUFFIX.length());

                String enabled = props.getProperty(CA_PREFIX + caName + CA_ENABLED_SUFFIX, "true");
                if(Boolean.parseBoolean(enabled))
                {
                    caNames.add(caName);
                }
                else
                {
                    LOG.info("CA " + caName + " is disabled");
                    disabledCaNames.add(caName);
                }
            }
        }

        if(caNames.isEmpty())
        {
            LOG.warn("No CA configured");
        }

        Set<String> configuredCaNames = new HashSet<String>();

        Set<CAConf> cas = new HashSet<CAConf>();
        for(String caName : caNames)
        {
            try
            {
                String _serviceUrl = props.getProperty(CA_PREFIX + caName + CA_URL_SUFFIX);
                String _caCertFile = props.getProperty(CA_PREFIX + caName + CA_CERT_SUFFIX);
                String _responderFile = props.getProperty(CA_PREFIX + caName + CA_RESPONDER_SUFFIX);
                String _profiles = props.getProperty(CA_PREFIX + caName + CA_PROFILES_SUFFIX);

                Set<String> profiles = null;
                if(_profiles != null)
                {
                    StringTokenizer st = new StringTokenizer(_profiles, ", ");
                    profiles = new HashSet<String>(st.countTokens());
                    while(st.hasMoreTokens())
                    {
                        profiles.add(st.nextToken().trim());
                    }
                }

                CAConf ca = new CAConf(caName, _serviceUrl, IoCertUtil.parseCert(_caCertFile), profiles,
                        IoCertUtil.parseCert(_responderFile));
                cas.add(ca);
                configuredCaNames.add(caName);
            }catch(IOException e)
            {
                LOG.warn("Could not configure CA {}, IOException: {}", caName, e.getMessage());
                LOG.debug("Could not configure CA " + caName, e);
                if(dev_mode == false)
                {
                    throw e;
                }
            }catch(CertificateException e)
            {
                LOG.warn("Could not configure CA {}, CertificateException: {}", caName, e.getMessage());
                LOG.debug("Could not configure CA " + caName, e);
                if(dev_mode == false)
                {
                    throw new ConfigurationException(e);
                }
            }
        }

        // ------------------------------------------------
        ConcurrentContentSigner requestorSigner;
        try
        {
            requestorSigner = securityFactory.createSigner(
                    requestorSignerType, requestorSignerConf, requestorCert, passwordResolver);
        } catch (SignerException e)
        {
            throw new ConfigurationException(e);
        } catch (PasswordResolverException e)
        {
            throw new ConfigurationException(e);
        }

        for(CAConf ca :cas)
        {
            if(null != this.casMap.put(ca.getName(), ca))
            {
                throw new IllegalArgumentException("duplicate CAs with the same name " + ca.getName());
            }

            X509CmpRequestor cmpRequestor = new DefaultHttpCmpRequestor(
                    requestorSigner, ca.getResponder(), ca.getCert(), ca.getUrl(),
                    securityFactory, signRequest);

            cmpRequestorsMap.put(ca.getName(), cmpRequestor);
        }
    }

    @Override
    public EnrollCertResult requestCert(CertificationRequest p10Request, String profile, String caName)
    throws RAWorkerException, PKIErrorException
    {
        return requestCert(p10Request, profile, caName, null);
    }

    @Override
    public EnrollCertResult requestCert(CertificationRequest p10Request, String profile, String caName,
            String username)
    throws RAWorkerException, PKIErrorException
    {
        EnrollCertEntryType entry = new EnrollCertEntryType(p10Request, profile);
        Map<String, EnrollCertEntryType> entries = new HashMap<String, EnrollCertEntryType>();

        final String id = "p10-1";
        entries.put(id, entry);
        return requestCerts(EnrollCertRequestType.Type.CERT_REQ, entries, caName, username);
    }

    @Override
    public EnrollCertResult requestCerts(EnrollCertRequestType.Type type,
            Map<String, EnrollCertEntryType> enrollCertEntries,
            String caName)
    throws RAWorkerException, PKIErrorException
    {
        return requestCerts(type, enrollCertEntries, caName, null);
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
    public EnrollCertResult requestCert(CertReqMsg request, String extCertReqId, String caName)
    throws RAWorkerException, PKIErrorException
    {
        return requestCert(request, extCertReqId, caName, null);
    }

    @Override
    public EnrollCertResult requestCert(CertReqMsg request, String extCertReqId, String caName,
            String username)
    throws RAWorkerException, PKIErrorException
    {
        ParamChecker.assertNotNull("request", request);
        X509CmpRequestor cmpRequestor = getCmpRequestor(request, caName);

        CmpResultType result;
        try
        {
            result = cmpRequestor.requestCertificate(request, extCertReqId,username);
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

    @Override
    public CertReqMsg getCertReqMsgWithAppliedCertProfile(CertRequest request,
            String profileName, ProofOfPossession popo)
    throws RAWorkerException
    {
        ParamChecker.assertNotEmpty("profileName", profileName);
        CmpUtf8Pairs utf8Pairs = new CmpUtf8Pairs(CmpUtf8Pairs.KEY_CERT_PROFILE, profileName);
        AttributeTypeAndValue certProfileInfo = new AttributeTypeAndValue(
                CMPObjectIdentifiers.regInfo_utf8Pairs, new DERUTF8String(utf8Pairs.getEncoded()));
        return new CertReqMsg(request, popo, new AttributeTypeAndValue[] { certProfileInfo });
    }

    @Override
    public EnrollCertResult requestCerts(EnrollCertRequestType request, String caName)
    throws RAWorkerException, PKIErrorException
    {
        return requestCerts(request, caName, null);
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

        // make sure that all requests are targeted on the same CA
        for(EnrollCertRequestEntryType entry : request.getRequestEntries())
        {
            String profile = entry.getCertProfile();
            checkCertProfileSupportInCA(profile, caName);
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
            Map<String, CertIDOrError> ret = new HashMap<String, CertIDOrError>();

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
                // TODO: check the whether the serial number and issuer match the requested ones.
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
        return requestCRL(caName, false);
    }

    @Override
    public X509CRL generateCRL(String caName)
    throws RAWorkerException, PKIErrorException
    {
        return requestCRL(caName, true);
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

    private X509CRL requestCRL(String caName, boolean generateCRL)
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
            result = generateCRL ? requestor.generateCRL() : requestor.downloadCurrentCRL();
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
    protected java.security.cert.Certificate getCertificate(
            CMPCertificate cmpCert)
    throws CertificateException
    {
        Certificate bcCert = cmpCert.getX509v3PKCert();
        return (bcCert == null) ? null : new X509CertificateObject(bcCert);
    }

    private static boolean isEmpty(String s)
    {
        return s == null || s.isEmpty();
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
    public byte[] envelope(CertReqMsg certReqMsg, String caName)
    throws RAWorkerException
    {
        return envelope(certReqMsg, caName, null);
    }

    @Override
    public byte[] envelope(CertReqMsg certReqMsg, String caName, String username)
    throws RAWorkerException
    {
        ParamChecker.assertNotNull("request", certReqMsg);
        X509CmpRequestor cmpRequestor = getCmpRequestor(certReqMsg, caName);
        try
        {
            return cmpRequestor.envelope(certReqMsg, username).getEncoded();
        } catch (IOException e)
        {
            throw new RAWorkerException("IOException: " + e.getMessage(), e);
        } catch (CmpRequestorException e)
        {
            throw new RAWorkerException("CmpRequestorException: " + e.getMessage(), e);
        }
    }

    private X509CmpRequestor getCmpRequestor(CertReqMsg request, String caName)
    throws RAWorkerException
    {
        ParamChecker.assertNotNull("request", request);

        if(caName == null)
        {
            CmpUtf8Pairs utf8Pairs = CmpUtil.extract(request.getRegInfo());
            String certProfileName = utf8Pairs.getValue(CmpUtf8Pairs.KEY_CERT_PROFILE);
            caName = getCANameForProfile(certProfileName);

            if(caName == null)
            {
                throw new RAWorkerException("CertProfile " + certProfileName + " is not supported by any CA");
            }
        }

        X509CmpRequestor cmpRequestor = cmpRequestorsMap.get(caName);
        if(cmpRequestor == null)
        {
            throw new RAWorkerException("could not find CA named " + caName);
        }

        return cmpRequestor;
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
                    return sigValid;
                }catch(Exception e)
                {
                    LOG.warn("Could not use {} to verify {} signature", provider, sigAlgName);
                    tryXipkiNSStoVerify = Boolean.FALSE;
                }

                tryXipkiNSStoVerifyMap.put(_caCert, tryXipkiNSStoVerify);
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
        } catch (SignatureException e)
        {
            LOG.debug("SignatureException while verifying signature: {}", e.getMessage());
            return false;
        } catch (InvalidKeyException e)
        {
            LOG.debug("InvalidKeyException while verifying signature: {}", e.getMessage());
            return false;
        } catch (CertificateException e)
        {
            LOG.debug("CertificateException while verifying signature: {}", e.getMessage());
            return false;
        } catch (NoSuchAlgorithmException e)
        {
            LOG.debug("NoSuchAlgorithmException while verifying signature: {}", e.getMessage());
            return false;
        } catch (NoSuchProviderException e)
        {
            LOG.debug("NoSuchProviderException while verifying signature: {}", e.getMessage());
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
        } catch (CmpRequestorException e)
        {
            throw new RAWorkerException(e);
        } catch (IOException e)
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

}
