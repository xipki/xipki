/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013-2016 Lijun Liao
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
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.SchemaFactory;

import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
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
import org.xipki.ca.client.api.RemoveExpiredCertsResult;
import org.xipki.ca.client.impl.jaxb.CAClientType;
import org.xipki.ca.client.impl.jaxb.CAInfoType;
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
    private class ClientConfigUpdater implements Runnable
    {
        private static final long MINUTE = 60L * 1000;
        private AtomicBoolean crlGenInProcess = new AtomicBoolean(false);
        private long lastUpdate;

        ClientConfigUpdater()
        {
        }

        @Override
        public void run()
        {
            if(crlGenInProcess.get())
            {
                return;
            }

            crlGenInProcess.set(true);

            try
            {
                // just updated within the last 2 minutes
                if(System.currentTimeMillis() - lastUpdate < 2 * MINUTE)
                {
                    return;
                }

                autoConfCAs(null);
            }finally
            {
                lastUpdate = System.currentTimeMillis();
                crlGenInProcess.set(false);
            }
        }
    }

    private static final Logger LOG = LoggerFactory.getLogger(RAWorkerImpl.class);

    private static Object jaxbUnmarshallerLock = new Object();
    private static Unmarshaller jaxbUnmarshaller;

    private final Map<String, CAConf> casMap = new HashMap<>();

    private String confFile;
    private Map<X509Certificate, Boolean> tryXipkiNSStoVerifyMap = new ConcurrentHashMap<>();
    private ScheduledThreadPoolExecutor scheduledThreadPoolExecutor;

    public RAWorkerImpl()
    {
    }

    /**
     *
     * @return names of CAs which could not been configured
     */
    private Set<String> autoConfCAs(Set<String> caNamesToBeConfigured)
    {
        Set<String> caNamesWithError = new HashSet<>();

        for(String name : casMap.keySet())
        {
            if(caNamesToBeConfigured != null && caNamesToBeConfigured.contains(name) == false)
            {
                continue;
            }

            CAConf ca = casMap.get(name);
            if(ca.isAutoConf() == false)
            {
                continue;
            }

            boolean responderConfigured = false;
            try
            {
                ca.getRequestor().autoConfigureResponder();
                responderConfigured = true;
                LOG.info("Retrieved CMP responder for CA " + name);
            }catch(Throwable t)
            {
                caNamesWithError.add(name);
                final String message = "Could not retrieve CMP responder for CA " + name;
                if(LOG.isWarnEnabled())
                {
                    LOG.warn(LogUtil.buildExceptionLogFormat(message), t.getClass().getName(), t.getMessage());
                }
                LOG.debug(message, t);
            }

            if(responderConfigured == false)
            {
                continue;
            }

            try
            {
                CAInfo caInfo = ca.getRequestor().retrieveCAInfo(name);
                ca.setCAInfo(caInfo);
                LOG.info("Retrieved CAInfo for CA " + name);
            } catch(Throwable t)
            {
                caNamesWithError.add(name);
                final String message = "Could not retrieve CAInfo for CA " + name;
                if(LOG.isWarnEnabled())
                {
                    LOG.warn(LogUtil.buildExceptionLogFormat(message), t.getClass().getName(), t.getMessage());
                }
                LOG.debug(message, t);
            }
        }

        return caNamesWithError;
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
                CAConf ca = new CAConf(caName, caType.getUrl(), caType.getRequestor());
                CAInfoType caInfo = caType.getCAInfo();
                if(caInfo.getAutoConf() == null)
                {
                    ca.setAutoConf(false);

                    // CA cert
                    X509Certificate cert = IoCertUtil.parseCert(readData(caInfo.getCert()));

                    // profiles
                    Set<String> certProfiles = new HashSet<>(caInfo.getCertProfiles().getCertProfile());
                    ca.setCAInfo(cert, certProfiles);

                    // responder
                    cert = IoCertUtil.parseCert(readData(caInfo.getResponder()));
                    ca.setResponder(cert);
                }
                else
                {
                    ca.setAutoConf(true);
                }

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

        // requestors
        Map<String, X509Certificate> requestorCerts = new HashMap<>();
        Map<String, ConcurrentContentSigner> requestorSigners = new HashMap<>();
        Map<String, Boolean> requestorSignRequests = new HashMap<>();

        for(RequestorType requestorConf : config.getRequestors().getRequestor())
        {
            String name = requestorConf.getName();
            requestorSignRequests.put(name, requestorConf.isSignRequest());

            X509Certificate requestorCert = null;
            if(requestorConf.getCert() != null)
            {
                try
                {
                    requestorCert = IoCertUtil.parseCert(readData(requestorConf.getCert()));
                    requestorCerts.put(name, requestorCert);
                } catch (Exception e)
                {
                    throw new ConfigurationException(e);
                }
            }

            // ------------------------------------------------
            if(requestorConf.getSignerType() != null)
            {
                try
                {
                    ConcurrentContentSigner requestorSigner = securityFactory.createSigner(
                            requestorConf.getSignerType(), requestorConf.getSignerConf(), requestorCert);
                    requestorSigners.put(name, requestorSigner);
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
        }

        boolean autoConf = false;
        for(CAConf ca :cas)
        {
            if(null != this.casMap.put(ca.getName(), ca))
            {
                throw new ConfigurationException("duplicate CAs with the same name " + ca.getName());
            }

            if(ca.isAutoConf())
            {
                autoConf = true;
            }

            String requestorName = ca.getRequestorName();

            X509CmpRequestor cmpRequestor;
            if(requestorSigners.containsKey(requestorName))
            {
                cmpRequestor = new DefaultHttpCmpRequestor(
                        requestorSigners.get(requestorName), ca.getResponder(), ca.getUrl(),
                        securityFactory, requestorSignRequests.get(requestorName));
            } else if(requestorCerts.containsKey(requestorName))
            {
                cmpRequestor = new DefaultHttpCmpRequestor(
                        requestorCerts.get(requestorName), ca.getResponder(), ca.getUrl(),
                        securityFactory);
            }
            else
            {
                throw new ConfigurationException("Could not find requestor named " + requestorName +
                        " for CA " + ca.getName());
            }

            ca.setRequestor(cmpRequestor);
        }

        if(autoConf)
        {
            Integer cAInfoUpdateInterval = config.getCAs().getCAInfoUpdateInterval();
            if(cAInfoUpdateInterval == null)
            {
                cAInfoUpdateInterval = 10;
            }
            else if(cAInfoUpdateInterval <= 0)
            {
                cAInfoUpdateInterval = 0;
            }
            else if(cAInfoUpdateInterval < 5)
            {
                cAInfoUpdateInterval = 5;
            }

            Set<String> caNames = casMap.keySet();
            StringBuilder sb = new StringBuilder("Configuring CAs ");
            sb.append(caNames);

            LOG.info(sb.toString());
            caNames = autoConfCAs(caNames);

            if(caNames.isEmpty() == false)
            {
                final String msg = "Could not configured following CAs " + caNames;
                if(devMode)
                {
                    LOG.warn(msg);
                }
                else
                {
                    throw new ConfigurationException(msg);
                }
            }

            if(cAInfoUpdateInterval > 0)
            {
                scheduledThreadPoolExecutor = new ScheduledThreadPoolExecutor(1);
                scheduledThreadPoolExecutor.scheduleAtFixedRate(
                        new ClientConfigUpdater(),
                        cAInfoUpdateInterval, cAInfoUpdateInterval, TimeUnit.MINUTES);
            }
        }
    }

    public void shutdown()
    {
        if(scheduledThreadPoolExecutor != null)
        {
            scheduledThreadPoolExecutor.shutdown();
            while(scheduledThreadPoolExecutor.isTerminated() == false)
            {
                try
                {
                    Thread.sleep(100);
                }catch(InterruptedException e)
                {
                }
            }
            scheduledThreadPoolExecutor = null;
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

        CAConf ca = casMap.get(caName);
        if(ca == null)
        {
            throw new RAWorkerException("could not find CA named " + caName);
        }

        CmpResultType result;
        try
        {
            result = ca.getRequestor().requestCertificate(request, username);
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
                if(ca.isCAInfoConfigured() == false)
                {
                    continue;
                }
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
            if(issuer.equals(requestEntries.get(i).getIssuer()) == false)
            {
                throw new PKIErrorException(
                        PKIStatus.REJECTION, PKIFailureInfo.badRequest,
                        "Revoking certificates issued by more than one CA is not allowed");
            }
        }

        final String caName = getCaNameByIssuer(issuer);
        X509CmpRequestor cmpRequestor = casMap.get(caName).getRequestor();
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

        X509CmpRequestor requestor = casMap.get(caName).getRequestor();
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

        X509CmpRequestor requestor = casMap.get(caName).getRequestor();
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

        if(issuer == null )
        {
            throw new RAWorkerException("Invalid issuer");
        }

        for(String name : casMap.keySet())
        {
            final CAConf ca = casMap.get(name);
            if(ca.isCAInfoConfigured() == false)
            {
                continue;
            }

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
            if(ca.isCAInfoConfigured() == false)
            {
                continue;
            }

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

        CAConf ca = casMap.get(caName);
        if(ca == null)
        {
            throw new RAWorkerException("could not find CA named " + caName);
        }

        PKIMessage pkiMessage;
        try
        {
            pkiMessage = ca.getRequestor().envelope(certRequest, pop, profileName, username);
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
        X509CmpRequestor cmpRequestor = casMap.get(caName).getRequestor();

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
            if(issuer.equals(requestEntries.get(i).getIssuer()) == false)
            {
                throw new PKIErrorException(
                        PKIStatus.REJECTION, PKIFailureInfo.badRequest,
                        "Unrevoking certificates issued by more than one CA is not allowed");
            }
        }

        final String caName = getCaNameByIssuer(issuer);
        X509CmpRequestor cmpRequestor = casMap.get(caName).getRequestor();
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
            if(issuer.equals(requestEntries.get(i).getIssuer()) == false)
            {
                throw new PKIErrorException(
                        PKIStatus.REJECTION, PKIFailureInfo.badRequest,
                        "Removing certificates issued by more than one CA is not allowed");
            }
        }

        final String caName = getCaNameByIssuer(issuer);
        X509CmpRequestor cmpRequestor = casMap.get(caName).getRequestor();
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

    @Override
    public RemoveExpiredCertsResult removeExpiredCerts(String caName,
            String certProfile, String userLike, long overlapSeconds)
    throws RAWorkerException, PKIErrorException
    {
        ParamChecker.assertNotNull("caName", caName);

        if(casMap.containsKey(caName) == false)
        {
            throw new IllegalArgumentException("Unknown CAConf " + caName);
        }

        X509CmpRequestor requestor = casMap.get(caName).getRequestor();
        try
        {
            return requestor.removeExpiredCerts(certProfile, userLike, overlapSeconds);
        } catch (CmpRequestorException e)
        {
            throw new RAWorkerException(e);
        }
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
