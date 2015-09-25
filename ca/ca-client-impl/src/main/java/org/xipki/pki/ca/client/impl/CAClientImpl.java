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

package org.xipki.pki.ca.client.impl;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
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
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
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
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.HealthCheckResult;
import org.xipki.common.InvalidConfException;
import org.xipki.common.RequestResponseDebug;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.XMLUtil;
import org.xipki.pki.ca.client.api.CAClient;
import org.xipki.pki.ca.client.api.CAClientException;
import org.xipki.pki.ca.client.api.CertIdOrError;
import org.xipki.pki.ca.client.api.CertOrError;
import org.xipki.pki.ca.client.api.CertprofileInfo;
import org.xipki.pki.ca.client.api.EnrollCertResult;
import org.xipki.pki.ca.client.api.PKIErrorException;
import org.xipki.pki.ca.client.api.dto.CRLResultType;
import org.xipki.pki.ca.client.api.dto.EnrollCertRequestEntryType;
import org.xipki.pki.ca.client.api.dto.EnrollCertRequestType;
import org.xipki.pki.ca.client.api.dto.EnrollCertResultEntryType;
import org.xipki.pki.ca.client.api.dto.EnrollCertResultType;
import org.xipki.pki.ca.client.api.dto.ErrorResultEntryType;
import org.xipki.pki.ca.client.api.dto.IssuerSerialEntryType;
import org.xipki.pki.ca.client.api.dto.P10EnrollCertRequestType;
import org.xipki.pki.ca.client.api.dto.ResultEntryType;
import org.xipki.pki.ca.client.api.dto.RevokeCertRequestEntryType;
import org.xipki.pki.ca.client.api.dto.RevokeCertRequestType;
import org.xipki.pki.ca.client.api.dto.RevokeCertResultEntryType;
import org.xipki.pki.ca.client.api.dto.RevokeCertResultType;
import org.xipki.pki.ca.client.api.dto.UnrevokeOrRemoveCertRequestType;
import org.xipki.pki.ca.client.impl.jaxb.CAClientType;
import org.xipki.pki.ca.client.impl.jaxb.CAType;
import org.xipki.pki.ca.client.impl.jaxb.CertprofileType;
import org.xipki.pki.ca.client.impl.jaxb.CertprofilesType;
import org.xipki.pki.ca.client.impl.jaxb.FileOrValueType;
import org.xipki.pki.ca.client.impl.jaxb.ObjectFactory;
import org.xipki.pki.ca.client.impl.jaxb.RequestorType;
import org.xipki.pki.ca.client.impl.jaxb.ResponderType;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;
import org.xipki.security.api.util.X509Util;
import org.xml.sax.SAXException;

/**
 * @author Lijun Liao
 */

public final class CAClientImpl implements CAClient
{
    private class ClientConfigUpdater implements Runnable
    {
        private static final long MINUTE = 60L * 1000;
        private AtomicBoolean inProcess = new AtomicBoolean(false);
        private long lastUpdate;

        ClientConfigUpdater()
        {
        }

        @Override
        public void run()
        {
            if(inProcess.get())
            {
                return;
            }

            inProcess.set(true);

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
                inProcess.set(false);
            }
        }
    }

    private static final Logger LOG = LoggerFactory.getLogger(CAClientImpl.class);

    private static Object jaxbUnmarshallerLock = new Object();
    private static Unmarshaller jaxbUnmarshaller;

    private final Map<String, CAConf> casMap = new HashMap<>();

    private SecurityFactory securityFactory;

    private String confFile;
    private Map<X509Certificate, Boolean> tryXipkiNSStoVerifyMap = new ConcurrentHashMap<>();
    private ScheduledThreadPoolExecutor scheduledThreadPoolExecutor;

    public CAClientImpl()
    {
    }

    public void setSecurityFactory(
            final SecurityFactory securityFactory)
    {
        this.securityFactory = securityFactory;
    }

    /**
     *
     * @return names of CAs which could not been configured
     */
    private Set<String> autoConfCAs(
            final Set<String> caNamesToBeConfigured)
    {
        Set<String> caNamesWithError = new HashSet<>();

        Set<String> errorCANames = new HashSet<>();
        for(String name : casMap.keySet())
        {
            if(caNamesToBeConfigured != null && caNamesToBeConfigured.contains(name) == false)
            {
                continue;
            }

            CAConf ca = casMap.get(name);

            if(ca.isCertAutoconf() == false && ca.isCertprofilesAutoconf() == false)
            {
                continue;
            }

            try
            {
                CAInfo caInfo = ca.getRequestor().retrieveCAInfo(name, null);
                if(ca.isCertAutoconf())
                {
                    ca.setCert(caInfo.getCert());
                }
                if(ca.isCertprofilesAutoconf())
                {
                    ca.setCertprofiles(caInfo.getCertprofiles());
                }
                LOG.info("retrieved CAInfo for CA " + name);
            } catch(Throwable t)
            {
                errorCANames.add(name);
                caNamesWithError.add(name);
                final String message = "could not retrieve CAInfo for CA " + name;
                if(LOG.isWarnEnabled())
                {
                    LOG.warn(LogUtil.buildExceptionLogFormat(message), t.getClass().getName(),
                            t.getMessage());
                }
                LOG.debug(message, t);
            }
        }

        if(CollectionUtil.isNotEmpty(errorCANames))
        {
            for(String caName : errorCANames)
            {
                casMap.remove(caName);
            }
        }

        return caNamesWithError;
    }

    public void init()
    throws InvalidConfException, IOException
    {
        ParamUtil.assertNotNull("confFile", confFile);
        ParamUtil.assertNotNull("securityFactory", securityFactory);

        if(Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        File configFile = new File(IoUtil.expandFilepath(confFile));
        if(configFile.exists() == false)
        {
            throw new FileNotFoundException("cound not find configuration file " + confFile);
        }

        CAClientType config = parse(new FileInputStream(configFile));
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
            LOG.warn("no active CA is configured");
        }

        Boolean b = config.isDevMode();
        boolean devMode = b != null && b.booleanValue();

        // responders
        Map<String, X509Certificate> responders = new HashMap<>();
        for(ResponderType m : config.getResponders().getResponder())
        {
            X509Certificate cert;
            try
            {
                cert = X509Util.parseCert(readData(m.getCert()));
            } catch (CertificateException e)
            {
                final String message = "could not configure responder " + m.getName();
                if(LOG.isWarnEnabled())
                {
                    LOG.warn(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                            e.getMessage());
                }
                LOG.debug(message, e);

                throw new InvalidConfException(e.getMessage(), e);
            }
            responders.put(m.getName(), cert);
        }

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
                // responder
                X509Certificate responder = responders.get(caType.getResponder());
                if(responder == null)
                {
                    throw new InvalidConfException("no responder named " + caType.getResponder()
                            + " is configured");
                }
                CAConf ca = new CAConf(caName, caType.getUrl(), caType.getHealthUrl(),
                        caType.getRequestor(), responder);

                // CA cert
                if(caType.getCaCert().getAutoconf() != null)
                {
                    ca.setCertAutoconf(true);
                }
                else
                {
                    ca.setCertAutoconf(true);
                    ca.setCert(X509Util.parseCert(readData(caType.getCaCert().getCert())));
                }

                // Certprofiles
                CertprofilesType certprofilesType = caType.getCertprofiles();
                if(certprofilesType.getAutoconf() != null)
                {
                    ca.setCertprofilesAutoconf(true);
                }
                else
                {
                    ca.setCertprofilesAutoconf(false);

                    List<CertprofileType> types = certprofilesType.getCertprofile();
                    Set<CertprofileInfo> profiles = new HashSet<>(types.size());
                    for(CertprofileType m : types)
                    {
                        String conf = null;
                        if(m.getConf() != null)
                        {
                            conf = m.getConf().getValue();
                            if(conf == null)
                            {
                                conf = new String(IoUtil.read(m.getConf().getFile()));
                            }
                        }
                        CertprofileInfo profile = new CertprofileInfo(m.getName(), m.getType(),
                                conf);
                        profiles.add(profile);
                    }
                    ca.setCertprofiles(profiles);
                }

                cas.add(ca);
                configuredCaNames.add(caName);
            }catch(IOException | CertificateException e)
            {
                final String message = "could not configure CA " + caName;
                if(LOG.isWarnEnabled())
                {
                    LOG.warn(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                            e.getMessage());
                }
                LOG.debug(message, e);

                if(devMode == false)
                {
                    throw new InvalidConfException(e.getMessage(), e);
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
                    requestorCert = X509Util.parseCert(readData(requestorConf.getCert()));
                    requestorCerts.put(name, requestorCert);
                } catch (Exception e)
                {
                    throw new InvalidConfException(e.getMessage(), e);
                }
            }

            // ------------------------------------------------
            if(requestorConf.getSignerType() != null)
            {
                try
                {
                    ConcurrentContentSigner requestorSigner = securityFactory.createSigner(
                            requestorConf.getSignerType(), requestorConf.getSignerConf(),
                            requestorCert);
                    requestorSigners.put(name, requestorSigner);
                } catch (SignerException e)
                {
                    throw new InvalidConfException(e.getMessage(), e);
                }
            } else
            {
                if(requestorConf.isSignRequest())
                {
                    throw new InvalidConfException("signer of requestor must be configured");
                } else if(requestorCert == null)
                {
                    throw new InvalidConfException(
                        "at least one of certificate and signer of requestor must be configured");
                }
            }
        }

        boolean autoConf = false;
        for(CAConf ca :cas)
        {
            if(this.casMap.containsKey(ca.getName()))
            {
                throw new InvalidConfException("duplicate CAs with the same name " + ca.getName());
            }

            if(ca.isCertAutoconf() || ca.isCertprofilesAutoconf())
            {
                autoConf = true;
            }

            String requestorName = ca.getRequestorName();

            X509CmpRequestor cmpRequestor;
            if(requestorSigners.containsKey(requestorName))
            {
                cmpRequestor = new DefaultHttpX509CmpRequestor(
                        requestorSigners.get(requestorName), ca.getResponder(), ca.getUrl(),
                        securityFactory, requestorSignRequests.get(requestorName));
            } else if(requestorCerts.containsKey(requestorName))
            {
                cmpRequestor = new DefaultHttpX509CmpRequestor(
                        requestorCerts.get(requestorName), ca.getResponder(), ca.getUrl(),
                        securityFactory);
            }
            else
            {
                throw new InvalidConfException("could not find requestor named "
                        + requestorName
                        + " for CA " + ca.getName());
            }

            ca.setRequestor(cmpRequestor);
            this.casMap.put(ca.getName(), ca);
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
            StringBuilder sb = new StringBuilder("configuring CAs ");
            sb.append(caNames);

            LOG.info(sb.toString());
            caNames = autoConfCAs(caNames);

            if(CollectionUtil.isNotEmpty(caNames))
            {
                final String msg = "could not configured following CAs " + caNames;
                if(devMode)
                {
                    LOG.warn(msg);
                } else
                {
                    throw new InvalidConfException(msg);
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

    private static byte[] readData(
            final FileOrValueType fileOrValue)
    throws IOException
    {
        byte[] data = fileOrValue.getValue();
        if(data == null)
        {
            data = IoUtil.read(fileOrValue.getFile());
        }
        return data;
    }

    @Override
    public EnrollCertResult requestCert(
            final CertificationRequest p10Request,
            final String profile,
            String caName,
            final String username,
            final RequestResponseDebug debug)
    throws CAClientException, PKIErrorException
    {
        if(caName == null)
        {
            caName = getCANameForProfile(profile);
            if(caName == null)
            {
                throw new CAClientException("cert profile " + profile
                        + " is not supported by any CA");
            }
        }

        CAConf ca = casMap.get(caName);
        if(ca == null)
        {
            throw new CAClientException("could not find CA named " + caName);
        }

        final String id = "cert-1";
        P10EnrollCertRequestType request = new P10EnrollCertRequestType(id, profile, p10Request);
        EnrollCertResultType result;
        try
        {
            result = ca.getRequestor().requestCertificate(request, username, debug);
        } catch (CmpRequestorException e)
        {
            throw new CAClientException(e.getMessage(), e);
        }

        return parseEnrollCertResult((EnrollCertResultType) result, caName);
    }

    @Override
    public EnrollCertResult requestCerts(
            final EnrollCertRequestType request,
            String caName,
            final String username,
            final RequestResponseDebug debug)
    throws CAClientException, PKIErrorException
    {
        ParamUtil.assertNotNull("request", request);

        List<EnrollCertRequestEntryType> requestEntries = request.getRequestEntries();
        if(CollectionUtil.isEmpty(requestEntries))
        {
            return null;
        }

        boolean b = (caName != null);
        if(caName == null)
        {
            // detect the CA name
            String profile = requestEntries.get(0).getCertprofile();
            caName = getCANameForProfile(profile);
            if(caName == null)
            {
                throw new CAClientException("cert profile " + profile
                        + " is not supported by any CA");
            }
        }

        if(b || request.getRequestEntries().size() > 1)
        {
            // make sure that all requests are targeted on the same CA
            for(EnrollCertRequestEntryType entry : request.getRequestEntries())
            {
                String profile = entry.getCertprofile();
                checkCertprofileSupportInCA(profile, caName);
            }
        }

        CAConf ca = casMap.get(caName);
        if(ca == null)
        {
            throw new CAClientException("could not find CA named " + caName);
        }

        EnrollCertResultType result;
        try
        {
            result = ca.getRequestor().requestCertificate(request, username, debug);
        } catch (CmpRequestorException e)
        {
            throw new CAClientException(e.getMessage(), e);
        }

        return parseEnrollCertResult((EnrollCertResultType) result, caName);
    }

    private void checkCertprofileSupportInCA(
            final String certprofile,
            String caName)
    throws CAClientException
    {
        if(caName != null)
        {
            if(casMap.containsKey(caName) == false)
            {
                throw new CAClientException("unknown ca: " + caName);
            }
            else
            {
                CAConf ca = casMap.get(caName);
                if(ca.supportsProfile(certprofile) == false)
                {
                    throw new CAClientException("cert profile " + certprofile
                            + " is not supported by the CA " + caName);
                }
            }
            return;
        }

        for(CAConf ca : casMap.values())
        {
            if(ca.isCAInfoConfigured() == false)
            {
                continue;
            }
            if(ca.supportsProfile(certprofile))
            {
                if(caName == null)
                {
                    caName = ca.getName();
                }
                else
                {
                    throw new CAClientException("cert profile " + certprofile
                            + " supported by more than one CA, please specify the CA name.");
                }
            }
        }

        if(caName == null)
        {
            throw new CAClientException("unsupported cert profile " + certprofile);
        }
    }

    @Override
    public CertIdOrError revokeCert(
            final X509Certificate cert,
            final int reason,
            final Date invalidityDate,
            final RequestResponseDebug debug)
    throws CAClientException, PKIErrorException
    {
        X500Name issuer = X500Name.getInstance(cert.getIssuerX500Principal().getEncoded());
        return revokeCert(issuer, cert.getSerialNumber(), reason, invalidityDate,debug);
    }

    @Override
    public CertIdOrError revokeCert(
            final X500Name issuer,
            final BigInteger serial,
            final int reason,
            final Date invalidityDate,
            final RequestResponseDebug debug)
    throws CAClientException, PKIErrorException
    {
        final String id = "cert-1";
        RevokeCertRequestEntryType entry =
                new RevokeCertRequestEntryType(id, issuer, serial, reason, invalidityDate);
        RevokeCertRequestType request = new RevokeCertRequestType();
        request.addRequestEntry(entry);
        Map<String, CertIdOrError> result = revokeCerts(request, debug);
        return (result == null)
                ? null
                : result.get(id);
    }

    @Override
    public Map<String, CertIdOrError> revokeCerts(
            final RevokeCertRequestType request,
            final RequestResponseDebug debug)
    throws CAClientException, PKIErrorException
    {
        ParamUtil.assertNotNull("request", request);

        List<RevokeCertRequestEntryType> requestEntries = request.getRequestEntries();
        if(CollectionUtil.isEmpty(requestEntries))
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
                        "revoking certificates issued by more than one CA is not allowed");
            }
        }

        final String caName = getCaNameByIssuer(issuer);
        X509CmpRequestor cmpRequestor = casMap.get(caName).getRequestor();
        RevokeCertResultType result;
        try
        {
            result = cmpRequestor.revokeCertificate(request, debug);
        } catch (CmpRequestorException e)
        {
            throw new CAClientException(e.getMessage(), e);
        }

        return parseRevokeCertResult(result);
    }

    private Map<String, CertIdOrError> parseRevokeCertResult(
            final RevokeCertResultType result)
    throws CAClientException
    {
        Map<String, CertIdOrError> ret = new HashMap<>();

        RevokeCertResultType _result = (RevokeCertResultType) result;
        for(ResultEntryType _entry : _result.getResultEntries())
        {
            CertIdOrError certIdOrError;
            if(_entry instanceof RevokeCertResultEntryType)
            {
                RevokeCertResultEntryType entry = (RevokeCertResultEntryType) _entry;
                certIdOrError = new CertIdOrError(entry.getCertId());
            }
            else if(_entry instanceof ErrorResultEntryType)
            {
                ErrorResultEntryType entry = (ErrorResultEntryType) _entry;
                certIdOrError = new CertIdOrError(entry.getStatusInfo());
            }
            else
            {
                throw new CAClientException("unknwon type " + _entry);
            }

            ret.put(_entry.getId(), certIdOrError);
        }

        return ret;
    }

    @Override
    public X509CRL downloadCRL(
            final String caName,
            final RequestResponseDebug debug)
    throws CAClientException, PKIErrorException
    {
        return downloadCRL(caName, (BigInteger) null, debug);
    }

    @Override
    public X509CRL downloadCRL(
            final String caName,
            final BigInteger crlNumber,
            final RequestResponseDebug debug)
    throws CAClientException, PKIErrorException
    {
        ParamUtil.assertNotNull("caName", caName);

        if(casMap.containsKey(caName) == false)
        {
            throw new IllegalArgumentException("unknown CAConf " + caName);
        }

        X509CmpRequestor requestor = casMap.get(caName).getRequestor();
        CRLResultType result;
        try
        {
            if(crlNumber == null)
            {
                result = requestor.downloadCurrentCRL(debug);
            }
            else
            {
                result = requestor.downloadCRL(crlNumber, debug);
            }
        } catch (CmpRequestorException e)
        {
            throw new CAClientException(e.getMessage(), e);
        }

        return result.getCRL();
    }

    @Override
    public X509CRL generateCRL(
            final String caName,
            final RequestResponseDebug debug)
    throws CAClientException, PKIErrorException
    {
        ParamUtil.assertNotNull("caName", caName);

        if(casMap.containsKey(caName) == false)
        {
            throw new IllegalArgumentException("unknown CAConf " + caName);
        }

        X509CmpRequestor requestor = casMap.get(caName).getRequestor();
        try
        {
            CRLResultType result = requestor.generateCRL(debug);
            return result.getCRL();
        } catch (CmpRequestorException e)
        {
            throw new CAClientException(e.getMessage(), e);
        }
    }

    @Override
    public String getCaNameByIssuer(
            final X500Name issuer)
    throws CAClientException
    {

        if(issuer == null )
        {
            throw new CAClientException("invalid issuer");
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

        throw new CAClientException("unknown CA for issuer: " + issuer);
    }

    private String getCANameForProfile(
            final String certprofile)
    throws CAClientException
    {
        String caName = null;
        for(CAConf ca : casMap.values())
        {
            if(ca.isCAInfoConfigured() == false)
            {
                continue;
            }

            if(ca.supportsProfile(certprofile))
            {
                if(caName == null)
                {
                    caName = ca.getName();
                }
                else
                {
                    throw new CAClientException("cert profile " + certprofile
                            + " supported by more than one CA, please specify the CA name.");
                }
            }
        }

        return caName;
    }

    private java.security.cert.Certificate getCertificate(
            final CMPCertificate cmpCert)
    throws CertificateException
    {
        Certificate bcCert = cmpCert.getX509v3PKCert();
        return (bcCert == null)
                ? null
                : new X509CertificateObject(bcCert);
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
    public byte[] envelope(
            final CertRequest certRequest,
            final ProofOfPossession pop,
            final String profileName,
            String caName,
            final String username)
    throws CAClientException
    {
        if(caName == null)
        {
            // detect the CA name
            caName = getCANameForProfile(profileName);
            if(caName == null)
            {
                throw new CAClientException("cert profile " + profileName
                        + " is not supported by any CA");
            }
        }
        else
        {
            checkCertprofileSupportInCA(profileName, caName);
        }

        CAConf ca = casMap.get(caName);
        if(ca == null)
        {
            throw new CAClientException("could not find CA named " + caName);
        }

        PKIMessage pkiMessage;
        try
        {
            pkiMessage = ca.getRequestor().envelope(certRequest, pop, profileName, username);
        } catch (CmpRequestorException e)
        {
            throw new CAClientException("CmpRequestorException: " + e.getMessage(), e);
        }

        try
        {
            return pkiMessage.getEncoded();
        } catch (IOException e)
        {
            throw new CAClientException("IOException: " + e.getMessage(), e);
        }
    }

    private boolean verify(
            final java.security.cert.Certificate caCert,
            final java.security.cert.Certificate cert)
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
                if(caPublicKey instanceof ECPublicKey || Security.getProvider(provider) == null)
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

                        LOG.info("use {} to verify {} signature", provider, sigAlgName);
                        tryXipkiNSStoVerify = Boolean.TRUE;
                        tryXipkiNSStoVerifyMap.put(_caCert, tryXipkiNSStoVerify);
                        return sigValid;
                    }catch(Exception e)
                    {
                        LOG.info("could not use {} to verify {} signature", provider, sigAlgName);
                        tryXipkiNSStoVerify = Boolean.FALSE;
                        tryXipkiNSStoVerifyMap.put(_caCert, tryXipkiNSStoVerify);
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
        } catch (SignatureException | InvalidKeyException | CertificateException
                | NoSuchAlgorithmException | NoSuchProviderException e)
        {
            LOG.debug("{} while verifying signature: {}", e.getClass().getName(), e.getMessage());
            return false;
        }
    }

    @Override
    public byte[] envelopeRevocation(
            final X500Name issuer,
            final BigInteger serial,
            final int reason)
    throws CAClientException
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
            throw new CAClientException(e.getMessage(), e);
        }
    }

    @Override
    public byte[] envelopeRevocation(
            final X509Certificate cert,
            final int reason)
    throws CAClientException
    {
        X500Name issuer = X500Name.getInstance(cert.getIssuerX500Principal().getEncoded());
        return envelopeRevocation(issuer, cert.getSerialNumber(), reason);
    }

    @Override
    public CertIdOrError unrevokeCert(
            final X500Name issuer,
            final BigInteger serial,
            final RequestResponseDebug debug)
    throws CAClientException, PKIErrorException
    {
        final String id = "cert-1";
        IssuerSerialEntryType entry =
                new IssuerSerialEntryType(id, issuer, serial);
        UnrevokeOrRemoveCertRequestType request = new UnrevokeOrRemoveCertRequestType();
        request.addRequestEntry(entry);
        Map<String, CertIdOrError> result = unrevokeCerts(request, debug);
        return (result == null)
                ? null
                : result.get(id);
    }

    @Override
    public CertIdOrError unrevokeCert(
            final X509Certificate cert,
            final RequestResponseDebug debug)
    throws CAClientException, PKIErrorException
    {
        X500Name issuer = X500Name.getInstance(cert.getIssuerX500Principal().getEncoded());
        return unrevokeCert(issuer, cert.getSerialNumber(), debug);
    }

    @Override
    public Map<String, CertIdOrError> unrevokeCerts(
            final UnrevokeOrRemoveCertRequestType request,
            final RequestResponseDebug debug)
    throws CAClientException, PKIErrorException
    {
        ParamUtil.assertNotNull("request", request);

        List<IssuerSerialEntryType> requestEntries = request.getRequestEntries();
        if(CollectionUtil.isEmpty(requestEntries))
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
                        "unrevoking certificates issued by more than one CA is not allowed");
            }
        }

        final String caName = getCaNameByIssuer(issuer);
        X509CmpRequestor cmpRequestor = casMap.get(caName).getRequestor();
        RevokeCertResultType result;
        try
        {
            result = cmpRequestor.unrevokeCertificate(request, debug);
        } catch (CmpRequestorException e)
        {
            throw new CAClientException(e.getMessage(), e);
        }

        return parseRevokeCertResult(result);
    }

    @Override
    public CertIdOrError removeCert(
            final X500Name issuer,
            final BigInteger serial,
            final RequestResponseDebug debug)
    throws CAClientException, PKIErrorException
    {
        final String id = "cert-1";
        IssuerSerialEntryType entry =
                new IssuerSerialEntryType(id, issuer, serial);
        UnrevokeOrRemoveCertRequestType request = new UnrevokeOrRemoveCertRequestType();
        request.addRequestEntry(entry);
        Map<String, CertIdOrError> result = removeCerts(request, debug);
        return (result == null)
                ? null
                : result.get(id);
    }

    @Override
    public CertIdOrError removeCert(
            final X509Certificate cert,
            final RequestResponseDebug debug)
    throws CAClientException, PKIErrorException
    {
        X500Name issuer = X500Name.getInstance(cert.getIssuerX500Principal().getEncoded());
        return removeCert(issuer, cert.getSerialNumber(), debug);
    }

    @Override
    public Map<String, CertIdOrError> removeCerts(
            final UnrevokeOrRemoveCertRequestType request,
            final RequestResponseDebug debug)
    throws CAClientException, PKIErrorException
    {
        ParamUtil.assertNotNull("request", request);

        List<IssuerSerialEntryType> requestEntries = request.getRequestEntries();
        if(CollectionUtil.isEmpty(requestEntries))
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
                        "removing certificates issued by more than one CA is not allowed");
            }
        }

        final String caName = getCaNameByIssuer(issuer);
        X509CmpRequestor cmpRequestor = casMap.get(caName).getRequestor();
        RevokeCertResultType result;
        try
        {
            result = cmpRequestor.removeCertificate(request, debug);
        } catch (CmpRequestorException e)
        {
            throw new CAClientException(e.getMessage(), e);
        }

        return parseRevokeCertResult(result);
    }

    @Override
    public Set<CertprofileInfo> getCertprofiles(
            final String caName)
    {
        CAConf ca = casMap.get(caName);
        if(ca == null)
        {
            return Collections.emptySet();
        }

        Set<String> profileNames = ca.getProfileNames();
        if(CollectionUtil.isEmpty(profileNames))
        {
            return Collections.emptySet();
        }

        Set<CertprofileInfo> ret = new HashSet<>(profileNames.size());
        for(String m : profileNames)
        {
            ret.add(ca.getProfile(m));
        }
        return ret;
    }

    @Override
    public HealthCheckResult getHealthCheckResult(
            final String caName)
    throws CAClientException
    {
        ParamUtil.assertNotNull("caName", caName);

        if(casMap.containsKey(caName) == false)
        {
            throw new IllegalArgumentException("unknown CAConf " + caName);
        }

        String healthUrlStr = casMap.get(caName).getHealthUrl();

        URL serverUrl;
        try
        {
            serverUrl = new URL(healthUrlStr);
        } catch (MalformedURLException e)
        {
            throw new CAClientException("invalid URL '" + healthUrlStr + "'");
        }

        String name = "X509CA";
        HealthCheckResult healthCheckResult = new HealthCheckResult(name);

        try
        {
            HttpURLConnection httpUrlConnection = (HttpURLConnection) serverUrl.openConnection();
            InputStream inputStream = httpUrlConnection.getInputStream();
            int responseCode = httpUrlConnection.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK
                    && responseCode != HttpURLConnection.HTTP_INTERNAL_ERROR)
            {
                inputStream.close();
                throw new IOException("bad response: "
                        + httpUrlConnection.getResponseCode() + "  "
                        + httpUrlConnection.getResponseMessage());
            }

            String responseContentType = httpUrlConnection.getContentType();
            boolean isValidContentType = false;
            if (responseContentType != null)
            {
                if (responseContentType.equalsIgnoreCase("application/json"))
                {
                    isValidContentType = true;
                }
            }
            if (isValidContentType == false)
            {
                inputStream.close();
                throw new IOException("bad response: mime type " + responseContentType
                        + " not supported!");
            }

            byte[] responseBytes = IoUtil.read(inputStream);
            if(responseBytes.length == 0)
            {
                healthCheckResult.setHealthy(responseCode == HttpURLConnection.HTTP_OK);
            }
            else
            {
                String response = new String(responseBytes);
                try
                {
                    healthCheckResult = HealthCheckResult.getInstanceFromJsonMessage(name,
                            response);
                }catch(IllegalArgumentException e)
                {
                    final String message = "IOException while parsing the health json message";
                    if(LOG.isErrorEnabled())
                    {
                        LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                                e.getMessage());
                    }
                    if(LOG.isDebugEnabled())
                    {
                        LOG.debug(message + ", json message: " + response, e);
                    }
                    healthCheckResult.setHealthy(false);
                }
            }
        }catch(IOException e)
        {
            final String message = "IOException while calling the URL " + healthUrlStr;
            if(LOG.isErrorEnabled())
            {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                        e.getMessage());
            }
            LOG.debug(message, e);

            healthCheckResult.setHealthy(false);
        }

        return healthCheckResult;
    }

    private static CAClientType parse(
            final InputStream configStream)
    throws InvalidConfException
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
            catch(SAXException e)
            {
                throw new InvalidConfException("parse profile failed, message: " + e.getMessage(),
                        e);
            } catch(JAXBException e)
            {
                throw new InvalidConfException("parse profile failed, message: "
                        + XMLUtil.getMessage((JAXBException) e), e);
            }

            if(root instanceof JAXBElement)
            {
                return (CAClientType) ((JAXBElement<?>)root).getValue();
            }
            else
            {
                throw new InvalidConfException("invalid root element type");
            }
        }
    }

    private EnrollCertResult parseEnrollCertResult(
            final EnrollCertResultType result,
            final String caName)
    throws CAClientException
    {
        Map<String, CertOrError> certOrErrors = new HashMap<>();
        for(ResultEntryType resultEntry : result.getResultEntries())
        {
            CertOrError certOrError;
            if(resultEntry instanceof EnrollCertResultEntryType)
            {
                EnrollCertResultEntryType entry = (EnrollCertResultEntryType) resultEntry;
                try
                {
                    java.security.cert.Certificate cert = getCertificate(entry.getCert());
                    certOrError = new CertOrError(cert);
                } catch (CertificateException e)
                {
                    throw new CAClientException(
                            "CertificateParsingException for request (id=" + entry.getId()+"): "
                            + e.getMessage());
                }
            }
            else if(resultEntry instanceof ErrorResultEntryType)
            {
                certOrError = new CertOrError(
                        ((ErrorResultEntryType) resultEntry).getStatusInfo());
            }
            else
            {
                certOrError = null;
            }

            certOrErrors.put(resultEntry.getId(), certOrError);
        }

        List<CMPCertificate> cmpCaPubs = result.getCACertificates();

        if(CollectionUtil.isEmpty(cmpCaPubs))
        {
            return new EnrollCertResult(null, certOrErrors);
        }

        List<java.security.cert.Certificate> caPubs = new ArrayList<>(cmpCaPubs.size());
        for(CMPCertificate cmpCaPub : cmpCaPubs)
        {
            try
            {
                caPubs.add(getCertificate(cmpCaPub));
            } catch (CertificateException e)
            {
                final String message = "could not extract the caPub from CMPCertificate";
                if(LOG.isErrorEnabled())
                {
                    LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                            e.getMessage());
                }
                LOG.debug(message, e);
            }
        }

        java.security.cert.Certificate caCert = null;
        for(CertOrError certOrError : certOrErrors.values())
        {
            java.security.cert.Certificate cert = certOrError.getCertificate();
            if(cert == null)
            {
                continue;
            }

            for(java.security.cert.Certificate caPub : caPubs)
            {
                if(verify(caPub, cert))
                {
                    caCert = caPub;
                    break;
                }
            }

            if(caCert != null)
            {
                break;
            }
        }

        if(caCert == null)
        {
            return new EnrollCertResult(null, certOrErrors);
        }

        for(CertOrError certOrError : certOrErrors.values())
        {
            java.security.cert.Certificate cert = certOrError.getCertificate();
            if(cert == null)
            {
                continue;
            }

            if(verify(caCert, cert) == false)
            {
                LOG.warn("not all certificates are issued by CA embedded in caPubs,"
                        + " ignore the caPubs");
                return new EnrollCertResult(null, certOrErrors);
            }
        }

        return new EnrollCertResult(caCert, certOrErrors);
    }

}
