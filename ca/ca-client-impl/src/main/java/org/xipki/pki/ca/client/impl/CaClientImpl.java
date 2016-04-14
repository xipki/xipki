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
import org.xipki.commons.common.HealthCheckResult;
import org.xipki.commons.common.InvalidConfException;
import org.xipki.commons.common.ObjectCreationException;
import org.xipki.commons.common.RequestResponseDebug;
import org.xipki.commons.common.util.CollectionUtil;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.common.util.XmlUtil;
import org.xipki.commons.security.api.ConcurrentContentSigner;
import org.xipki.commons.security.api.SecurityFactory;
import org.xipki.commons.security.api.SignerConf;
import org.xipki.commons.security.api.XiSecurityConstants;
import org.xipki.commons.security.api.util.X509Util;
import org.xipki.pki.ca.client.api.CaClient;
import org.xipki.pki.ca.client.api.CaClientException;
import org.xipki.pki.ca.client.api.CertIdOrError;
import org.xipki.pki.ca.client.api.CertOrError;
import org.xipki.pki.ca.client.api.CertprofileInfo;
import org.xipki.pki.ca.client.api.EnrollCertResult;
import org.xipki.pki.ca.client.api.PkiErrorException;
import org.xipki.pki.ca.client.api.dto.EnrollCertRequest;
import org.xipki.pki.ca.client.api.dto.EnrollCertRequestEntry;
import org.xipki.pki.ca.client.api.dto.EnrollCertResultEntry;
import org.xipki.pki.ca.client.api.dto.EnrollCertResultResp;
import org.xipki.pki.ca.client.api.dto.ErrorResultEntry;
import org.xipki.pki.ca.client.api.dto.IssuerSerialEntry;
import org.xipki.pki.ca.client.api.dto.P10EnrollCertRequest;
import org.xipki.pki.ca.client.api.dto.ResultEntry;
import org.xipki.pki.ca.client.api.dto.RevokeCertRequest;
import org.xipki.pki.ca.client.api.dto.RevokeCertRequestEntry;
import org.xipki.pki.ca.client.api.dto.RevokeCertResultEntry;
import org.xipki.pki.ca.client.api.dto.RevokeCertResultType;
import org.xipki.pki.ca.client.api.dto.UnrevokeOrRemoveCertRequest;
import org.xipki.pki.ca.client.impl.jaxb.CAClientType;
import org.xipki.pki.ca.client.impl.jaxb.CAType;
import org.xipki.pki.ca.client.impl.jaxb.CertprofileType;
import org.xipki.pki.ca.client.impl.jaxb.CertprofilesType;
import org.xipki.pki.ca.client.impl.jaxb.FileOrValueType;
import org.xipki.pki.ca.client.impl.jaxb.ObjectFactory;
import org.xipki.pki.ca.client.impl.jaxb.RequestorType;
import org.xipki.pki.ca.client.impl.jaxb.ResponderType;
import org.xml.sax.SAXException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public final class CaClientImpl implements CaClient {

    private class ClientConfigUpdater implements Runnable {

        private static final long MINUTE = 60L * 1000;

        private AtomicBoolean inProcess = new AtomicBoolean(false);

        private long lastUpdate;

        ClientConfigUpdater() {
        }

        @Override
        public void run() {
            if (inProcess.get()) {
                return;
            }

            inProcess.set(true);

            try {
                // just updated within the last 2 minutes
                if (System.currentTimeMillis() - lastUpdate < 2 * MINUTE) {
                    return;
                }

                autoConfCas(null);
            } finally {
                lastUpdate = System.currentTimeMillis();
                inProcess.set(false);
            }
        }

    } // class ClientConfigUpdater

    private static final Logger LOG = LoggerFactory.getLogger(CaClientImpl.class);

    private static Object jaxbUnmarshallerLock = new Object();

    private static Unmarshaller jaxbUnmarshaller;

    private final Map<String, CaConf> casMap = new HashMap<>();

    private SecurityFactory securityFactory;

    private String confFile;

    private Map<X509Certificate, Boolean> tryNssToVerifyMap = new ConcurrentHashMap<>();

    private ScheduledThreadPoolExecutor scheduledThreadPoolExecutor;

    public CaClientImpl() {
    }

    public void setSecurityFactory(
            final SecurityFactory securityFactory) {
        this.securityFactory = securityFactory;
    }

    /**
     *
     * @return names of CAs which must not been configured.
     */
    private Set<String> autoConfCas(
            final Set<String> caNamesToBeConfigured) {
        Set<String> caNamesWithError = new HashSet<>();

        Set<String> errorCaNames = new HashSet<>();
        for (String name : casMap.keySet()) {
            if (caNamesToBeConfigured != null && !caNamesToBeConfigured.contains(name)) {
                continue;
            }

            CaConf ca = casMap.get(name);

            if (!ca.isCertAutoconf() && !ca.isCertprofilesAutoconf()) {
                continue;
            }

            try {
                CaInfo caInfo = ca.getRequestor().retrieveCaInfo(name, null);
                if (ca.isCertAutoconf()) {
                    ca.setCert(caInfo.getCert());
                }
                if (ca.isCertprofilesAutoconf()) {
                    ca.setCertprofiles(caInfo.getCertprofiles());
                }
                LOG.info("retrieved CAInfo for CA " + name);
            } catch (Throwable th) {
                errorCaNames.add(name);
                caNamesWithError.add(name);
                final String message = "could not retrieve CAInfo for CA " + name;
                LOG.error(LogUtil.getErrorLog(message), th.getClass().getName(), th.getMessage());
                LOG.debug(message, th);
            }
        }

        if (CollectionUtil.isNonEmpty(errorCaNames)) {
            for (String caName : errorCaNames) {
                casMap.remove(caName);
            }
        }

        return caNamesWithError;
    } // method autoConfCas

    public void asynInit() {
        Runnable initRun = new Runnable() {
            @Override
            public void run() {
                try {
                    init();
                } catch (Throwable th) {
                    String msg = "could not init";
                    LOG.error(msg, th.getMessage());
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(LogUtil.getErrorLog(msg), th.getClass().getName(),
                                th.getMessage());
                    }
                }
            }
        };
        new Thread(initRun).start();
    }

    public void init()
    throws InvalidConfException, IOException {
        ParamUtil.requireNonNull("confFile", confFile);
        ParamUtil.requireNonNull("securityFactory", securityFactory);

        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        File configFile = new File(IoUtil.expandFilepath(confFile));
        if (!configFile.exists()) {
            throw new FileNotFoundException("cound not find configuration file " + confFile);
        }

        CAClientType config = parse(new FileInputStream(configFile));
        int numActiveCAs = 0;

        for (CAType caType : config.getCAs().getCA()) {
            if (!caType.isEnabled()) {
                LOG.info("CA " + caType.getName() + " is disabled");
                continue;
            }
            numActiveCAs++;
        }

        if (numActiveCAs == 0) {
            LOG.warn("no active CA is configured");
        }

        Boolean bo = config.isDevMode();
        boolean devMode = bo != null && bo.booleanValue();

        // responders
        Map<String, X509Certificate> responders = new HashMap<>();
        for (ResponderType m : config.getResponders().getResponder()) {
            X509Certificate cert;
            try {
                cert = X509Util.parseCert(readData(m.getCert()));
            } catch (CertificateException ex) {
                final String message = "could not configure responder " + m.getName();
                LOG.error(LogUtil.getErrorLog(message), ex.getClass().getName(), ex.getMessage());
                LOG.debug(message, ex);

                throw new InvalidConfException(ex.getMessage(), ex);
            }
            responders.put(m.getName(), cert);
        }

        // CA
        Set<String> configuredCaNames = new HashSet<>();

        Set<CaConf> cas = new HashSet<>();
        for (CAType caType : config.getCAs().getCA()) {
            bo = caType.isEnabled();
            if (!bo.booleanValue()) {
                continue;
            }

            String caName = caType.getName();
            try {
                // responder
                X509Certificate responder = responders.get(caType.getResponder());
                if (responder == null) {
                    throw new InvalidConfException("no responder named " + caType.getResponder()
                            + " is configured");
                }
                CaConf ca = new CaConf(caName, caType.getUrl(), caType.getHealthUrl(),
                        caType.getRequestor(), responder);

                // CA cert
                if (caType.getCaCert().getAutoconf() != null) {
                    ca.setCertAutoconf(true);
                } else {
                    ca.setCertAutoconf(true);
                    ca.setCert(X509Util.parseCert(readData(caType.getCaCert().getCert())));
                }

                // Certprofiles
                CertprofilesType certprofilesType = caType.getCertprofiles();
                if (certprofilesType.getAutoconf() != null) {
                    ca.setCertprofilesAutoconf(true);
                } else {
                    ca.setCertprofilesAutoconf(false);

                    List<CertprofileType> types = certprofilesType.getCertprofile();
                    Set<CertprofileInfo> profiles = new HashSet<>(types.size());
                    for (CertprofileType m : types) {
                        String conf = null;
                        if (m.getConf() != null) {
                            conf = m.getConf().getValue();
                            if (conf == null) {
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
            } catch (IOException | CertificateException ex) {
                final String message = "could not configure CA " + caName;
                LOG.error(LogUtil.getErrorLog(message), ex.getClass().getName(), ex.getMessage());
                LOG.debug(message, ex);

                if (!devMode) {
                    throw new InvalidConfException(ex.getMessage(), ex);
                }
            }
        }

        // requestors
        Map<String, X509Certificate> requestorCerts = new HashMap<>();
        Map<String, ConcurrentContentSigner> requestorSigners = new HashMap<>();
        Map<String, Boolean> requestorSignRequests = new HashMap<>();

        for (RequestorType requestorConf : config.getRequestors().getRequestor()) {
            String name = requestorConf.getName();
            requestorSignRequests.put(name, requestorConf.isSignRequest());

            X509Certificate requestorCert = null;
            if (requestorConf.getCert() != null) {
                try {
                    requestorCert = X509Util.parseCert(readData(requestorConf.getCert()));
                    requestorCerts.put(name, requestorCert);
                } catch (Exception ex) {
                    throw new InvalidConfException(ex.getMessage(), ex);
                }
            }

            if (requestorConf.getSignerType() != null) {
                try {
                    SignerConf signerConf = new SignerConf(requestorConf.getSignerConf());
                    ConcurrentContentSigner requestorSigner = securityFactory.createSigner(
                            requestorConf.getSignerType(), signerConf, requestorCert);
                    requestorSigners.put(name, requestorSigner);
                } catch (ObjectCreationException ex) {
                    throw new InvalidConfException(ex.getMessage(), ex);
                }
            } else {
                if (requestorConf.isSignRequest()) {
                    throw new InvalidConfException("signer of requestor must be configured");
                } else if (requestorCert == null) {
                    throw new InvalidConfException(
                        "at least one of certificate and signer of requestor must be configured");
                }
            }
        }

        boolean autoConf = false;
        for (CaConf ca :cas) {
            if (this.casMap.containsKey(ca.getName())) {
                throw new InvalidConfException("duplicate CAs with the same name " + ca.getName());
            }

            if (ca.isCertAutoconf() || ca.isCertprofilesAutoconf()) {
                autoConf = true;
            }

            String requestorName = ca.getRequestorName();

            X509CmpRequestor cmpRequestor;
            if (requestorSigners.containsKey(requestorName)) {
                cmpRequestor = new DefaultHttpX509CmpRequestor(
                        requestorSigners.get(requestorName), ca.getResponder(), ca.getUrl(),
                        securityFactory, requestorSignRequests.get(requestorName));
            } else if (requestorCerts.containsKey(requestorName)) {
                cmpRequestor = new DefaultHttpX509CmpRequestor(
                        requestorCerts.get(requestorName), ca.getResponder(), ca.getUrl(),
                        securityFactory);
            } else {
                throw new InvalidConfException("could not find requestor named "
                        + requestorName
                        + " for CA " + ca.getName());
            }

            ca.setRequestor(cmpRequestor);
            this.casMap.put(ca.getName(), ca);
        }

        if (autoConf) {
            Integer caInfoUpdateInterval = config.getCAs().getCAInfoUpdateInterval();
            if (caInfoUpdateInterval == null) {
                caInfoUpdateInterval = 10;
            } else if (caInfoUpdateInterval <= 0) {
                caInfoUpdateInterval = 0;
            } else if (caInfoUpdateInterval < 5) {
                caInfoUpdateInterval = 5;
            }

            Set<String> caNames = casMap.keySet();
            StringBuilder sb = new StringBuilder("configuring CAs ");
            sb.append(caNames);

            LOG.info(sb.toString());
            caNames = autoConfCas(caNames);

            if (CollectionUtil.isNonEmpty(caNames)) {
                final String msg = "could not configured following CAs " + caNames;
                if (devMode) {
                    LOG.warn(msg);
                } else {
                    throw new InvalidConfException(msg);
                }
            }

            if (caInfoUpdateInterval > 0) {
                scheduledThreadPoolExecutor = new ScheduledThreadPoolExecutor(1);
                scheduledThreadPoolExecutor.scheduleAtFixedRate(
                        new ClientConfigUpdater(),
                        caInfoUpdateInterval, caInfoUpdateInterval, TimeUnit.MINUTES);
            }
        }
    } // method init

    public void shutdown() {
        if (scheduledThreadPoolExecutor != null) {
            scheduledThreadPoolExecutor.shutdown();
            while (!scheduledThreadPoolExecutor.isTerminated()) {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException ex) {
                    LOG.warn("interrupted: {}", ex.getMessage());
                }
            }
            scheduledThreadPoolExecutor = null;
        }
    }

    @Override
    public EnrollCertResult requestCert(
            final CertificationRequest p10Request,
            final String profile,
            final String caName,
            final String username,
            final RequestResponseDebug debug)
    throws CaClientException, PkiErrorException {
        ParamUtil.requireNonNull("p10Request", p10Request);

        String tmpCaName = caName;
        if (tmpCaName == null) {
            tmpCaName = getCaNameForProfile(profile);
        }

        if (tmpCaName == null) {
            throw new CaClientException("cert profile " + profile + " is not supported by any CA");
        }

        CaConf ca = casMap.get(tmpCaName.trim());
        if (ca == null) {
            throw new CaClientException("could not find CA named " + tmpCaName);
        }

        final String id = "cert-1";
        P10EnrollCertRequest request = new P10EnrollCertRequest(id, profile, p10Request);
        EnrollCertResultResp result;
        try {
            result = ca.getRequestor().requestCertificate(request, username, debug);
        } catch (CmpRequestorException ex) {
            throw new CaClientException(ex.getMessage(), ex);
        }

        return parseEnrollCertResult((EnrollCertResultResp) result, tmpCaName);
    } // method requestCert

    @Override
    public EnrollCertResult requestCerts(
            final EnrollCertRequest request,
            final String caName,
            final String username,
            final RequestResponseDebug debug)
    throws CaClientException, PkiErrorException {
        ParamUtil.requireNonNull("request", request);

        List<EnrollCertRequestEntry> requestEntries = request.getRequestEntries();
        if (CollectionUtil.isEmpty(requestEntries)) {
            return null;
        }

        String tmpCaName = caName;
        boolean bo = (tmpCaName != null);
        if (tmpCaName == null) {
            // detect the CA name
            String profile = requestEntries.get(0).getCertprofile();
            tmpCaName = getCaNameForProfile(profile);
            if (tmpCaName == null) {
                throw new CaClientException("cert profile " + profile
                        + " is not supported by any CA");
            }
        }

        if (bo || request.getRequestEntries().size() > 1) {
            // make sure that all requests are targeted on the same CA
            for (EnrollCertRequestEntry entry : request.getRequestEntries()) {
                String profile = entry.getCertprofile();
                checkCertprofileSupportInCa(profile, tmpCaName);
            }
        }

        CaConf ca = casMap.get(tmpCaName.trim());
        if (ca == null) {
            throw new CaClientException("could not find CA named " + tmpCaName);
        }

        EnrollCertResultResp result;
        try {
            result = ca.getRequestor().requestCertificate(request, username, debug);
        } catch (CmpRequestorException ex) {
            throw new CaClientException(ex.getMessage(), ex);
        }

        return parseEnrollCertResult((EnrollCertResultResp) result, tmpCaName);
    } // method requestCerts

    private void checkCertprofileSupportInCa(
            final String certprofile,
            final String caName)
    throws CaClientException {
        String tmpCaName = caName;
        if (tmpCaName != null) {
            CaConf ca = casMap.get(tmpCaName.trim());
            if (ca == null) {
                throw new CaClientException("unknown ca: " + tmpCaName);
            } else {
                if (!ca.supportsProfile(certprofile)) {
                    throw new CaClientException("cert profile " + certprofile
                            + " is not supported by the CA " + tmpCaName);
                }
            }
            return;
        }

        for (CaConf ca : casMap.values()) {
            if (!ca.isCaInfoConfigured()) {
                continue;
            }
            if (!ca.supportsProfile(certprofile)) {
                continue;
            }

            if (tmpCaName == null) {
                tmpCaName = ca.getName();
            } else {
                throw new CaClientException("cert profile " + certprofile
                        + " supported by more than one CA, please specify the CA name.");
            }
        }

        if (tmpCaName == null) {
            throw new CaClientException("unsupported cert profile " + certprofile);
        }
    }

    @Override
    public CertIdOrError revokeCert(
            final X509Certificate cert,
            final int reason,
            final Date invalidityDate,
            final RequestResponseDebug debug)
    throws CaClientException, PkiErrorException {
        ParamUtil.requireNonNull("cert", cert);

        X500Name issuer = X500Name.getInstance(cert.getIssuerX500Principal().getEncoded());
        return revokeCert(issuer, cert.getSerialNumber(), reason, invalidityDate, debug);
    }

    @Override
    public CertIdOrError revokeCert(
            final X500Name issuer,
            final BigInteger serial,
            final int reason,
            final Date invalidityDate,
            final RequestResponseDebug debug)
    throws CaClientException, PkiErrorException {
        ParamUtil.requireNonNull("issuer", issuer);
        ParamUtil.requireNonNull("serial", serial);

        final String id = "cert-1";
        RevokeCertRequestEntry entry =
                new RevokeCertRequestEntry(id, issuer, serial, reason, invalidityDate);
        RevokeCertRequest request = new RevokeCertRequest();
        request.addRequestEntry(entry);
        Map<String, CertIdOrError> result = revokeCerts(request, debug);
        return (result == null)
                ? null
                : result.get(id);
    }

    @Override
    public Map<String, CertIdOrError> revokeCerts(
            final RevokeCertRequest request,
            final RequestResponseDebug debug)
    throws CaClientException, PkiErrorException {
        ParamUtil.requireNonNull("request", request);

        List<RevokeCertRequestEntry> requestEntries = request.getRequestEntries();
        if (CollectionUtil.isEmpty(requestEntries)) {
            return Collections.emptyMap();
        }

        X500Name issuer = requestEntries.get(0).getIssuer();
        for (int i = 1; i < requestEntries.size(); i++) {
            if (!issuer.equals(requestEntries.get(i).getIssuer())) {
                throw new PkiErrorException(
                        PKIStatus.REJECTION, PKIFailureInfo.badRequest,
                        "revoking certificates issued by more than one CA is not allowed");
            }
        }

        final String caName = getCaNameByIssuer(issuer);
        X509CmpRequestor cmpRequestor = casMap.get(caName).getRequestor();
        RevokeCertResultType result;
        try {
            result = cmpRequestor.revokeCertificate(request, debug);
        } catch (CmpRequestorException ex) {
            throw new CaClientException(ex.getMessage(), ex);
        }

        return parseRevokeCertResult(result);
    }

    private Map<String, CertIdOrError> parseRevokeCertResult(
            final RevokeCertResultType result)
    throws CaClientException {
        Map<String, CertIdOrError> ret = new HashMap<>();

        for (ResultEntry re : result.getResultEntries()) {
            CertIdOrError certIdOrError;
            if (re instanceof RevokeCertResultEntry) {
                RevokeCertResultEntry entry = (RevokeCertResultEntry) re;
                certIdOrError = new CertIdOrError(entry.getCertId());
            } else if (re instanceof ErrorResultEntry) {
                ErrorResultEntry entry = (ErrorResultEntry) re;
                certIdOrError = new CertIdOrError(entry.getStatusInfo());
            } else {
                throw new CaClientException("unknwon type " + re);
            }

            ret.put(re.getId(), certIdOrError);
        }

        return ret;
    }

    @Override
    public X509CRL downloadCrl(
            final String caName,
            final RequestResponseDebug debug)
    throws CaClientException, PkiErrorException {
        ParamUtil.requireNonNull("caName", caName);
        return downloadCrl(caName, (BigInteger) null, debug);
    }

    @Override
    public X509CRL downloadCrl(
            final String caName,
            final BigInteger crlNumber,
            final RequestResponseDebug debug)
    throws CaClientException, PkiErrorException {
        ParamUtil.requireNonNull("caName", caName);

        CaConf ca = casMap.get(caName.trim());
        if (ca == null) {
            throw new IllegalArgumentException("unknown CA " + caName);
        }

        X509CmpRequestor requestor = ca.getRequestor();
        X509CRL result;
        try {
            if (crlNumber == null) {
                result = requestor.downloadCurrentCrl(debug);
            } else {
                result = requestor.downloadCrl(crlNumber, debug);
            }
        } catch (CmpRequestorException ex) {
            throw new CaClientException(ex.getMessage(), ex);
        }

        return result;
    }

    @Override
    public X509CRL generateCrl(
            final String caName,
            final RequestResponseDebug debug)
    throws CaClientException, PkiErrorException {
        ParamUtil.requireNonNull("caName", caName);

        CaConf ca = casMap.get(caName.trim());
        if (ca == null) {
            throw new IllegalArgumentException("unknown CA " + caName);
        }

        X509CmpRequestor requestor = ca.getRequestor();
        try {
            return requestor.generateCrl(debug);
        } catch (CmpRequestorException ex) {
            throw new CaClientException(ex.getMessage(), ex);
        }
    }

    @Override
    public String getCaNameByIssuer(
            final X500Name issuer)
    throws CaClientException {
        ParamUtil.requireNonNull("issuer", issuer);

        for (String name : casMap.keySet()) {
            final CaConf ca = casMap.get(name);
            if (!ca.isCaInfoConfigured()) {
                continue;
            }

            if (ca.getSubject().equals(issuer)) {
                return name;
            }
        }

        throw new CaClientException("unknown CA for issuer: " + issuer);
    }

    private String getCaNameForProfile(
            final String certprofile)
    throws CaClientException {
        String caName = null;
        for (CaConf ca : casMap.values()) {
            if (!ca.isCaInfoConfigured()) {
                continue;
            }

            if (!ca.supportsProfile(certprofile)) {
                continue;
            }

            if (caName == null) {
                caName = ca.getName();
            } else {
                throw new CaClientException("cert profile " + certprofile
                        + " supported by more than one CA, please specify the CA name.");
            }
        }

        return caName;
    }

    private java.security.cert.Certificate getCertificate(
            final CMPCertificate cmpCert)
    throws CertificateException {
        Certificate bcCert = cmpCert.getX509v3PKCert();
        return (bcCert == null)
                ? null
                : new X509CertificateObject(bcCert);
    }

    public String getConfFile() {
        return confFile;
    }

    public void setConfFile(String confFile) {
        this.confFile = ParamUtil.requireNonBlank("confFile", confFile);
    }

    @Override
    public Set<String> getCaNames() {
        return casMap.keySet();
    }

    @Override
    public byte[] envelope(
            final CertRequest certRequest,
            final ProofOfPossession pop,
            final String profileName,
            final String caName,
            final String username)
    throws CaClientException {
        ParamUtil.requireNonNull("certRequest", certRequest);
        ParamUtil.requireNonNull("pop", pop);
        ParamUtil.requireNonNull("profileName", profileName);

        String tmpCaName = caName;
        if (tmpCaName == null) {
            // detect the CA name
            tmpCaName = getCaNameForProfile(profileName);
            if (tmpCaName == null) {
                throw new CaClientException("cert profile " + profileName
                        + " is not supported by any CA");
            }
        } else {
            checkCertprofileSupportInCa(profileName, tmpCaName);
        }

        CaConf ca = casMap.get(tmpCaName.trim());
        if (ca == null) {
            throw new CaClientException("could not find CA named " + tmpCaName);
        }

        PKIMessage pkiMessage;
        try {
            pkiMessage = ca.getRequestor().envelope(certRequest, pop, profileName, username);
        } catch (CmpRequestorException ex) {
            throw new CaClientException("CmpRequestorException: " + ex.getMessage(), ex);
        }

        try {
            return pkiMessage.getEncoded();
        } catch (IOException ex) {
            throw new CaClientException("IOException: " + ex.getMessage(), ex);
        }
    } // method envelope

    private boolean verify(
            final java.security.cert.Certificate caCert,
            final java.security.cert.Certificate cert) {
        if (!(caCert instanceof X509Certificate)) {
            return false;
        }
        if (!(cert instanceof X509Certificate)) {
            return false;
        }

        X509Certificate x509caCert = (X509Certificate) caCert;
        X509Certificate x509cert = (X509Certificate) cert;

        if (!x509cert.getIssuerX500Principal().equals(x509caCert.getSubjectX500Principal())) {
            return false;
        }

        boolean inLoadTest = Boolean.getBoolean("org.xipki.loadtest");
        if (inLoadTest) {
            return true;
        }

        final String provider = XiSecurityConstants.PROVIDER_NAME_NSS;
        Boolean tryNssToVerify = tryNssToVerifyMap.get(x509caCert);
        PublicKey caPublicKey = x509caCert.getPublicKey();
        try {
            if (tryNssToVerify == null) {
                if (Security.getProvider(provider) == null) {
                    tryNssToVerify = Boolean.FALSE;
                    tryNssToVerifyMap.put(x509caCert, tryNssToVerify);
                } else {
                    byte[] tbs = x509cert.getTBSCertificate();
                    byte[] signatureValue = x509cert.getSignature();
                    String sigAlgName = x509cert.getSigAlgName();
                    try {
                        Signature verifier = Signature.getInstance(sigAlgName, provider);
                        verifier.initVerify(caPublicKey);
                        verifier.update(tbs);

                        LOG.info("use {} to verify {} signature", provider, sigAlgName);
                        tryNssToVerify = Boolean.TRUE;
                        tryNssToVerifyMap.put(x509caCert, tryNssToVerify);
                        return verifier.verify(signatureValue);
                    } catch (Exception ex) {
                        LOG.info("could not use {} to verify {} signature", provider, sigAlgName);
                        tryNssToVerify = Boolean.FALSE;
                        tryNssToVerifyMap.put(x509caCert, tryNssToVerify);
                    }
                }
            }

            if (tryNssToVerify) {
                byte[] tbs = x509cert.getTBSCertificate();
                byte[] signatureValue = x509cert.getSignature();
                String sigAlgName = x509cert.getSigAlgName();
                Signature verifier = Signature.getInstance(sigAlgName, provider);
                verifier.initVerify(caPublicKey);
                verifier.update(tbs);
                return verifier.verify(signatureValue);
            } else {
                x509cert.verify(caPublicKey);
                return true;
            }
        } catch (SignatureException | InvalidKeyException | CertificateException
                | NoSuchAlgorithmException | NoSuchProviderException ex) {
            LOG.debug("{} while verifying signature: {}", ex.getClass().getName(), ex.getMessage());
            return false;
        }
    } // method verify

    @Override
    public byte[] envelopeRevocation(
            final X500Name issuer,
            final BigInteger serial,
            final int reason)
    throws CaClientException {
        ParamUtil.requireNonNull("issuer", issuer);
        final String id = "cert-1";
        RevokeCertRequestEntry entry =
                new RevokeCertRequestEntry(id, issuer, serial, reason, null);
        RevokeCertRequest request = new RevokeCertRequest();
        request.addRequestEntry(entry);

        String caName = getCaNameByIssuer(issuer);
        X509CmpRequestor cmpRequestor = casMap.get(caName).getRequestor();

        try {
            PKIMessage pkiMessage = cmpRequestor.envelopeRevocation(request);
            return pkiMessage.getEncoded();
        } catch (CmpRequestorException | IOException ex) {
            throw new CaClientException(ex.getMessage(), ex);
        }
    }

    @Override
    public byte[] envelopeRevocation(
            final X509Certificate cert,
            final int reason)
    throws CaClientException {
        ParamUtil.requireNonNull("cert", cert);
        X500Name issuer = X500Name.getInstance(cert.getIssuerX500Principal().getEncoded());
        return envelopeRevocation(issuer, cert.getSerialNumber(), reason);
    }

    @Override
    public CertIdOrError unrevokeCert(
            final X500Name issuer,
            final BigInteger serial,
            final RequestResponseDebug debug)
    throws CaClientException, PkiErrorException {
        ParamUtil.requireNonNull("issuer", issuer);
        ParamUtil.requireNonNull("serial", serial);
        final String id = "cert-1";
        IssuerSerialEntry entry =
                new IssuerSerialEntry(id, issuer, serial);
        UnrevokeOrRemoveCertRequest request = new UnrevokeOrRemoveCertRequest();
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
    throws CaClientException, PkiErrorException {
        ParamUtil.requireNonNull("cert", cert);
        X500Name issuer = X500Name.getInstance(cert.getIssuerX500Principal().getEncoded());
        return unrevokeCert(issuer, cert.getSerialNumber(), debug);
    }

    @Override
    public Map<String, CertIdOrError> unrevokeCerts(
            final UnrevokeOrRemoveCertRequest request,
            final RequestResponseDebug debug)
    throws CaClientException, PkiErrorException {
        ParamUtil.requireNonNull("request", request);

        List<IssuerSerialEntry> requestEntries = request.getRequestEntries();
        if (CollectionUtil.isEmpty(requestEntries)) {
            return Collections.emptyMap();
        }

        X500Name issuer = requestEntries.get(0).getIssuer();
        for (int i = 1; i < requestEntries.size(); i++) {
            if (!issuer.equals(requestEntries.get(i).getIssuer())) {
                throw new PkiErrorException(
                        PKIStatus.REJECTION, PKIFailureInfo.badRequest,
                        "unrevoking certificates issued by more than one CA is not allowed");
            }
        }

        final String caName = getCaNameByIssuer(issuer);
        X509CmpRequestor cmpRequestor = casMap.get(caName).getRequestor();
        RevokeCertResultType result;
        try {
            result = cmpRequestor.unrevokeCertificate(request, debug);
        } catch (CmpRequestorException ex) {
            throw new CaClientException(ex.getMessage(), ex);
        }

        return parseRevokeCertResult(result);
    } // method unrevokeCerts

    @Override
    public CertIdOrError removeCert(
            final X500Name issuer,
            final BigInteger serial,
            final RequestResponseDebug debug)
    throws CaClientException, PkiErrorException {
        ParamUtil.requireNonNull("issuer", issuer);
        ParamUtil.requireNonNull("serial", serial);
        final String id = "cert-1";
        IssuerSerialEntry entry = new IssuerSerialEntry(id, issuer, serial);
        UnrevokeOrRemoveCertRequest request = new UnrevokeOrRemoveCertRequest();
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
    throws CaClientException, PkiErrorException {
        ParamUtil.requireNonNull("cert", cert);
        X500Name issuer = X500Name.getInstance(cert.getIssuerX500Principal().getEncoded());
        return removeCert(issuer, cert.getSerialNumber(), debug);
    }

    @Override
    public Map<String, CertIdOrError> removeCerts(
            final UnrevokeOrRemoveCertRequest request,
            final RequestResponseDebug debug)
    throws CaClientException, PkiErrorException {
        ParamUtil.requireNonNull("request", request);

        List<IssuerSerialEntry> requestEntries = request.getRequestEntries();
        if (CollectionUtil.isEmpty(requestEntries)) {
            return Collections.emptyMap();
        }

        X500Name issuer = requestEntries.get(0).getIssuer();
        for (int i = 1; i < requestEntries.size(); i++) {
            if (!issuer.equals(requestEntries.get(i).getIssuer())) {
                throw new PkiErrorException(
                        PKIStatus.REJECTION, PKIFailureInfo.badRequest,
                        "removing certificates issued by more than one CA is not allowed");
            }
        }

        final String caName = getCaNameByIssuer(issuer);
        X509CmpRequestor cmpRequestor = casMap.get(caName).getRequestor();
        RevokeCertResultType result;
        try {
            result = cmpRequestor.removeCertificate(request, debug);
        } catch (CmpRequestorException ex) {
            throw new CaClientException(ex.getMessage(), ex);
        }

        return parseRevokeCertResult(result);
    }

    @Override
    public Set<CertprofileInfo> getCertprofiles(
            final String caName) {
        ParamUtil.requireNonNull("caName", caName);

        CaConf ca = casMap.get(caName.trim());
        if (ca == null) {
            return Collections.emptySet();
        }

        Set<String> profileNames = ca.getProfileNames();
        if (CollectionUtil.isEmpty(profileNames)) {
            return Collections.emptySet();
        }

        Set<CertprofileInfo> ret = new HashSet<>(profileNames.size());
        for (String m : profileNames) {
            ret.add(ca.getProfile(m));
        }
        return ret;
    }

    @Override
    public HealthCheckResult getHealthCheckResult(
            final String caName)
    throws CaClientException {
        ParamUtil.requireNonNull("caName", caName);

        CaConf ca = casMap.get(caName.trim());
        if (ca == null) {
            throw new IllegalArgumentException("unknown CA " + caName);
        }

        String healthUrlStr = ca.getHealthUrl();

        URL serverUrl;
        try {
            serverUrl = new URL(healthUrlStr);
        } catch (MalformedURLException ex) {
            throw new CaClientException("invalid URL '" + healthUrlStr + "'");
        }

        String name = "X509CA";
        HealthCheckResult healthCheckResult = new HealthCheckResult(name);

        try {
            HttpURLConnection httpUrlConnection = (HttpURLConnection) serverUrl.openConnection();
            InputStream inputStream = httpUrlConnection.getInputStream();
            int responseCode = httpUrlConnection.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK
                    && responseCode != HttpURLConnection.HTTP_INTERNAL_ERROR) {
                inputStream.close();
                throw new IOException(String.format(
                        "bad response: code='%s', message='%s'",
                        httpUrlConnection.getResponseCode(),
                        httpUrlConnection.getResponseMessage()));
            }

            String responseContentType = httpUrlConnection.getContentType();
            boolean isValidContentType = false;
            if (responseContentType != null) {
                if ("application/json".equalsIgnoreCase(responseContentType)) {
                    isValidContentType = true;
                }
            }
            if (!isValidContentType) {
                inputStream.close();
                throw new IOException("bad response: mime type " + responseContentType
                        + " not supported!");
            }

            byte[] responseBytes = IoUtil.read(inputStream);
            if (responseBytes.length == 0) {
                healthCheckResult.setHealthy(responseCode == HttpURLConnection.HTTP_OK);
            } else {
                String response = new String(responseBytes);
                try {
                    healthCheckResult = HealthCheckResult.getInstanceFromJsonMessage(name,
                            response);
                } catch (IllegalArgumentException ex) {
                    final String message = "IOException while parsing the health json message";
                    LOG.error(LogUtil.getErrorLog(message), ex.getClass().getName(),
                            ex.getMessage());
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(message + ", json message: " + response, ex);
                    }
                    healthCheckResult.setHealthy(false);
                }
            }
        } catch (IOException ex) {
            final String message = "IOException while calling the URL " + healthUrlStr;
            LOG.error(LogUtil.getErrorLog(message), ex.getClass().getName(), ex.getMessage());
            LOG.debug(message, ex);
            healthCheckResult.setHealthy(false);
        }

        return healthCheckResult;
    } // method getHealthCheckResult

    private EnrollCertResult parseEnrollCertResult(
            final EnrollCertResultResp result,
            final String caName)
    throws CaClientException {
        Map<String, CertOrError> certOrErrors = new HashMap<>();
        for (ResultEntry resultEntry : result.getResultEntries()) {
            CertOrError certOrError;
            if (resultEntry instanceof EnrollCertResultEntry) {
                EnrollCertResultEntry entry = (EnrollCertResultEntry) resultEntry;
                try {
                    java.security.cert.Certificate cert = getCertificate(entry.getCert());
                    certOrError = new CertOrError(cert);
                } catch (CertificateException ex) {
                    throw new CaClientException(String.format(
                            "CertificateParsingException for request (id=%s): %s",
                            entry.getId(), ex.getMessage()));
                }
            } else if (resultEntry instanceof ErrorResultEntry) {
                certOrError = new CertOrError(((ErrorResultEntry) resultEntry).getStatusInfo());
            } else {
                certOrError = null;
            }

            certOrErrors.put(resultEntry.getId(), certOrError);
        }

        List<CMPCertificate> cmpCaPubs = result.getCaCertificates();

        if (CollectionUtil.isEmpty(cmpCaPubs)) {
            return new EnrollCertResult(null, certOrErrors);
        }

        List<java.security.cert.Certificate> caPubs = new ArrayList<>(cmpCaPubs.size());
        for (CMPCertificate cmpCaPub : cmpCaPubs) {
            try {
                caPubs.add(getCertificate(cmpCaPub));
            } catch (CertificateException ex) {
                final String message = "could not extract the caPub from CMPCertificate";
                LOG.error(LogUtil.getErrorLog(message), ex.getClass().getName(), ex.getMessage());
                LOG.debug(message, ex);
            }
        }

        java.security.cert.Certificate caCert = null;
        for (CertOrError certOrError : certOrErrors.values()) {
            java.security.cert.Certificate cert = certOrError.getCertificate();
            if (cert == null) {
                continue;
            }

            for (java.security.cert.Certificate caPub : caPubs) {
                if (verify(caPub, cert)) {
                    caCert = caPub;
                    break;
                }
            }

            if (caCert != null) {
                break;
            }
        }

        if (caCert == null) {
            return new EnrollCertResult(null, certOrErrors);
        }

        for (CertOrError certOrError : certOrErrors.values()) {
            java.security.cert.Certificate cert = certOrError.getCertificate();
            if (cert == null) {
                continue;
            }

            if (!verify(caCert, cert)) {
                LOG.warn("not all certificates are issued by CA embedded in caPubs,"
                        + " ignore the caPubs");
                return new EnrollCertResult(null, certOrErrors);
            }
        }

        return new EnrollCertResult(caCert, certOrErrors);
    } // method parseEnrollCertResult

    private static CAClientType parse(
            final InputStream configStream)
    throws InvalidConfException {
        synchronized (jaxbUnmarshallerLock) {
            Object root;
            try {
                if (jaxbUnmarshaller == null) {
                    JAXBContext context = JAXBContext.newInstance(ObjectFactory.class);
                    jaxbUnmarshaller = context.createUnmarshaller();

                    final SchemaFactory schemaFact = SchemaFactory.newInstance(
                            javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI);
                    URL url = CAClientType.class.getResource("/xsd/caclient-conf.xsd");
                    jaxbUnmarshaller.setSchema(schemaFact.newSchema(url));
                }

                root = jaxbUnmarshaller.unmarshal(configStream);
            } catch (SAXException ex) {
                throw new InvalidConfException("parse profile failed, message: " + ex.getMessage(),
                        ex);
            } catch (JAXBException ex) {
                throw new InvalidConfException("parse profile failed, message: "
                        + XmlUtil.getMessage((JAXBException) ex), ex);
            }

            if (root instanceof JAXBElement) {
                return (CAClientType) ((JAXBElement<?>) root).getValue();
            } else {
                throw new InvalidConfException("invalid root element type");
            }
        }
    } // method parse

    private static byte[] readData(
            final FileOrValueType fileOrValue)
    throws IOException {
        byte[] data = fileOrValue.getValue();
        if (data == null) {
            data = IoUtil.read(fileOrValue.getFile());
        }
        return data;
    }

}
