/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.client;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSocketFactory;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.SchemaFactory;

import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.client.api.CaClient;
import org.xipki.ca.client.api.CaClientException;
import org.xipki.ca.client.api.CertIdOrError;
import org.xipki.ca.client.api.CertifiedKeyPairOrError;
import org.xipki.ca.client.api.CertprofileInfo;
import org.xipki.ca.client.api.EnrollCertResult;
import org.xipki.ca.client.api.PkiErrorException;
import org.xipki.ca.client.api.dto.CsrEnrollCertRequest;
import org.xipki.ca.client.api.dto.EnrollCertRequest;
import org.xipki.ca.client.api.dto.EnrollCertRequestEntry;
import org.xipki.ca.client.api.dto.EnrollCertResultEntry;
import org.xipki.ca.client.api.dto.EnrollCertResultResp;
import org.xipki.ca.client.api.dto.ErrorResultEntry;
import org.xipki.ca.client.api.dto.ResultEntry;
import org.xipki.ca.client.api.dto.RevokeCertRequest;
import org.xipki.ca.client.api.dto.RevokeCertRequestEntry;
import org.xipki.ca.client.api.dto.RevokeCertResultEntry;
import org.xipki.ca.client.api.dto.RevokeCertResultType;
import org.xipki.ca.client.api.dto.UnrevokeOrRemoveCertEntry;
import org.xipki.ca.client.api.dto.UnrevokeOrRemoveCertRequest;
import org.xipki.ca.client.jaxb.CaType;
import org.xipki.ca.client.jaxb.CaclientType;
import org.xipki.ca.client.jaxb.CertprofileType;
import org.xipki.ca.client.jaxb.CertprofilesType;
import org.xipki.ca.client.jaxb.CmpcontrolType;
import org.xipki.ca.client.jaxb.FileOrValueType;
import org.xipki.ca.client.jaxb.ObjectFactory;
import org.xipki.ca.client.jaxb.RequestorType;
import org.xipki.ca.client.jaxb.RequestorType.PbmMac;
import org.xipki.ca.client.jaxb.RequestorType.Signature;
import org.xipki.ca.client.jaxb.ResponderType;
import org.xipki.ca.client.jaxb.SslType;
import org.xipki.security.AlgorithmValidator;
import org.xipki.security.CollectionAlgorithmValidator;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.HashAlgo;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignerConf;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.X509Util;
import org.xipki.util.CollectionUtil;
import org.xipki.util.CompareUtil;
import org.xipki.util.HealthCheckResult;
import org.xipki.util.IoUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.ObjectCreationException;
import org.xipki.util.ParamUtil;
import org.xipki.util.ReqRespDebug;
import org.xipki.util.XmlUtil;
import org.xipki.util.http.ssl.SSLContextBuilder;
import org.xipki.util.http.ssl.SslUtil;
import org.xml.sax.SAXException;

/**
 * TODO.
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

        LOG.info("scheduled configuring CAs {}", autoConfCaNames);
        Set<String> failedCaNames = autoConfCas(autoConfCaNames);

        if (CollectionUtil.isNonEmpty(failedCaNames)) {
          LOG.warn("could not configure following CAs {}", failedCaNames);
        }

      } finally {
        lastUpdate = System.currentTimeMillis();
        inProcess.set(false);
      }
    }

  } // class ClientConfigUpdater

  private class SslConf {

    private final SSLSocketFactory sslSocketFactory;

    private final HostnameVerifier hostnameVerifier;

    SslConf(SSLSocketFactory sslSocketFactory, HostnameVerifier hostnameVerifier) {
      this.sslSocketFactory = sslSocketFactory;
      this.hostnameVerifier = hostnameVerifier;
    }

    public SSLSocketFactory getSslSocketFactory() {
      return sslSocketFactory;
    }

    public HostnameVerifier getHostnameVerifier() {
      return hostnameVerifier;
    }

  }

  private static final Logger LOG = LoggerFactory.getLogger(CaClientImpl.class);

  private static Object jaxbUnmarshallerLock = new Object();

  private static Unmarshaller jaxbUnmarshaller;

  private final Map<String, ClientCaConf> casMap = new HashMap<>();

  private final Set<String> autoConfCaNames = new HashSet<>();

  private SecurityFactory securityFactory;

  private String confFile;

  private ScheduledThreadPoolExecutor scheduledThreadPoolExecutor;

  private AtomicBoolean initialized = new AtomicBoolean(false);

  public CaClientImpl() {
  }

  public void setSecurityFactory(SecurityFactory securityFactory) {
    this.securityFactory = securityFactory;
  }

  /**
   * TODO.
   * @return names of CAs which must not been configured.
   */
  private Set<String> autoConfCas(Set<String> caNames) {
    if (caNames.isEmpty()) {
      return Collections.emptySet();
    }

    Set<String> caNamesWithError = new HashSet<>();

    Set<String> errorCaNames = new HashSet<>();
    for (String name : caNames) {
      ClientCaConf ca = casMap.get(name);

      try {
        ClientCaInfo caInfo = ca.getAgent().retrieveCaInfo(name, null);
        if (ca.isCertAutoconf()) {
          ca.setCert(caInfo.getCert());
        }
        if (ca.isCertprofilesAutoconf()) {
          ca.setCertprofiles(caInfo.getCertprofiles());
        }
        if (ca.isCmpControlAutoconf()) {
          ca.setCmpControl(caInfo.getCmpControl());
        }
        LOG.info("retrieved CAInfo for CA " + name);
      } catch (CaClientException | PkiErrorException | CertificateEncodingException
            | RuntimeException ex) {
        errorCaNames.add(name);
        caNamesWithError.add(name);
        LogUtil.error(LOG, ex, "could not retrieve CAInfo for CA " + name);
      }
    }

    return caNamesWithError;
  } // method autoConfCas

  private synchronized void init() throws CaClientException {
    if (confFile == null) {
      throw new IllegalStateException("confFile is not set");
    }

    if (securityFactory == null) {
      throw new IllegalStateException("securityFactory is not set");
    }

    if (initialized.get()) {
      return;
    }

    // reset
    this.casMap.clear();
    this.autoConfCaNames.clear();
    if (this.scheduledThreadPoolExecutor != null) {
      this.scheduledThreadPoolExecutor.shutdownNow();
    }
    this.initialized.set(false);

    LOG.info("initializing ...");
    File configFile = new File(IoUtil.expandFilepath(confFile));
    if (!configFile.exists()) {
      throw new CaClientException("could not find configuration file " + confFile);
    }

    CaclientType config;
    try {
      config = parse(Files.newInputStream(configFile.toPath()));
    } catch (IOException ex) {
      throw new CaClientException("could not read file " + confFile);
    }

    if (config.getCas().getCa().isEmpty()) {
      LOG.warn("no CA is configured");
    }

    // ssl configurations
    Map<String, SslConf> sslConfs = new HashMap<>();
    if (config.getSsls() != null) {
      for (SslType ssl : config.getSsls().getSsl()) {
        SSLContextBuilder builder = new SSLContextBuilder();
        if (ssl.getStoreType() != null) {
          builder.setKeyStoreType(ssl.getStoreType());
        }

        try {
          if (ssl.getKeystoreFile() != null) {
            char[] pwd = ssl.getKeystorePassword() == null
                ? null : ssl.getKeystorePassword().toCharArray();
            builder.loadKeyMaterial(new File(ssl.getKeystoreFile()), pwd, pwd);
          }

          if (ssl.getTruststoreFile() != null) {
            char[] pwd = ssl.getTruststorePassword() == null
                ? null : ssl.getTruststorePassword().toCharArray();
            builder.loadTrustMaterial(new File(ssl.getTruststoreFile()), pwd);
          }

          SSLSocketFactory socketFactory = builder.build().getSocketFactory();
          HostnameVerifier hostnameVerifier =
              SslUtil.createHostnameVerifier(ssl.getHostnameVerifier());
          sslConfs.put(ssl.getName(), new SslConf(socketFactory, hostnameVerifier));
        } catch (IOException | UnrecoverableKeyException | NoSuchAlgorithmException
            | KeyStoreException | CertificateException | KeyManagementException
            | ObjectCreationException ex) {
          throw new CaClientException("could not initialize SSL configuration " + ssl.getName()
              + ": " + ex.getMessage(), ex);
        }
      }
    }

    // responders
    Map<String, ClientCmpResponder> responders = new HashMap<>();
    for (ResponderType m : config.getResponders().getResponder()) {
      X509Certificate cert;
      try {
        cert = X509Util.parseCert(readData(m.getCert()));
      } catch (CertificateException | IOException ex) {
        LogUtil.error(LOG, ex, "could not configure responder " + m.getName());
        throw new CaClientException(ex.getMessage(), ex);
      }

      ClientCmpResponder responder;
      if (m.getSignature() != null) {
        Set<String> algoNames = new HashSet<>();
        for (String algo : m.getSignature().getSignatureAlgos().getAlgo()) {
          algoNames.add(algo);
        }
        AlgorithmValidator sigAlgoValidator;
        try {
          sigAlgoValidator = new CollectionAlgorithmValidator(algoNames);
        } catch (NoSuchAlgorithmException ex) {
          throw new CaClientException(ex.getMessage());
        }

        responder = new SignatureClientCmpResponder(cert, sigAlgoValidator);
      } else { // if (m.getPbmMac() != null)
        ResponderType.PbmMac mac = m.getPbmMac();
        X500Name subject = X500Name.getInstance(cert.getSubjectX500Principal().getEncoded());
        responder = new PbmMacClientCmpResponder(subject, mac.getOwfAlgos().getAlgo(),
            mac.getMacAlgos().getAlgo());
      }

      responders.put(m.getName(), responder);
    }

    // CA;
    Set<ClientCaConf> cas = new HashSet<>();
    for (CaType caType : config.getCas().getCa()) {
      String caName = caType.getName();
      try {
        // responder
        ClientCmpResponder responder = responders.get(caType.getResponder());
        if (responder == null) {
          throw new CaClientException("no responder named " + caType.getResponder()
              + " is configured");
        }

        SslConf sslConf = null;
        if (caType.getSsl() != null) {
          sslConf = sslConfs.get(caType.getSsl());
          if (sslConf == null) {
            throw new CaClientException("no ssl named " + caType.getSsl() + " is configured");
          }
        }

        ClientCaConf ca = new ClientCaConf(caName, caType.getUrl(), caType.getHealthUrl(),
            caType.getRequestor(), responder,
            sslConf.getSslSocketFactory(), sslConf.getHostnameVerifier());

        // CA cert
        if (caType.getCaCert().getAutoconf() != null) {
          ca.setCertAutoconf(true);
        } else {
          ca.setCertAutoconf(false);
          ca.setCert(X509Util.parseCert(readData(caType.getCaCert().getCert())));
        }

        // CMPControl
        CmpcontrolType cmpCtrlType = caType.getCmpcontrol();
        if (cmpCtrlType.getAutoconf() != null) {
          ca.setCmpControlAutoconf(true);
        } else {
          ca.setCmpControlAutoconf(false);
          Boolean tmpBo = cmpCtrlType.isRrAkiRequired();
          ClientCmpControl control = new ClientCmpControl(
              (tmpBo == null) ? false : tmpBo.booleanValue());
          ca.setCmpControl(control);
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

            CertprofileInfo profile = new CertprofileInfo(m.getName(), m.getType(), conf);
            profiles.add(profile);
          }
          ca.setCertprofiles(profiles);
        }

        cas.add(ca);
        if (ca.isCertAutoconf() || ca.isCertprofilesAutoconf() || ca.isCmpControlAutoconf()) {
          autoConfCaNames.add(caName);
        }
      } catch (IOException | CertificateException ex) {
        LogUtil.error(LOG, ex, "could not configure CA " + caName);
        throw new CaClientException(ex.getMessage(), ex);
      }
    }

    // requestors
    Map<String, ClientCmpRequestor> requestors = new HashMap<>();

    for (RequestorType requestorConf : config.getRequestors().getRequestor()) {
      boolean signRequest = requestorConf.isSignRequest();
      String name = requestorConf.getName();
      ClientCmpRequestor requestor;

      if (requestorConf.getSignature() != null) {
        Signature cf = requestorConf.getSignature();
        //requestorSignRequests.put(name, cf.isSignRequest());

        X509Certificate requestorCert = null;
        if (cf.getCert() != null) {
          try {
            requestorCert = X509Util.parseCert(readData(cf.getCert()));
          } catch (Exception ex) {
            throw new CaClientException(ex.getMessage(), ex);
          }
        }

        if (cf.getSignerType() != null) {
          try {
            SignerConf signerConf = new SignerConf(cf.getSignerConf());
            ConcurrentContentSigner requestorSigner = securityFactory.createSigner(
                cf.getSignerType(), signerConf, requestorCert);
            requestor = new SignatureClientCmpRequestor(
                signRequest, requestorSigner, securityFactory);
          } catch (ObjectCreationException ex) {
            throw new CaClientException(ex.getMessage(), ex);
          }
        } else {
          if (signRequest) {
            throw new CaClientException("signer of requestor must be configured");
          } else if (requestorCert == null) {
            throw new CaClientException(
                "at least one of certificate and signer of requestor must be configured");
          } else {
            requestor = new SignatureClientCmpRequestor(requestorCert);
          }
        }
      } else {
        PbmMac cf = requestorConf.getPbmMac();
        X500Name x500name = new X500Name(cf.getSender());
        AlgorithmIdentifier owf = HashAlgo.getNonNullInstance(cf.getOwf()).getAlgorithmIdentifier();
        AlgorithmIdentifier mac;
        try {
          mac = AlgorithmUtil.getMacAlgId(cf.getMac());
        } catch (NoSuchAlgorithmException ex) {
          throw new CaClientException("Unknown MAC algorithm " + cf.getMac());
        }

        requestor = new PbmMacClientCmpRequestor(signRequest, x500name,
            cf.getPassword().toCharArray(), cf.getKid(), owf, cf.getIterationCount(), mac);
      }

      requestors.put(name, requestor);
    }

    for (ClientCaConf ca :cas) {
      if (this.casMap.containsKey(ca.getName())) {
        throw new CaClientException("duplicate CAs with the same name " + ca.getName());
      }

      String requestorName = ca.getRequestorName();

      if (requestors.containsKey(requestorName)) {
        ClientCmpAgent agent = new HttpClientCmpAgent(requestors.get(requestorName),
            ca.getResponder(), ca.getUrl(), securityFactory,
            ca.getSslSocketFactory(), ca.getHostnameVerifier());
        ca.setAgent(agent);
      } else {
        throw new CaClientException("could not find requestor named " + requestorName
                + " for CA " + ca.getName());
      }

      this.casMap.put(ca.getName(), ca);
    }

    if (!autoConfCaNames.isEmpty()) {
      Integer caInfoUpdateInterval = config.getCas().getCainfoUpdateInterval();
      if (caInfoUpdateInterval == null) {
        caInfoUpdateInterval = 10;
      } else if (caInfoUpdateInterval <= 0) {
        caInfoUpdateInterval = 0;
      } else if (caInfoUpdateInterval < 5) {
        caInfoUpdateInterval = 5;
      }

      LOG.info("configuring CAs {}", autoConfCaNames);
      Set<String> failedCaNames = autoConfCas(autoConfCaNames);

      // try to re-configure the failed CAs
      if (CollectionUtil.isNonEmpty(failedCaNames)) {
        for (int i = 0; i < 3; i++) {
          LOG.info("configuring ({}-th retry) CAs {}", i + 1, failedCaNames);

          failedCaNames = autoConfCas(failedCaNames);
          if (CollectionUtil.isEmpty(failedCaNames)) {
            break;
          }

          try {
            Thread.sleep(10000);
          } catch (InterruptedException ex) {
            LOG.warn("interrupted", ex);
          }
        }
      }

      if (CollectionUtil.isNonEmpty(failedCaNames)) {
        throw new CaClientException("could not configure following CAs " + failedCaNames);
      }

      if (caInfoUpdateInterval > 0) {
        scheduledThreadPoolExecutor = new ScheduledThreadPoolExecutor(1);
        scheduledThreadPoolExecutor.scheduleAtFixedRate(new ClientConfigUpdater(),
            caInfoUpdateInterval, caInfoUpdateInterval, TimeUnit.MINUTES);
      }
    }

    initialized.set(true);
    LOG.info("initialized");
  } // method init

  @Override
  public void close() {
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
  public EnrollCertResult enrollCert(String caName, CertificationRequest csr, String profile,
      Date notBefore, Date notAfter, ReqRespDebug debug)
      throws CaClientException, PkiErrorException {
    ParamUtil.requireNonNull("csr", csr);

    init();

    if (caName == null) {
      caName = getCaNameForProfile(profile);
    } else {
      caName = caName.toLowerCase();
    }

    if (caName == null) {
      throw new CaClientException("certprofile " + profile + " is not supported by any CA");
    }

    ClientCaConf ca = casMap.get(caName);
    if (ca == null) {
      throw new CaClientException("could not find CA named " + caName);
    }

    final String id = "cert-1";
    CsrEnrollCertRequest request = new CsrEnrollCertRequest(id, profile, csr);
    EnrollCertResultResp result = ca.getAgent().requestCertificate(
        request, notBefore, notAfter, debug);

    return parseEnrollCertResult(result);
  } // method requestCert

  @Override
  public EnrollCertResult enrollCerts(String caName, EnrollCertRequest request,
      ReqRespDebug debug) throws CaClientException, PkiErrorException {
    ParamUtil.requireNonNull("request", request);

    List<EnrollCertRequestEntry> requestEntries = request.getRequestEntries();
    if (CollectionUtil.isEmpty(requestEntries)) {
      return null;
    }

    init();

    boolean bo = (caName != null);
    if (caName == null) {
      // detect the CA name
      String profile = requestEntries.get(0).getCertprofile();
      caName = getCaNameForProfile(profile);
      if (caName == null) {
        throw new CaClientException("certprofile " + profile + " is not supported by any CA");
      }
    } else {
      caName = caName.toLowerCase();
    }

    if (bo || request.getRequestEntries().size() > 1) {
      // make sure that all requests are targeted on the same CA
      for (EnrollCertRequestEntry entry : request.getRequestEntries()) {
        String profile = entry.getCertprofile();
        if (profile != null) {
          checkCertprofileSupportInCa(profile, caName);
        }
      }
    }

    ClientCaConf ca = casMap.get(caName);
    if (ca == null) {
      throw new CaClientException("could not find CA named " + caName);
    }

    EnrollCertResultResp result = ca.getAgent().requestCertificate(request, debug);
    return parseEnrollCertResult(result);
  } // method requestCerts

  private void checkCertprofileSupportInCa(String certprofile, String caName)
      throws CaClientException {
    if (caName != null) {
      caName = caName.toLowerCase();
      ClientCaConf ca = casMap.get(caName);
      if (ca == null) {
        throw new CaClientException("unknown ca: " + caName);
      }

      if (!ca.supportsProfile(certprofile)) {
        throw new CaClientException("certprofile " + certprofile + " is not supported by the CA "
            + caName);
      }
      return;
    }

    for (ClientCaConf ca : casMap.values()) {
      if (!ca.isCaInfoConfigured()) {
        continue;
      }
      if (!ca.supportsProfile(certprofile)) {
        continue;
      }

      if (caName == null) {
        caName = ca.getName();
      } else {
        throw new CaClientException("certprofile " + certprofile
            + " supported by more than one CA, please specify the CA name.");
      }
    }

    if (caName == null) {
      throw new CaClientException("unsupported certprofile " + certprofile);
    }
  }

  @Override
  public CertIdOrError revokeCert(String caName, X509Certificate cert, int reason,
      Date invalidityDate, ReqRespDebug debug) throws CaClientException, PkiErrorException {
    ParamUtil.requireNonNull("cert", cert);
    init();
    ClientCaConf ca = getCa(caName);
    assertIssuedByCa(cert, ca);
    return revokeCert(ca, cert.getSerialNumber(), reason, invalidityDate, debug);
  }

  @Override
  public CertIdOrError revokeCert(String caName, BigInteger serial, int reason, Date invalidityDate,
      ReqRespDebug debug) throws CaClientException, PkiErrorException {
    init();
    ClientCaConf ca = getCa(caName);
    return revokeCert(ca, serial, reason, invalidityDate, debug);
  }

  private CertIdOrError revokeCert(ClientCaConf ca, BigInteger serial, int reason,
      Date invalidityDate, ReqRespDebug debug) throws CaClientException, PkiErrorException {
    ParamUtil.requireNonNull("ca", ca);
    ParamUtil.requireNonNull("serial", serial);

    final String id = "cert-1";
    RevokeCertRequestEntry entry = new RevokeCertRequestEntry(id, ca.getSubject(), serial, reason,
        invalidityDate);
    if (ca.getCmpControl().isRrAkiRequired()) {
      entry.setAuthorityKeyIdentifier(ca.getSubjectKeyIdentifier());
    }

    RevokeCertRequest request = new RevokeCertRequest();
    request.addRequestEntry(entry);
    Map<String, CertIdOrError> result = revokeCerts(request, debug);
    return (result == null) ? null : result.get(id);
  }

  @Override
  public Map<String, CertIdOrError> revokeCerts(RevokeCertRequest request, ReqRespDebug debug)
      throws CaClientException, PkiErrorException {
    ParamUtil.requireNonNull("request", request);

    List<RevokeCertRequestEntry> requestEntries = request.getRequestEntries();
    if (CollectionUtil.isEmpty(requestEntries)) {
      return Collections.emptyMap();
    }

    X500Name issuer = requestEntries.get(0).getIssuer();
    for (int i = 1; i < requestEntries.size(); i++) {
      if (!issuer.equals(requestEntries.get(i).getIssuer())) {
        throw new PkiErrorException(PKIStatus.REJECTION, PKIFailureInfo.badRequest,
            "revoking certificates issued by more than one CA is not allowed");
      }
    }

    init();

    final String caName = getCaNameByIssuer(issuer);
    ClientCaConf caConf = casMap.get(caName);
    if (caConf.getCmpControl().isRrAkiRequired()) {
      byte[] aki = caConf.getSubjectKeyIdentifier();
      List<RevokeCertRequestEntry> entries = request.getRequestEntries();
      for (RevokeCertRequestEntry entry : entries) {
        if (entry.getAuthorityKeyIdentifier() == null) {
          entry.setAuthorityKeyIdentifier(aki);
        }
      }
    }

    RevokeCertResultType result = caConf.getAgent().revokeCertificate(request, debug);
    return parseRevokeCertResult(result);
  }

  private Map<String, CertIdOrError> parseRevokeCertResult(RevokeCertResultType result)
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
        throw new CaClientException("unknown type " + re.getClass().getName());
      }

      ret.put(re.getId(), certIdOrError);
    }

    return ret;
  }

  @Override
  public X509CRL downloadCrl(String caName, ReqRespDebug debug)
      throws CaClientException, PkiErrorException {
    caName = ParamUtil.requireNonBlankLower("caName", caName);
    return downloadCrl(caName, (BigInteger) null, debug);
  }

  @Override
  public X509CRL downloadCrl(String caName, BigInteger crlNumber, ReqRespDebug debug)
      throws CaClientException, PkiErrorException {
    caName = ParamUtil.requireNonBlankLower("caName", caName);
    init();

    ClientCaConf ca = casMap.get(caName);
    if (ca == null) {
      throw new IllegalArgumentException("unknown CA " + caName);
    }

    ClientCmpAgent agent = ca.getAgent();
    X509CRL result = (crlNumber == null) ? agent.downloadCurrentCrl(debug)
          : agent.downloadCrl(crlNumber, debug);

    return result;
  }

  @Override
  public X509CRL generateCrl(String caName, ReqRespDebug debug)
      throws CaClientException, PkiErrorException {
    caName = ParamUtil.requireNonBlankLower("caName", caName);

    init();

    ClientCaConf ca = casMap.get(caName);
    if (ca == null) {
      throw new IllegalArgumentException("unknown CA " + caName);
    }

    return ca.getAgent().generateCrl(debug);
  }

  @Override
  public String getCaNameByIssuer(X500Name issuer) throws CaClientException {
    ParamUtil.requireNonNull("issuer", issuer);

    init();

    for (String name : casMap.keySet()) {
      final ClientCaConf ca = casMap.get(name);
      if (!ca.isCaInfoConfigured()) {
        continue;
      }

      if (CompareUtil.equalsObject(ca.getSubject(), issuer)) {
        return name;
      }
    }

    throw new CaClientException("unknown CA for issuer: " + issuer);
  }

  private String getCaNameForProfile(String certprofile) throws CaClientException {
    String caName = null;
    for (ClientCaConf ca : casMap.values()) {
      if (!ca.isCaInfoConfigured()) {
        continue;
      }

      if (!ca.supportsProfile(certprofile)) {
        continue;
      }

      if (caName == null) {
        caName = ca.getName();
      } else {
        throw new CaClientException("certprofile " + certprofile
                + " supported by more than one CA, please specify the CA name.");
      }
    }

    return caName;
  }

  private java.security.cert.Certificate getCertificate(CMPCertificate cmpCert)
      throws CertificateException {
    Certificate bcCert = cmpCert.getX509v3PKCert();
    return (bcCert == null) ? null : X509Util.toX509Cert(bcCert);
  }

  public String getConfFile() {
    return confFile;
  }

  public void setConfFile(String confFile) {
    this.confFile = ParamUtil.requireNonBlank("confFile", confFile);
  }

  @Override
  public Set<String> getCaNames() throws CaClientException {
    init();
    return casMap.keySet();
  }

  private static boolean verify(java.security.cert.Certificate caCert,
      java.security.cert.Certificate cert) {
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

    boolean inBenchmark = Boolean.getBoolean("org.xipki.benchmark");
    if (inBenchmark) {
      return true;
    }

    PublicKey caPublicKey = x509caCert.getPublicKey();
    try {
      x509cert.verify(caPublicKey);
      return true;
    } catch (SignatureException | InvalidKeyException | CertificateException
        | NoSuchAlgorithmException | NoSuchProviderException ex) {
      LOG.debug("{} while verifying signature: {}", ex.getClass().getName(), ex.getMessage());
      return false;
    }
  } // method verify

  @Override
  public CertIdOrError unrevokeCert(String caName, X509Certificate cert, ReqRespDebug debug)
      throws CaClientException, PkiErrorException {
    ParamUtil.requireNonNull("cert", cert);
    init();

    ClientCaConf ca = getCa(caName);
    assertIssuedByCa(cert, ca);
    return unrevokeCert(ca, cert.getSerialNumber(), debug);
  }

  @Override
  public CertIdOrError unrevokeCert(String caName, BigInteger serial, ReqRespDebug debug)
      throws CaClientException, PkiErrorException {
    init();
    ClientCaConf ca = getCa(caName);
    return unrevokeCert(ca, serial, debug);
  }

  private CertIdOrError unrevokeCert(ClientCaConf ca, BigInteger serial, ReqRespDebug debug)
      throws CaClientException, PkiErrorException {
    ParamUtil.requireNonNull("ca", ca);
    ParamUtil.requireNonNull("serial", serial);
    final String id = "cert-1";
    UnrevokeOrRemoveCertEntry entry = new UnrevokeOrRemoveCertEntry(id, ca.getSubject(), serial);
    if (ca.getCmpControl().isRrAkiRequired()) {
      entry.setAuthorityKeyIdentifier(ca.getSubjectKeyIdentifier());
    }

    UnrevokeOrRemoveCertRequest request = new UnrevokeOrRemoveCertRequest();
    request.addRequestEntry(entry);
    Map<String, CertIdOrError> result = unrevokeCerts(request, debug);
    return (result == null) ? null : result.get(id);
  }

  @Override
  public Map<String, CertIdOrError> unrevokeCerts(UnrevokeOrRemoveCertRequest request,
      ReqRespDebug debug) throws CaClientException, PkiErrorException {
    ParamUtil.requireNonNull("request", request);

    init();
    List<UnrevokeOrRemoveCertEntry> requestEntries = request.getRequestEntries();
    if (CollectionUtil.isEmpty(requestEntries)) {
      return Collections.emptyMap();
    }

    X500Name issuer = requestEntries.get(0).getIssuer();
    for (int i = 1; i < requestEntries.size(); i++) {
      if (!issuer.equals(requestEntries.get(i).getIssuer())) {
        throw new PkiErrorException(PKIStatus.REJECTION, PKIFailureInfo.badRequest,
            "unrevoking certificates issued by more than one CA is not allowed");
      }
    }

    final String caName = getCaNameByIssuer(issuer);
    ClientCmpAgent agent = casMap.get(caName).getAgent();
    RevokeCertResultType result = agent.unrevokeCertificate(request, debug);
    return parseRevokeCertResult(result);
  } // method unrevokeCerts

  @Override
  public CertIdOrError removeCert(String caName, X509Certificate cert, ReqRespDebug debug)
      throws CaClientException, PkiErrorException {
    ParamUtil.requireNonNull("cert", cert);
    init();
    ClientCaConf ca = getCa(caName);
    assertIssuedByCa(cert, ca);
    return removeCert(ca, cert.getSerialNumber(), debug);
  }

  @Override
  public CertIdOrError removeCert(String caName, BigInteger serial, ReqRespDebug debug)
      throws CaClientException, PkiErrorException {
    init();
    ClientCaConf ca = getCa(caName);
    return removeCert(ca, serial, debug);
  }

  private CertIdOrError removeCert(ClientCaConf ca, BigInteger serial, ReqRespDebug debug)
      throws CaClientException, PkiErrorException {
    ParamUtil.requireNonNull("ca", ca);
    ParamUtil.requireNonNull("serial", serial);
    final String id = "cert-1";
    UnrevokeOrRemoveCertEntry entry = new UnrevokeOrRemoveCertEntry(id, ca.getSubject(), serial);
    if (ca.getCmpControl().isRrAkiRequired()) {
      entry.setAuthorityKeyIdentifier(ca.getSubjectKeyIdentifier());
    }

    UnrevokeOrRemoveCertRequest request = new UnrevokeOrRemoveCertRequest();
    request.addRequestEntry(entry);
    Map<String, CertIdOrError> result = removeCerts(request, debug);
    return (result == null) ? null : result.get(id);
  }

  @Override
  public Map<String, CertIdOrError> removeCerts(UnrevokeOrRemoveCertRequest request,
      ReqRespDebug debug) throws CaClientException, PkiErrorException {
    ParamUtil.requireNonNull("request", request);

    init();
    List<UnrevokeOrRemoveCertEntry> requestEntries = request.getRequestEntries();
    if (CollectionUtil.isEmpty(requestEntries)) {
      return Collections.emptyMap();
    }

    X500Name issuer = requestEntries.get(0).getIssuer();
    for (int i = 1; i < requestEntries.size(); i++) {
      if (!issuer.equals(requestEntries.get(i).getIssuer())) {
        throw new PkiErrorException(PKIStatus.REJECTION, PKIFailureInfo.badRequest,
            "removing certificates issued by more than one CA is not allowed");
      }
    }

    final String caName = getCaNameByIssuer(issuer);
    ClientCmpAgent agent = casMap.get(caName).getAgent();
    RevokeCertResultType result = agent.removeCertificate(request, debug);
    return parseRevokeCertResult(result);
  }

  @Override
  public Set<CertprofileInfo> getCertprofiles(String caName) throws CaClientException {
    caName = ParamUtil.requireNonBlankLower("caName", caName);

    init();
    ClientCaConf ca = casMap.get(caName);
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
  public HealthCheckResult getHealthCheckResult(String caName) throws CaClientException {
    caName = ParamUtil.requireNonBlankLower("caName", caName);

    String name = "X509CA";
    HealthCheckResult healthCheckResult = new HealthCheckResult(name);

    try {
      init();
    } catch (CaClientException ex) {
      LogUtil.error(LOG, ex, "could not initialize CaCleint");
      healthCheckResult.setHealthy(false);
      return healthCheckResult;
    }

    ClientCaConf ca = casMap.get(caName);
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

    try {
      HttpURLConnection httpUrlConnection = IoUtil.openHttpConn(serverUrl);
      InputStream inputStream = httpUrlConnection.getInputStream();
      int responseCode = httpUrlConnection.getResponseCode();
      if (responseCode != HttpURLConnection.HTTP_OK
          && responseCode != HttpURLConnection.HTTP_INTERNAL_ERROR) {
        inputStream.close();
        throw new IOException(String.format("bad response: code='%s', message='%s'",
            httpUrlConnection.getResponseCode(), httpUrlConnection.getResponseMessage()));
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
        throw new IOException("bad response: mime type " + responseContentType + " not supported!");
      }

      byte[] responseBytes = IoUtil.read(inputStream);
      if (responseBytes.length == 0) {
        healthCheckResult.setHealthy(responseCode == HttpURLConnection.HTTP_OK);
      } else {
        String response = new String(responseBytes);
        try {
          healthCheckResult = HealthCheckResult.getInstanceFromJsonMessage(name, response);
        } catch (IllegalArgumentException ex) {
          LogUtil.error(LOG, ex, "IOException while parsing the health json message");
          if (LOG.isDebugEnabled()) {
            LOG.debug("json message: {}", response);
          }
          healthCheckResult.setHealthy(false);
        }
      }
    } catch (IOException ex) {
      LogUtil.error(LOG, ex, "IOException while fetching the URL " + healthUrlStr);
      healthCheckResult.setHealthy(false);
    }

    return healthCheckResult;
  } // method getHealthCheckResult

  private EnrollCertResult parseEnrollCertResult(EnrollCertResultResp result)
      throws CaClientException {
    Map<String, CertifiedKeyPairOrError> certOrErrors = new HashMap<>();
    for (ResultEntry resultEntry : result.getResultEntries()) {
      CertifiedKeyPairOrError certOrError;
      if (resultEntry instanceof EnrollCertResultEntry) {
        EnrollCertResultEntry entry = (EnrollCertResultEntry) resultEntry;
        try {
          java.security.cert.Certificate cert = getCertificate(entry.getCert());
          certOrError = new CertifiedKeyPairOrError(cert, entry.getPrivateKeyInfo());
        } catch (CertificateException ex) {
          throw new CaClientException(String.format(
              "CertificateParsingException for request (id=%s): %s",
              entry.getId(), ex.getMessage()));
        }
      } else if (resultEntry instanceof ErrorResultEntry) {
        certOrError = new CertifiedKeyPairOrError(((ErrorResultEntry) resultEntry).getStatusInfo());
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
        LogUtil.error(LOG, ex, "could not extract the caPub from CMPCertificate");
      }
    }

    java.security.cert.Certificate caCert = null;
    for (CertifiedKeyPairOrError certOrError : certOrErrors.values()) {
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

    for (CertifiedKeyPairOrError certOrError : certOrErrors.values()) {
      java.security.cert.Certificate cert = certOrError.getCertificate();
      if (cert == null) {
        continue;
      }

      if (!verify(caCert, cert)) {
        LOG.warn("not all certificates are issued by CA embedded in caPubs, ignore the caPubs");
        return new EnrollCertResult(null, certOrErrors);
      }
    }

    return new EnrollCertResult(caCert, certOrErrors);
  } // method parseEnrollCertResult

  private static CaclientType parse(InputStream configStream) throws CaClientException {
    Object root;
    synchronized (jaxbUnmarshallerLock) {
      try {
        if (jaxbUnmarshaller == null) {
          JAXBContext context = JAXBContext.newInstance(ObjectFactory.class);
          jaxbUnmarshaller = context.createUnmarshaller();

          final SchemaFactory schemaFact = SchemaFactory.newInstance(
                  javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI);
          URL url = CaclientType.class.getResource("/xsd/caclient-conf.xsd");
          jaxbUnmarshaller.setSchema(schemaFact.newSchema(url));
        }

        root = jaxbUnmarshaller.unmarshal(configStream);
      } catch (SAXException ex) {
        throw new CaClientException("parsing profile failed, message: " + ex.getMessage(), ex);
      } catch (JAXBException ex) {
        throw new CaClientException("parsing profile failed, message: " + XmlUtil.getMessage(ex),
            ex);
      }
    }

    try {
      configStream.close();
    } catch (IOException ex) {
      LOG.warn("could not close xmlConfStream: {}", ex.getMessage());
    }

    if (!(root instanceof JAXBElement)) {
      throw new CaClientException("invalid root element type");
    }

    CaclientType conf = (CaclientType) ((JAXBElement<?>) root).getValue();
    // canonicalize the names
    for (RequestorType m : conf.getRequestors().getRequestor()) {
      m.setName(m.getName().toLowerCase());
    }

    for (ResponderType m : conf.getResponders().getResponder()) {
      m.setName(m.getName().toLowerCase());
    }

    for (CaType ca : conf.getCas().getCa()) {
      ca.setName(ca.getName().toLowerCase());
      ca.setRequestor(ca.getRequestor().toLowerCase());
      ca.setResponder(ca.getResponder().toLowerCase());
    }

    return conf;
  } // method parse

  private static byte[] readData(FileOrValueType fileOrValue) throws IOException {
    byte[] data = fileOrValue.getValue();
    if (data == null) {
      data = IoUtil.read(fileOrValue.getFile());
    }
    return data;
  }

  private ClientCaConf getCa(String caName) throws CaClientException {
    if (caName == null) {
      Iterator<String> names = casMap.keySet().iterator();
      if (!names.hasNext()) {
        throw new CaClientException("no CA is configured");
      }
      caName = names.next();
    } else {
      caName = caName.toLowerCase();
    }

    ClientCaConf ca = casMap.get(caName);
    if (ca == null) {
      throw new CaClientException("could not find CA named " + caName);
    }
    return ca;
  }

  private static void assertIssuedByCa(X509Certificate cert, ClientCaConf ca)
      throws CaClientException {
    boolean issued;
    try {
      issued = X509Util.issues(ca.getCert(), cert);
    } catch (CertificateEncodingException ex) {
      LogUtil.error(LOG, ex);
      issued = false;
    }
    if (!issued) {
      throw new CaClientException("the given certificate is not issued by the CA");
    }
  }

  @Override
  public java.security.cert.Certificate getCaCert(String caName) throws CaClientException {
    init();

    ClientCaConf ca = casMap.get(caName.toLowerCase());
    return ca == null ? null : ca.getCert();
  }

  @Override
  public X500Name getCaCertSubject(String caName) throws CaClientException {
    init();
    ClientCaConf ca = casMap.get(caName.toLowerCase());
    return ca == null ? null : ca.getSubject();
  }

}
