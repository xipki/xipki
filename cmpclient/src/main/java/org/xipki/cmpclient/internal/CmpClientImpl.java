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

package org.xipki.cmpclient.internal;

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
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.cmpclient.CertIdOrError;
import org.xipki.cmpclient.CertprofileInfo;
import org.xipki.cmpclient.CmpClient;
import org.xipki.cmpclient.CmpClientConf;
import org.xipki.cmpclient.CmpClientException;
import org.xipki.cmpclient.EnrollCertRequest;
import org.xipki.cmpclient.EnrollCertResult;
import org.xipki.cmpclient.PkiErrorException;
import org.xipki.cmpclient.RevokeCertRequest;
import org.xipki.cmpclient.UnrevokeOrRemoveCertRequest;
import org.xipki.cmpclient.internal.Requestor.PbmMacCmpRequestor;
import org.xipki.cmpclient.internal.Requestor.SignatureCmpRequestor;
import org.xipki.security.AlgorithmValidator;
import org.xipki.security.CollectionAlgorithmValidator;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.HashAlgo;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignerConf;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;
import org.xipki.util.CompareUtil;
import org.xipki.util.HealthCheckResult;
import org.xipki.util.InvalidConfException;
import org.xipki.util.IoUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.ObjectCreationException;
import org.xipki.util.ReqRespDebug;
import org.xipki.util.http.HostnameVerifiers;
import org.xipki.util.http.SSLContextBuilder;

import com.alibaba.fastjson.JSON;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public final class CmpClientImpl implements CmpClient {

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

  private static final Logger LOG = LoggerFactory.getLogger(CmpClientImpl.class);

  private final Map<String, CaConf> casMap = new HashMap<>();

  private final Set<String> autoConfCaNames = new HashSet<>();

  private SecurityFactory securityFactory;

  private String confFile;

  private ScheduledThreadPoolExecutor scheduledThreadPoolExecutor;

  private AtomicBoolean initialized = new AtomicBoolean(false);

  public CmpClientImpl() {
  }

  public void setSecurityFactory(SecurityFactory securityFactory) {
    this.securityFactory = securityFactory;
  }

  /**
   * TODO.
   * @return names of CAs which may not been configured.
   */
  private Set<String> autoConfCas(Set<String> caNames) {
    if (caNames.isEmpty()) {
      return Collections.emptySet();
    }

    Set<String> caNamesWithError = new HashSet<>();

    Set<String> errorCaNames = new HashSet<>();
    for (String name : caNames) {
      CaConf ca = casMap.get(name);

      try {
        CaConf.CaInfo caInfo = ca.getAgent().retrieveCaInfo(name, null);
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
      } catch (CmpClientException | PkiErrorException | CertificateEncodingException
            | RuntimeException ex) {
        errorCaNames.add(name);
        caNamesWithError.add(name);
        LogUtil.error(LOG, ex, "could not retrieve CAInfo for CA " + name);
      }
    }

    return caNamesWithError;
  } // method autoConfCas

  private synchronized void initIfNotInitialized() throws CmpClientException {
    if (confFile == null) {
      throw new IllegalStateException("confFile is not set");
    }

    if (securityFactory == null) {
      throw new IllegalStateException("securityFactory is not set");
    }

    if (initialized.get()) {
      return;
    }

    if (!init()) {
      throw new CmpClientException("initialization of CA client failed");
    }
  }

  public synchronized boolean init() {
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
      LOG.error("could not find configuration file {}", confFile);
      return false;
    }

    CmpClientConf conf;
    try {
      conf = parse(Files.newInputStream(configFile.toPath()));
    } catch (IOException | CmpClientException ex) {
      LOG.error("could not read file {}", confFile);
      return false;
    }

    if (CollectionUtil.isEmpty(conf.getCas())) {
      LOG.warn("no CA is configured");
    }

    // ssl configurations
    Map<String, SslConf> sslConfs = new HashMap<>();
    if (conf.getSsls() != null) {
      for (CmpClientConf.Ssl ssl : conf.getSsls()) {
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
              HostnameVerifiers.createHostnameVerifier(ssl.getHostnameVerifier());
          sslConfs.put(ssl.getName(), new SslConf(socketFactory, hostnameVerifier));
        } catch (IOException | UnrecoverableKeyException | NoSuchAlgorithmException
            | KeyStoreException | CertificateException | KeyManagementException
            | ObjectCreationException ex) {
          LOG.error("could not initialize SSL configuration " + ssl.getName()
              + ": " + ex.getMessage(), ex);
          return false;
        }
      }
    }

    // responders
    Map<String, Responder> responders = new HashMap<>();
    for (CmpClientConf.Responder m : conf.getResponders()) {
      X509Certificate cert;
      try {
        cert = X509Util.parseCert(m.getCert().readContent());
      } catch (CertificateException | IOException ex) {
        LogUtil.error(LOG, ex, "could not configure responder " + m.getName());
        return false;
      }

      Responder responder;
      if (m.getSignature() != null) {
        Set<String> algoNames = new HashSet<>();
        for (String algo : m.getSignature().getSignatureAlgos()) {
          algoNames.add(algo);
        }
        AlgorithmValidator sigAlgoValidator;
        try {
          sigAlgoValidator = new CollectionAlgorithmValidator(algoNames);
        } catch (NoSuchAlgorithmException ex) {
          LogUtil.error(LOG, ex, "could not initialize CollectionAlgorithmValidator");
          return false;
        }

        responder = new Responder.SignaturetCmpResponder(cert, sigAlgoValidator);
      } else { // if (m.getPbmMac() != null)
        CmpClientConf.Responder.PbmMac mac = m.getPbmMac();
        X500Name subject = X500Name.getInstance(cert.getSubjectX500Principal().getEncoded());
        responder = new Responder.PbmMacCmpResponder(subject, mac.getOwfAlgos(), mac.getMacAlgos());
      }

      responders.put(m.getName(), responder);
    }

    // CA;
    Set<CaConf> cas = new HashSet<>();
    for (CmpClientConf.Ca caType : conf.getCas()) {
      String caName = caType.getName();
      try {
        // responder
        Responder responder = responders.get(caType.getResponder());
        if (responder == null) {
          LOG.error("no responder named {} is configured", caType.getResponder());
          return false;
        }

        SSLSocketFactory sslSocketFactory = null;
        HostnameVerifier hostnameVerifier = null;
        if (caType.getSsl() != null) {
          SslConf sslConf = sslConfs.get(caType.getSsl());
          if (sslConf == null) {
            LOG.error("no ssl named {} is configured", caType.getSsl());
          } else {
              sslSocketFactory = sslConf.getSslSocketFactory();
              hostnameVerifier = sslConf.getHostnameVerifier();
          }
        }

        CaConf ca = new CaConf(caName, caType.getUrl(), caType.getHealthUrl(),
            caType.getRequestor(), responder, sslSocketFactory, hostnameVerifier);

        // CA cert
        if (caType.getCaCert().isAutoconf()) {
          ca.setCertAutoconf(true);
        } else {
          ca.setCertAutoconf(false);
          ca.setCert(X509Util.parseCert(caType.getCaCert().getCert().getBinary()));
        }

        // CMPControl
        CmpClientConf.Cmpcontrol cmpCtrlType = caType.getCmpcontrol();
        ca.setCmpControlAutoconf(cmpCtrlType.isAutoconf());
        if (!ca.isCmpControlAutoconf()) {
          Boolean tmpBo = cmpCtrlType.getRrAkiRequired();
          CaConf.CmpControl control = new CaConf.CmpControl(
              (tmpBo == null) ? false : tmpBo.booleanValue());
          ca.setCmpControl(control);
        }

        // Certprofiles
        CmpClientConf.Certprofiles certprofilesType = caType.getCertprofiles();
        ca.setCertprofilesAutoconf(certprofilesType.isAutoconf());
        if (!ca.isCertprofilesAutoconf()) {
          List<CmpClientConf.Certprofile> types = certprofilesType.getProfiles();
          Set<CertprofileInfo> profiles = new HashSet<>(types.size());
          for (CmpClientConf.Certprofile m : types) {
            String conf0 = null;
            if (m.getConf() != null) {
              conf0 = m.getConf().getValue();
              if (conf0 == null) {
                conf0 = new String(IoUtil.read(m.getConf().getFile()));
              }
            }

            CertprofileInfo profile = new CertprofileInfo(m.getName(), m.getType(), conf0);
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
        return false;
      }
    }

    // requestors
    Map<String, Requestor> requestors = new HashMap<>();

    for (CmpClientConf.Requestor requestorConf : conf.getRequestors()) {
      boolean signRequest = requestorConf.isSignRequest();
      String name = requestorConf.getName();
      Requestor requestor;

      if (requestorConf.getSignature() != null) {
        CmpClientConf.Requestor.Signature cf = requestorConf.getSignature();
        //requestorSignRequests.put(name, cf.isSignRequest());

        X509Certificate requestorCert = null;
        if (cf.getCert() != null) {
          try {
            requestorCert = X509Util.parseCert(cf.getCert().getBinary());
          } catch (Exception ex) {
            LogUtil.error(LOG, ex,
                "could not parse certificate of rquestor " + requestorConf.getName());
            return false;
          }
        }

        if (cf.getSignerType() != null) {
          try {
            SignerConf signerConf = new SignerConf(cf.getSignerConf());
            ConcurrentContentSigner requestorSigner = securityFactory.createSigner(
                cf.getSignerType(), signerConf, requestorCert);
            requestor = new SignatureCmpRequestor(
                signRequest, requestorSigner, securityFactory);
          } catch (ObjectCreationException ex) {
            LogUtil.error(LOG, ex, "could not create rquestor " + requestorConf.getName());
            return false;
          }
        } else {
          if (signRequest) {
            LOG.error("signer of requestor must be configured");
            return false;
          } else if (requestorCert == null) {
            LOG.error("at least one of certificate and signer of requestor must be configured");
            return false;
          } else {
            requestor = new SignatureCmpRequestor(requestorCert);
          }
        }
      } else {
        CmpClientConf.Requestor.PbmMac cf = requestorConf.getPbmMac();
        X500Name x500name = new X500Name(cf.getSender());
        AlgorithmIdentifier owf = HashAlgo.getNonNullInstance(cf.getOwf()).getAlgorithmIdentifier();
        AlgorithmIdentifier mac;
        try {
          mac = AlgorithmUtil.getMacAlgId(cf.getMac());
        } catch (NoSuchAlgorithmException ex) {
          LOG.error("Unknown MAC algorithm {}", cf.getMac());
          return false;
        }

        requestor = new PbmMacCmpRequestor(signRequest, x500name,
            cf.getPassword().toCharArray(), cf.getKid(), owf, cf.getIterationCount(), mac);
      }

      requestors.put(name, requestor);
    }

    for (CaConf ca :cas) {
      if (this.casMap.containsKey(ca.getName())) {
        LOG.error("duplicate CAs with the same name {}", ca.getName());
        return false;
      }

      String requestorName = ca.getRequestorName();

      if (requestors.containsKey(requestorName)) {
        CmpAgent agent = new CmpAgent(requestors.get(requestorName), ca.getResponder(), ca.getUrl(),
            securityFactory, ca.getSslSocketFactory(), ca.getHostnameVerifier());
        ca.setAgent(agent);
      } else {
        LOG.error("could not find requestor named {} for CA {}", requestorName, ca.getName());
        return false;
      }

      this.casMap.put(ca.getName(), ca);
    }

    if (!autoConfCaNames.isEmpty()) {
      Integer caInfoUpdateInterval = conf.getCainfoUpdateInterval();
      if (caInfoUpdateInterval == null) {
        caInfoUpdateInterval = 10;
      } else if (caInfoUpdateInterval <= 0) {
        caInfoUpdateInterval = 0;
      } else if (caInfoUpdateInterval < 5) {
        caInfoUpdateInterval = 5;
      }

      LOG.info("configuring CAs {}", autoConfCaNames);
      Set<String> failedCaNames = autoConfCas(autoConfCaNames);

      if (CollectionUtil.isNonEmpty(failedCaNames)) {
        LOG.error("could not configure following CAs {}", failedCaNames);
        return false;
      }

      if (caInfoUpdateInterval > 0) {
        scheduledThreadPoolExecutor = new ScheduledThreadPoolExecutor(1);
        scheduledThreadPoolExecutor.scheduleAtFixedRate(new ClientConfigUpdater(),
            caInfoUpdateInterval, caInfoUpdateInterval, TimeUnit.MINUTES);
      }
    }

    initialized.set(true);
    LOG.info("initialized");
    return true;
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
      throws CmpClientException, PkiErrorException {
    Args.notNull(csr, "csr");

    initIfNotInitialized();

    if (caName == null) {
      caName = getCaNameForProfile(profile);
    } else {
      caName = caName.toLowerCase();
    }

    if (caName == null) {
      throw new CmpClientException("certprofile " + profile + " is not supported by any CA");
    }

    CaConf ca = casMap.get(caName);
    if (ca == null) {
      throw new CmpClientException("could not find CA named " + caName);
    }

    final String id = "cert-1";
    CsrEnrollCertRequest request = new CsrEnrollCertRequest(id, profile, csr);
    EnrollCertResponse result = ca.getAgent().requestCertificate(
        request, notBefore, notAfter, debug);

    return parseEnrollCertResult(result);
  } // method requestCert

  @Override
  public EnrollCertResult enrollCerts(String caName, EnrollCertRequest request,
      ReqRespDebug debug) throws CmpClientException, PkiErrorException {
    List<EnrollCertRequest.Entry> requestEntries =
          Args.notNull(request, "request").getRequestEntries();
    if (CollectionUtil.isEmpty(requestEntries)) {
      return null;
    }

    initIfNotInitialized();

    boolean bo = (caName != null);
    if (caName == null) {
      // detect the CA name
      String profile = requestEntries.get(0).getCertprofile();
      caName = getCaNameForProfile(profile);
      if (caName == null) {
        throw new CmpClientException("certprofile " + profile + " is not supported by any CA");
      }
    } else {
      caName = caName.toLowerCase();
    }

    if (bo || request.getRequestEntries().size() > 1) {
      // make sure that all requests are targeted on the same CA
      for (EnrollCertRequest.Entry entry : request.getRequestEntries()) {
        String profile = entry.getCertprofile();
        if (profile != null) {
          checkCertprofileSupportInCa(profile, caName);
        }
      }
    }

    CaConf ca = casMap.get(caName);
    if (ca == null) {
      throw new CmpClientException("could not find CA named " + caName);
    }

    EnrollCertResponse result = ca.getAgent().requestCertificate(request, debug);
    return parseEnrollCertResult(result);
  } // method requestCerts

  private void checkCertprofileSupportInCa(String certprofile, String caName)
      throws CmpClientException {
    if (caName != null) {
      caName = caName.toLowerCase();
      CaConf ca = casMap.get(caName);
      if (ca == null) {
        throw new CmpClientException("unknown ca: " + caName);
      }

      if (!ca.supportsProfile(certprofile)) {
        throw new CmpClientException("certprofile " + certprofile + " is not supported by the CA "
            + caName);
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

      if (caName == null) {
        caName = ca.getName();
      } else {
        throw new CmpClientException("certprofile " + certprofile
            + " supported by more than one CA, please specify the CA name.");
      }
    }

    if (caName == null) {
      throw new CmpClientException("unsupported certprofile " + certprofile);
    }
  }

  @Override
  public CertIdOrError revokeCert(String caName, X509Certificate cert, int reason,
      Date invalidityDate, ReqRespDebug debug) throws CmpClientException, PkiErrorException {
    Args.notNull(cert, "cert");
    initIfNotInitialized();
    CaConf ca = getCa(caName);
    assertIssuedByCa(cert, ca);
    return revokeCert(ca, cert.getSerialNumber(), reason, invalidityDate, debug);
  }

  @Override
  public CertIdOrError revokeCert(String caName, BigInteger serial, int reason, Date invalidityDate,
      ReqRespDebug debug) throws CmpClientException, PkiErrorException {
    initIfNotInitialized();
    CaConf ca = getCa(caName);
    return revokeCert(ca, serial, reason, invalidityDate, debug);
  }

  private CertIdOrError revokeCert(CaConf ca, BigInteger serial, int reason,
      Date invalidityDate, ReqRespDebug debug) throws CmpClientException, PkiErrorException {
    Args.notNull(ca, "ca");
    Args.notNull(serial, "serial");

    final String id = "cert-1";
    RevokeCertRequest.Entry entry = new RevokeCertRequest.Entry(id, ca.getSubject(), serial, reason,
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
      throws CmpClientException, PkiErrorException {
    List<RevokeCertRequest.Entry> requestEntries =
          Args.notNull(request, "request").getRequestEntries();
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

    initIfNotInitialized();

    final String caName = getCaNameByIssuer(issuer);
    CaConf caConf = casMap.get(caName);
    if (caConf.getCmpControl().isRrAkiRequired()) {
      byte[] aki = caConf.getSubjectKeyIdentifier();
      List<RevokeCertRequest.Entry> entries = request.getRequestEntries();
      for (RevokeCertRequest.Entry entry : entries) {
        if (entry.getAuthorityKeyIdentifier() == null) {
          entry.setAuthorityKeyIdentifier(aki);
        }
      }
    }

    RevokeCertResponse result = caConf.getAgent().revokeCertificate(request, debug);
    return parseRevokeCertResult(result);
  }

  private Map<String, CertIdOrError> parseRevokeCertResult(RevokeCertResponse result)
      throws CmpClientException {
    Map<String, CertIdOrError> ret = new HashMap<>();

    for (ResultEntry re : result.getResultEntries()) {
      CertIdOrError certIdOrError;
      if (re instanceof ResultEntry.RevokeCert) {
        ResultEntry.RevokeCert entry = (ResultEntry.RevokeCert) re;
        certIdOrError = new CertIdOrError(entry.getCertId());
      } else if (re instanceof ResultEntry.Error) {
        ResultEntry.Error entry = (ResultEntry.Error) re;
        certIdOrError = new CertIdOrError(entry.getStatusInfo());
      } else {
        throw new CmpClientException("unknown type " + re.getClass().getName());
      }

      ret.put(re.getId(), certIdOrError);
    }

    return ret;
  }

  @Override
  public X509CRL downloadCrl(String caName, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    caName = Args.toNonBlankLower(caName, "caName");
    return downloadCrl(caName, (BigInteger) null, debug);
  }

  @Override
  public X509CRL downloadCrl(String caName, BigInteger crlNumber, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    caName = Args.toNonBlankLower(caName, "caName");
    initIfNotInitialized();

    CaConf ca = casMap.get(caName);
    if (ca == null) {
      throw new IllegalArgumentException("unknown CA " + caName);
    }

    CmpAgent agent = ca.getAgent();
    X509CRL result = (crlNumber == null) ? agent.downloadCurrentCrl(debug)
          : agent.downloadCrl(crlNumber, debug);

    return result;
  }

  @Override
  public X509CRL generateCrl(String caName, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    caName = Args.toNonBlankLower(caName, "caName");

    initIfNotInitialized();

    CaConf ca = casMap.get(caName);
    if (ca == null) {
      throw new IllegalArgumentException("unknown CA " + caName);
    }

    return ca.getAgent().generateCrl(debug);
  }

  @Override
  public String getCaNameByIssuer(X500Name issuer) throws CmpClientException {
    Args.notNull(issuer, "issuer");

    initIfNotInitialized();

    for (String name : casMap.keySet()) {
      final CaConf ca = casMap.get(name);
      if (!ca.isCaInfoConfigured()) {
        continue;
      }

      if (CompareUtil.equalsObject(ca.getSubject(), issuer)) {
        return name;
      }
    }

    throw new CmpClientException("unknown CA for issuer: " + issuer);
  }

  private String getCaNameForProfile(String certprofile) throws CmpClientException {
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
        throw new CmpClientException("certprofile " + certprofile
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
    this.confFile = Args.notBlank(confFile, "confFile");
  }

  @Override
  public Set<String> getCaNames() throws CmpClientException {
    initIfNotInitialized();
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
      throws CmpClientException, PkiErrorException {
    Args.notNull(cert, "cert");
    initIfNotInitialized();

    CaConf ca = getCa(caName);
    assertIssuedByCa(cert, ca);
    return unrevokeCert(ca, cert.getSerialNumber(), debug);
  }

  @Override
  public CertIdOrError unrevokeCert(String caName, BigInteger serial, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    initIfNotInitialized();
    CaConf ca = getCa(caName);
    return unrevokeCert(ca, serial, debug);
  }

  private CertIdOrError unrevokeCert(CaConf ca, BigInteger serial, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    Args.notNull(ca, "ca");
    Args.notNull(serial, "serial");
    final String id = "cert-1";
    ResultEntry.UnrevokeOrRemoveCert entry = new ResultEntry.UnrevokeOrRemoveCert(
        id, ca.getSubject(), serial);
    if (ca.getCmpControl().isRrAkiRequired()) {
      entry.setAuthorityKeyIdentifier(ca.getSubjectKeyIdentifier());
    }

    UnrevokeOrRemoveCertRequest request = new UnrevokeOrRemoveCertRequest();
    UnrevokeOrRemoveCertRequest.Entry entry2 = new UnrevokeOrRemoveCertRequest.Entry(
        entry.getId(), entry.getIssuer(), entry.getSerialNumber());
    entry2.setAuthorityKeyIdentifier(entry.getAuthorityKeyIdentifier());
    request.addRequestEntry(entry2);
    Map<String, CertIdOrError> result = unrevokeCerts(request, debug);
    return (result == null) ? null : result.get(id);
  }

  @Override
  public Map<String, CertIdOrError> unrevokeCerts(UnrevokeOrRemoveCertRequest request,
      ReqRespDebug debug) throws CmpClientException, PkiErrorException {
    Args.notNull(request, "request");

    initIfNotInitialized();
    List<UnrevokeOrRemoveCertRequest.Entry> requestEntries = request.getRequestEntries();
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
    CmpAgent agent = casMap.get(caName).getAgent();
    RevokeCertResponse result = agent.unrevokeCertificate(request, debug);
    return parseRevokeCertResult(result);
  } // method unrevokeCerts

  @Override
  public CertIdOrError removeCert(String caName, X509Certificate cert, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    Args.notNull(cert, "cert");
    initIfNotInitialized();
    CaConf ca = getCa(caName);
    assertIssuedByCa(cert, ca);
    return removeCert(ca, cert.getSerialNumber(), debug);
  }

  @Override
  public CertIdOrError removeCert(String caName, BigInteger serial, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    initIfNotInitialized();
    CaConf ca = getCa(caName);
    return removeCert(ca, serial, debug);
  }

  private CertIdOrError removeCert(CaConf ca, BigInteger serial, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    Args.notNull(ca, "ca");
    Args.notNull(serial, "serial");
    final String id = "cert-1";
    UnrevokeOrRemoveCertRequest.Entry entry =
        new UnrevokeOrRemoveCertRequest.Entry(id, ca.getSubject(), serial);
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
      ReqRespDebug debug) throws CmpClientException, PkiErrorException {
    Args.notNull(request, "request");

    initIfNotInitialized();
    List<UnrevokeOrRemoveCertRequest.Entry> requestEntries = request.getRequestEntries();
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
    CmpAgent agent = casMap.get(caName).getAgent();
    RevokeCertResponse result = agent.removeCertificate(request, debug);
    return parseRevokeCertResult(result);
  }

  @Override
  public Set<CertprofileInfo> getCertprofiles(String caName) throws CmpClientException {
    caName = Args.toNonBlankLower(caName, "caName");

    initIfNotInitialized();
    CaConf ca = casMap.get(caName);
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
  public HealthCheckResult getHealthCheckResult(String caName) throws CmpClientException {
    caName = Args.toNonBlankLower(caName, "caName");

    String name = "X509CA";
    HealthCheckResult healthCheckResult = new HealthCheckResult();
    healthCheckResult.setName(name);

    try {
      initIfNotInitialized();
    } catch (CmpClientException ex) {
      LogUtil.error(LOG, ex, "could not initialize CaCleint");
      healthCheckResult.setHealthy(false);
      return healthCheckResult;
    }

    CaConf ca = casMap.get(caName);
    if (ca == null) {
      throw new IllegalArgumentException("unknown CA " + caName);
    }

    String healthUrlStr = ca.getHealthUrl();

    URL serverUrl;
    try {
      serverUrl = new URL(healthUrlStr);
    } catch (MalformedURLException ex) {
      throw new CmpClientException("invalid URL '" + healthUrlStr + "'");
    }

    try {
      HttpURLConnection httpUrlConnection = IoUtil.openHttpConn(serverUrl);
      if (httpUrlConnection instanceof HttpsURLConnection) {
        if (ca.getHostnameVerifier() != null) {
          ((HttpsURLConnection) httpUrlConnection).setHostnameVerifier(ca.getHostnameVerifier());
        }
        if (ca.getSslSocketFactory() != null) {
          ((HttpsURLConnection) httpUrlConnection).setSSLSocketFactory(ca.getSslSocketFactory());
        }
      }

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
        try {
          healthCheckResult = JSON.parseObject(responseBytes, HealthCheckResult.class);
        } catch (RuntimeException ex) {
          LogUtil.error(LOG, ex, "IOException while parsing the health json message");
          if (LOG.isDebugEnabled()) {
            LOG.debug("json message: {}", new String(responseBytes));
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

  private EnrollCertResult parseEnrollCertResult(EnrollCertResponse result)
      throws CmpClientException {
    Map<String, EnrollCertResult.CertifiedKeyPairOrError> certOrErrors = new HashMap<>();
    for (ResultEntry resultEntry : result.getResultEntries()) {
      EnrollCertResult.CertifiedKeyPairOrError certOrError;
      if (resultEntry instanceof ResultEntry.EnrollCert) {
        ResultEntry.EnrollCert entry = (ResultEntry.EnrollCert) resultEntry;
        try {
          java.security.cert.Certificate cert = getCertificate(entry.getCert());
          certOrError =
              new EnrollCertResult.CertifiedKeyPairOrError(cert, entry.getPrivateKeyInfo());
        } catch (CertificateException ex) {
          throw new CmpClientException(String.format(
              "CertificateParsingException for request (id=%s): %s",
              entry.getId(), ex.getMessage()));
        }
      } else if (resultEntry instanceof ResultEntry.Error) {
        certOrError =
            new EnrollCertResult.CertifiedKeyPairOrError(
                  ((ResultEntry.Error) resultEntry).getStatusInfo());
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
    for (EnrollCertResult.CertifiedKeyPairOrError certOrError : certOrErrors.values()) {
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

    for (EnrollCertResult.CertifiedKeyPairOrError certOrError : certOrErrors.values()) {
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

  private static CmpClientConf parse(InputStream configStream) throws CmpClientException {
    CmpClientConf conf;
    try {
      conf = JSON.parseObject(configStream, CmpClientConf.class);
      conf.validate();
    } catch (IOException | InvalidConfException | RuntimeException ex) {
      throw new CmpClientException("parsing profile failed, message: " + ex.getMessage(), ex);
    } finally {
      try {
        configStream.close();
      } catch (IOException ex) {
        LOG.warn("could not close confStream: {}", ex.getMessage());
      }
    }

    // canonicalize the names
    for (CmpClientConf.Requestor m : conf.getRequestors()) {
      m.setName(m.getName().toLowerCase());
    }

    for (CmpClientConf.Responder m : conf.getResponders()) {
      m.setName(m.getName().toLowerCase());
    }

    for (CmpClientConf.Ca ca : conf.getCas()) {
      ca.setName(ca.getName().toLowerCase());
      ca.setRequestor(ca.getRequestor().toLowerCase());
      ca.setResponder(ca.getResponder().toLowerCase());
    }

    return conf;
  } // method parse

  private CaConf getCa(String caName) throws CmpClientException {
    if (caName == null) {
      Iterator<String> names = casMap.keySet().iterator();
      if (!names.hasNext()) {
        throw new CmpClientException("no CA is configured");
      }
      caName = names.next();
    } else {
      caName = caName.toLowerCase();
    }

    CaConf ca = casMap.get(caName);
    if (ca == null) {
      throw new CmpClientException("could not find CA named " + caName);
    }
    return ca;
  }

  private static void assertIssuedByCa(X509Certificate cert, CaConf ca)
      throws CmpClientException {
    boolean issued;
    try {
      issued = X509Util.issues(ca.getCert(), cert);
    } catch (CertificateEncodingException ex) {
      LogUtil.error(LOG, ex);
      issued = false;
    }
    if (!issued) {
      throw new CmpClientException("the given certificate is not issued by the CA");
    }
  }

  @Override
  public java.security.cert.Certificate getCaCert(String caName) throws CmpClientException {
    initIfNotInitialized();

    CaConf ca = casMap.get(caName.toLowerCase());
    return ca == null ? null : ca.getCert();
  }

  @Override
  public X500Name getCaCertSubject(String caName) throws CmpClientException {
    initIfNotInitialized();
    CaConf ca = casMap.get(caName.toLowerCase());
    return ca == null ? null : ca.getSubject();
  }

}
