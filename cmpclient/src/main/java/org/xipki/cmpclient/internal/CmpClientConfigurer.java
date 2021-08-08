/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

import com.alibaba.fastjson.JSON;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.cmpclient.CertprofileInfo;
import org.xipki.cmpclient.CmpClientConf;
import org.xipki.cmpclient.CmpClientConf.Certs;
import org.xipki.cmpclient.CmpClientException;
import org.xipki.cmpclient.PkiErrorException;
import org.xipki.cmpclient.internal.Requestor.PbmMacCmpRequestor;
import org.xipki.cmpclient.internal.Requestor.SignatureCmpRequestor;
import org.xipki.security.*;
import org.xipki.security.util.X509Util;
import org.xipki.util.*;
import org.xipki.util.http.HostnameVerifiers;
import org.xipki.util.http.SSLContextBuilder;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSocketFactory;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.xipki.util.Args.notBlank;

/**
 * CmpClientImpl configurer.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

final class CmpClientConfigurer {

  private class ClientConfigUpdater implements Runnable {

    private static final long MINUTE = 60L * 1000;

    private final AtomicBoolean inProcess = new AtomicBoolean(false);

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

        if (CollectionUtil.isNotEmpty(failedCaNames)) {
          LOG.warn("could not configure following CAs {}", failedCaNames);
        }

      } finally {
        lastUpdate = System.currentTimeMillis();
        inProcess.set(false);
      }
    } // method run

  } // class ClientConfigUpdater

  private static class SslConf {

    private final SSLSocketFactory sslSocketFactory;

    private final HostnameVerifier hostnameVerifier;

    SslConf(SSLSocketFactory sslSocketFactory, HostnameVerifier hostnameVerifier) {
      this.sslSocketFactory = sslSocketFactory;
      this.hostnameVerifier = hostnameVerifier;
    }

  } // class SslConf

  private static final Logger LOG = LoggerFactory.getLogger(CmpClientConfigurer.class);

  private static final X500Name NULL_GENERALNAME = new X500Name(new RDN[0]);

  private final Map<String, CaConf> casMap = new HashMap<>();

  private final Set<String> autoConfCaNames = new HashSet<>();

  private SecurityFactory securityFactory;

  private String confFile;

  private ScheduledThreadPoolExecutor scheduledThreadPoolExecutor;

  private final AtomicBoolean initialized = new AtomicBoolean(false);

  CmpClientConfigurer() {
  }

  void setSecurityFactory(SecurityFactory securityFactory) {
    this.securityFactory = securityFactory;
  }

  Map<String, CaConf> getCasMap() {
    return casMap;
  }

  CaConf getCaConf(String name) {
    return casMap.get(name.toLowerCase());
  }

  void close() {
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
  } // method close

  synchronized void initIfNotInitialized()
      throws CmpClientException {
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
  } // method initIfNotInitialized

  synchronized boolean init() {
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
          if (ssl.getKeystore() != null) {
            char[] pwd = ssl.getKeystorePassword() == null
                ? null : ssl.getKeystorePassword().toCharArray();
            builder.loadKeyMaterial(
                new ByteArrayInputStream(ssl.getKeystore().readContent()), pwd, pwd);
          }

          if (ssl.getTruststore() != null) {
            char[] pwd = ssl.getTruststorePassword() == null
                ? null : ssl.getTruststorePassword().toCharArray();
            builder.loadTrustMaterial(
                new ByteArrayInputStream(ssl.getTruststore().readContent()), pwd);
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
      X509Cert cert;
      try {
        cert = X509Util.parseCert(m.getCert().readContent());
      } catch (CertificateException | IOException ex) {
        LogUtil.error(LOG, ex, "could not configure responder " + m.getName());
        return false;
      }

      Responder responder;
      if (m.getSignature() != null) {
        Set<String> algoNames = new HashSet<>(m.getSignature().getSignatureAlgos());

        Set<SignAlgo> algos = new HashSet<>();
        for (String algoName : algoNames) {
          SignAlgo sa;
          try {
            sa = SignAlgo.getInstance(algoName);
          } catch (NoSuchAlgorithmException ex) {
            LOG.warn("algorithm is not supported {}, ignore it", algoName);
            continue;
          }

          algos.add(sa);
        }

        AlgorithmValidator sigAlgoValidator;
        try {
          if (algos.isEmpty()) {
            throw new NoSuchAlgorithmException("none of the signature algorithms "
                + algoNames + " are supported");
          }

          sigAlgoValidator = new CollectionAlgorithmValidator(algos);
        } catch (NoSuchAlgorithmException ex) {
          LogUtil.error(LOG, ex, "could not initialize CollectionAlgorithmValidator");
          return false;
        }

        responder = new Responder.SignatureCmpResponder(cert, sigAlgoValidator);
      } else { // if (m.getPbmMac() != null)
        CmpClientConf.Responder.PbmMac mac = m.getPbmMac();
        X500Name subject = cert.getSubject();
        try {
          responder = new Responder.PbmMacCmpResponder(subject, mac.getOwfAlgos(),
              mac.getMacAlgos());
        } catch (NoSuchAlgorithmException ex) {
          LogUtil.error(LOG, ex, "could not initialize PbmMacCmpResponder");
          return false;
        }
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
            return false;
          } else {
            sslSocketFactory = sslConf.sslSocketFactory;
            hostnameVerifier = sslConf.hostnameVerifier;
          }
        }

        CaConf ca = new CaConf(caName, caType.getUrl(), caType.getHealthUrl(),
            caType.getRequestor(), responder, sslSocketFactory, hostnameVerifier);

        // CA certchain
        Certs caCertchain = caType.getCaCertchain();
        if (caCertchain == null || caCertchain.isAutoconf()) {
          ca.setCertAutoconf(true);
        } else {
          ca.setCertAutoconf(false);
          List<FileOrBinary> certchainConf = caType.getCaCertchain().getCertificates();

          X509Cert caCert = X509Util.parseCert(certchainConf.get(0).readContent());
          Set<X509Cert> issuers = new HashSet<>();
          int size = certchainConf.size();
          if (size > 1) {
            for (int i = 1; i < size; i++) {
              X509Cert cert = X509Util.parseCert(certchainConf.get(i).readContent());
              issuers.add(cert);
            }

            X509Cert[] certchain = X509Util.buildCertPath(caCert, issuers);
            if (certchain.length != size) {
              LOG.error("cannot build certpath containing all configured issuers");
            }

            ca.setCertchain(Arrays.asList(certchain));
          } else {
            ca.setCertchain(Collections.singletonList(caCert));
          }
        }

        // DHPoc
        Certs dhpocCerts = caType.getDhpocCerts();
        if (dhpocCerts == null || dhpocCerts.isAutoconf()) {
          ca.setDhpocAutoconf(true);
        } else {
          ca.setDhpocAutoconf(false);
          List<X509Cert> dhpocs = new LinkedList<>();

          List<FileOrBinary> list = dhpocCerts.getCertificates();
          if (list != null) {
            for (FileOrBinary m : list) {
              X509Cert cert = X509Util.parseCert(m.readContent());
              dhpocs.add(cert);
            }
          }
          ca.setDhpocs(dhpocs);
        }

        // CMPControl
        CmpClientConf.Cmpcontrol cmpCtrlType = caType.getCmpcontrol();
        if (cmpCtrlType == null || cmpCtrlType.isAutoconf()) {
          ca.setCmpControlAutoconf(true);
        } else {
          ca.setCmpControlAutoconf(false);
          Boolean tmpBo = cmpCtrlType.getRrAkiRequired();
          CaConf.CmpControl control = new CaConf.CmpControl(
                  tmpBo != null && tmpBo);
          ca.setCmpControl(control);
        }

        // Certprofiles
        CmpClientConf.Certprofiles certprofilesType = caType.getCertprofiles();
        if (certprofilesType == null || certprofilesType.isAutoconf()) {
          ca.setCertprofilesAutoconf(true);
        } else {
          ca.setCertprofilesAutoconf(false);
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
        if (ca.isCertAutoconf() || ca.isCertprofilesAutoconf() || ca.isCmpControlAutoconf()
            || ca.isDhpocAutoconf()) {
          autoConfCaNames.add(caName);
        }
      } catch (IOException | CertificateException
          | CertPathBuilderException ex) {
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

        X509Cert requestorCert = null;
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
            requestor = new SignatureCmpRequestor(signRequest, requestorSigner);
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
        HashAlgo owfAlgo;
        try {
          owfAlgo = HashAlgo.getInstance(cf.getOwf());
        } catch (NoSuchAlgorithmException ex1) {
          LOG.error("Unknown OWF algorithm {}", cf.getOwf());
          return false;
        }

        SignAlgo macAlgo;
        try {
          macAlgo = SignAlgo.getInstance(cf.getMac());
        } catch (NoSuchAlgorithmException ex) {
          LOG.error("Unknown MAC algorithm {}", cf.getMac());
          return false;
        }

        requestor = new PbmMacCmpRequestor(signRequest, NULL_GENERALNAME,
            cf.getPassword().toCharArray(), cf.getKid(), owfAlgo, cf.getIterationCount(), macAlgo);
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

      if (CollectionUtil.isNotEmpty(failedCaNames)) {
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

  void setConfFile(String confFile) {
    this.confFile = notBlank(confFile, "confFile");
  }

  private static CmpClientConf parse(InputStream configStream)
      throws CmpClientException {
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

  /**
   * Configure the CAs automatically.
   *
   * @return names of CAs which may not been configured.
   */
  private Set<String> autoConfCas(Set<String> caNames) {
    if (caNames.isEmpty()) {
      return Collections.emptySet();
    }

    Set<String> caNamesWithError = new HashSet<>();

    for (String name : caNames) {
      CaConf ca = casMap.get(name);

      try {
        CaConf.CaInfo caInfo = ca.getAgent().retrieveCaInfo(name, null);
        if (ca.isCertAutoconf()) {
          ca.setCertchain(caInfo.getCertchain());
        }
        if (ca.isCertprofilesAutoconf()) {
          ca.setCertprofiles(caInfo.getCertprofiles());
        }
        if (ca.isCmpControlAutoconf()) {
          ca.setCmpControl(caInfo.getCmpControl());
        }
        if (ca.isDhpocAutoconf()) {
          ca.setDhpocs(caInfo.getDhpocs());
        }
        LOG.info("retrieved CAInfo for CA " + name);
      } catch (CmpClientException | PkiErrorException | CertificateEncodingException
            | RuntimeException ex) {
        caNamesWithError.add(name);
        LogUtil.error(LOG, ex, "could not retrieve CAInfo for CA " + name);
      }
    }

    return caNamesWithError;
  } // method autoConfCas

}
