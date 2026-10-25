// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.ca;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.codec.util.Args;
import org.xipki.codec.json.JsonMap;
import org.xipki.codec.json.JsonParser;
import org.xipki.ca.api.CertprofileException;
import org.xipki.pkix.util.misc.LogUtil;
import org.xipki.pkix.util.misc.StringUtil;

import java.io.Closeable;
import java.io.IOException;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * CA Qa System Manager.
 *
 * @author Lijun Liao (xipki)
 */
public class CaQaSystemManager implements Closeable {

  private static final Logger LOG = LoggerFactory.getLogger(CaQaSystemManager.class);

  private String confFile = "xipki/ca-qa/qa-certcheck-conf.json";

  private final Map<String, CertprofileQa> profileMap = new HashMap<>();

  private final Map<String, IssuerInfo> issuerInfoMap = new HashMap<>();

  private final AtomicBoolean initialized = new AtomicBoolean(false);

  public CaQaSystemManager() {
  }

  public String getConfFile() {
    return confFile;
  }

  public void setConfFile(String confFile) {
    this.confFile = Args.notBlank(confFile, "confFile");
  }

  public boolean init() {
    if (StringUtil.isBlank(confFile)) {
      throw new IllegalStateException("confFile may not be null and empty");
    }

    LOG.info("initializing ...");
    initialized.set(false);
    issuerInfoMap.clear();

    QaconfType qaConf;
    try {
      JsonMap json = JsonParser.parseMap(Path.of(confFile), true);
      qaConf = QaconfType.parse(json);
    } catch (Exception ex) {
      final String message = "could not parse the QA configuration";
      LogUtil.error(LOG, ex, message);
      return false;
    }

    for (QaconfType.Issuer issuer : qaConf.getIssuers()) {
      byte[] certBytes;
      try {
        certBytes = issuer.getCert().readContent();
      } catch (IOException ex) {
        LogUtil.error(LOG, ex, "could not read the certificate " +
            "bytes of issuer " + issuer.getName());
        continue;
      }

      String str = issuer.getValidityMode();
      boolean cutoffNotAfter;
      if (StringUtil.isBlank(str) || "CUTOFF".equalsIgnoreCase(str)) {
        cutoffNotAfter = true;
      } else if ("LAX".equalsIgnoreCase(str)) {
        cutoffNotAfter = false;
      } else {
        LOG.error("invalid validityMode {}", str);
        return false;
      }

      IssuerInfo issuerInfo;
      try {
        issuerInfo = new IssuerInfo(issuer.getCaIssuerUrls(),
            issuer.getOcspUrls(), issuer.getCrlUrls(),
            issuer.getDeltaCrlUrls(), certBytes, cutoffNotAfter);
      } catch (CertificateException ex) {
        LogUtil.error(LOG, ex, "could not parse certificate of issuer " + issuer.getName());
        continue;
      }

      issuerInfoMap.put(issuer.getName(), issuerInfo);
      LOG.info("configured X509 issuer {}", issuer.getName());
    }

    for (QaconfType.Certprofile type : qaConf.getCertprofiles()) {
      String name = type.getName();
      try {
        String content = type.readContent();
        CertprofileQa certprofileQa = new CertprofileQa(content);

        profileMap.put(name, certprofileQa);
        LOG.info("configured X509 certificate profile {}", name);
      } catch (IOException | CertprofileException ex) {
        LogUtil.error(LOG, ex, "could not parse QA certificate profile " + name);
      }
    }

    initialized.set(true);
    LOG.info("initialized");

    return true;
  } // method init

  @Override
  public void close() {
  }

  public Set<String> getIssuerNames() {
    assertInitialized();
    return Collections.unmodifiableSet(issuerInfoMap.keySet());
  }

  /**
   * Returns the issuer information.
   * @param issuerName
   *          Name of the issuer
   * @return the issuer
   */
  public IssuerInfo getIssuer(String issuerName) {
    assertInitialized();
    return issuerInfoMap.get(Args.notNull(issuerName, "issuerName"));
  }

  public Set<String> getCertprofileNames() {
    assertInitialized();
    return Collections.unmodifiableSet(profileMap.keySet());
  }

  /**
   * Returns the Certprofile for the given name.
   * @param certprofileName
   *          Name of the cert profile.
   * @return the cert profile.
   */
  public CertprofileQa getCertprofile(String certprofileName) {
    assertInitialized();
    return profileMap.get(Args.notNull(certprofileName, "certprofileName"));
  }

  private void assertInitialized() {
    if (!initialized.get()) {
      init();
    }

    if (!initialized.get()) {
      throw new IllegalStateException("Could not start CaQaSystemManager.");
    }
  }

}
