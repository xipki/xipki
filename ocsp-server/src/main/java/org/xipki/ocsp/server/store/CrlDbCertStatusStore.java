/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

package org.xipki.ocsp.server.store;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.ocsp.api.OcspStoreException;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.CrlReason;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.DateUtil;
import org.xipki.util.IoUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.2.0
 */

public class CrlDbCertStatusStore extends DbCertStatusStore {

  public static final String KEY_CA_REVOCATION_TIME = "ca.revocation.time";

  public static final String KEY_CA_INVALIDITY_TIME = "ca.invalidity.time";

  private class CrlUpdateService implements Runnable {

    @Override
    public void run() {
      try {
        updateStore(datasource);
      } catch (Throwable th) {
        LogUtil.error(LOG, th, "error while calling initializeStore() for store " + name);
      }
    }

  } // StoreUpdateService

  private static final Logger LOG = LoggerFactory.getLogger(CrlDbCertStatusStore.class);

  private final AtomicBoolean crlUpdateInProcess = new AtomicBoolean(false);

  private X509Certificate caCert;

  private X509Certificate issuerCert;

  private String crlFilename;

  private String crlUrl;

  private String certsDirName;

  private boolean crlUpdated;

  private boolean crlUpdateFailed;

  /**
   * Initialize the store.
   *
   * @param sourceConf
   * the store source configuration. It contains following key-value pairs:
   * <ul>
   * <li>crlFile: required
   *   <p/>
   *   CRL file.The optional file ${crlFile}.revocation contains the revocation information
   *   of the CA itself.<p/>
   *   Just create the file ${crlFile}.UPDATEME to tell responder to update the CRL.</li>
   * <li>crlUrl: optional
   *   <p/>
   *   CRL url</li>
   * <li>caCertFile: optional
   *   <p/>
   *   CA cert file.</li>
   * <li>issuerCertFile
   *   <p/>certificate used to verify the CRL signature.<br/>
   *   required for indirect CRL, otherwise optional</li>
   * <li>certsDir: optional
   *   <p/>
   *   Folder containing the DER-encoded certificates suffixed with ".der" and ".crt"</li>
   *  </ul>
   * @param datasource DataSource.
   */
  public void init(Map<String, ? extends Object> sourceConf, DataSourceWrapper datasource)
      throws OcspStoreException {
    Args.notNull(sourceConf, "sourceConf");

    this.crlFilename = IoUtil.expandFilepath(getStrValue(sourceConf, "crlFile", true));
    this.crlUrl = getStrValue(sourceConf, "crlUrl", false);
    this.caCert = parseCert(getStrValue(sourceConf, "caCertFile", true));

    String str = getStrValue(sourceConf, "certsDir", false);
    this.certsDirName = (str == null) ? null : IoUtil.expandFilepath(str);

    str = getStrValue(sourceConf, "issuerCertFile", false);
    this.issuerCert = (str == null) ? null : parseCert(str);

    updateStore(datasource);
    super.init(sourceConf, datasource);
  }

  private static String getStrValue(Map<String, ? extends Object> sourceConf,
      String confName, boolean mandatory) {
    Object objVal = sourceConf.get(confName);
    if (objVal == null) {
      if (mandatory) {
        throw new IllegalArgumentException(
            "mandatory " + confName + " is not specified in sourceConf");
      } else {
        return null;
      }
    }

    if (objVal instanceof String) {
      return (String) objVal;
    } else {
      throw new IllegalArgumentException(
          "content of " + confName + " is not String, but " + objVal.getClass().getName());
    }
  }

  @Override
  protected List<Runnable> getScheduledServices() {
    return Arrays.asList(new CrlUpdateService());
  }

  @Override
  protected boolean isInitialized() {
    return crlUpdated && super.isInitialized();
  }

  @Override
  protected boolean isInitializationFailed() {
    return crlUpdateFailed || super.isInitializationFailed();
  }

  private static X509Certificate parseCert(String certFile) throws OcspStoreException {
    try {
      return X509Util.parseCert(new File(certFile));
    } catch (CertificateException | IOException ex) {
      throw new OcspStoreException("could not parse X.509 certificate from file "
          + certFile + ": " + ex.getMessage(), ex);
    }
  }

  private synchronized void updateStore(DataSourceWrapper datasource) {
    if (crlUpdateInProcess.get()) {
      return;
    }

    File updateMeFile = new File(crlFilename + ".UPDATEME");
    if (!updateMeFile.exists()) {
      LOG.info("The CRL will not be updated. Create new file {} to force the update",
          updateMeFile.getAbsolutePath());
      return;
    }

    Boolean updateCrlSuccessful = null;
    crlUpdateInProcess.set(true);

    try {
      File fullCrlFile = new File(crlFilename);
      if (!fullCrlFile.exists()) {
        // file does not exist
        LOG.warn("CRL File {} does not exist", crlFilename);
        return;
      }

      LOG.info("UPDATE_CERTSTORE: a newer CRL is available");
      updateCrlSuccessful = false;

      X509CRL crl = X509Util.parseCrl(new File(crlFilename));

      File revFile = new File(crlFilename + ".revocation");
      CertRevocationInfo caRevInfo = null;
      if (revFile.exists()) {
        Properties props = new Properties();
        InputStream is = Files.newInputStream(revFile.toPath());
        try {
          props.load(is);
        } finally {
          is.close();
        }

        String str = props.getProperty(KEY_CA_REVOCATION_TIME);
        if (StringUtil.isNotBlank(str)) {
          Date revocationTime = DateUtil.parseUtcTimeyyyyMMddhhmmss(str);
          Date invalidityTime = null;

          str = props.getProperty(KEY_CA_INVALIDITY_TIME);
          if (StringUtil.isNotBlank(str)) {
            invalidityTime = DateUtil.parseUtcTimeyyyyMMddhhmmss(str);
          }
          caRevInfo = new CertRevocationInfo(CrlReason.UNSPECIFIED, revocationTime, invalidityTime);
        }
      }

      ImportCrl importCrl = new ImportCrl(datasource, crl, crlUrl,
          caCert, issuerCert, caRevInfo, certsDirName);
      updateCrlSuccessful = importCrl.importCrlToOcspDb();
      crlUpdated = true;
      if (updateCrlSuccessful) {
        crlUpdateFailed = false;
        LOG.info("updated CertStore {} successfully", name);
      } else {
        crlUpdateFailed = true;
        LOG.error("updating CertStore {} failed", name);
      }
    } catch (Throwable th) {
      LogUtil.error(LOG, th, "error while executing updateStore()");
      crlUpdateFailed = true;
      crlUpdated = true;
    } finally {
      updateMeFile.delete();
      crlUpdateInProcess.set(false);
      if (updateCrlSuccessful != null) {
        if (updateCrlSuccessful.booleanValue()) {
          LOG.info("UPDATE_CRL: successful");
        } else {
          LOG.warn("UPDATE_CRL: failed");
        }
      }
    }
  } // method initializeStore

}
