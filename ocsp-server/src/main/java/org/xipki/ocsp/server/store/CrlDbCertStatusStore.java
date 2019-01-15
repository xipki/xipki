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
import java.util.Properties;
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.ocsp.api.OcspStoreException;
import org.xipki.ocsp.server.OcspServerConf;
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
        initializeStore(datasource);
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

  private boolean useUpdateDatesFromCrl;

  private boolean crlUpdated;

  private boolean crlUpdateFailed;

  public void init(SourceConf conf, DataSourceWrapper datasource) throws OcspStoreException {
    Args.notNull(conf, "conf");
    if (!(conf instanceof OcspServerConf.SourceConfImpl)) {
      throw new OcspStoreException("unknown conf " + conf.getClass().getName());
    }

    OcspServerConf.CrlSourceConf conf0 = ((OcspServerConf.SourceConfImpl) conf).getCrlSource();
    if (conf0 == null) {
      throw new OcspStoreException("conf.getCrlSource() may not be null");
    }

    this.datasource = Args.notNull(datasource, "datasource");

    this.crlFilename = IoUtil.expandFilepath(conf0.getCrlFile());
    this.crlUrl = conf0.getCrlUrl();
    this.certsDirName = (conf0.getCertsDir() == null) ? null
        : IoUtil.expandFilepath(conf0.getCertsDir());
    this.caCert = parseCert(conf0.getCaCertFile());
    this.issuerCert = (conf0.getIssuerCertFile() == null) ? null
        : parseCert(conf0.getIssuerCertFile());
    this.useUpdateDatesFromCrl = conf0.isUseUpdateDatesFromCrl();

    initializeStore(datasource);
    super.init(conf, datasource);
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

  private synchronized void initializeStore(DataSourceWrapper datasource) {
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

      ImportCrl importCrl = new ImportCrl(datasource, useUpdateDatesFromCrl, crl, crlUrl,
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
      LogUtil.error(LOG, th, "could not execute initializeStore()");
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
