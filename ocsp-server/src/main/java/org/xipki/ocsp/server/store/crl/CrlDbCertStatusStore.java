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

package org.xipki.ocsp.server.store.crl;

import java.io.File;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.ocsp.api.OcspStoreException;
import org.xipki.ocsp.server.store.DbCertStatusStore;
import org.xipki.util.Args;
import org.xipki.util.IoUtil;
import org.xipki.util.LogUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.2.0
 */

public class CrlDbCertStatusStore extends DbCertStatusStore {

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

  //private X509Certificate caCert;

  //private X509Certificate issuerCert;

  private String dir;

  private boolean crlUpdated;

  /**
   * Initialize the store.
   *
   * @param sourceConf
   * the store source configuration. It contains following key-value pairs:
   * <ul>
   * <li>dir: required
   *   <p/>
   *   Directory of the CRL resources.</li>
   * </ul>
   * @param datasource DataSource.
   */
  public void init(Map<String, ? extends Object> sourceConf, DataSourceWrapper datasource)
      throws OcspStoreException {
    Args.notNull(sourceConf, "sourceConf");

    this.dir = IoUtil.expandFilepath(getStrValue(sourceConf, "dir", true));

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

  private synchronized void updateStore(DataSourceWrapper datasource) {
    if (crlUpdateInProcess.get()) {
      return;
    }

    crlUpdateInProcess.set(true);
    File updateMeFile = null;
    try {
      updateMeFile = new File(dir, "UPDATEME");
      if (!updateMeFile.exists()) {
        LOG.info("The CRL will not be updated. Create new file {} to force the update",
            updateMeFile.getAbsolutePath());
        return;
      }

      ImportCrl importCrl = new ImportCrl(datasource, dir);
      if (importCrl.importCrlToOcspDb()) {
        LOG.info("updated CertStore {} successfully", name);
      } else {
        LOG.error("updating CertStore {} failed", name);
      }
    } catch (Throwable th) {
      LogUtil.error(LOG, th, "error while executing updateStore()");
    } finally {
      crlUpdated = true;
      crlUpdateInProcess.set(false);
      if (updateMeFile != null) {
        updateMeFile.delete();
      }
    }
  } // method initializeStore

}
