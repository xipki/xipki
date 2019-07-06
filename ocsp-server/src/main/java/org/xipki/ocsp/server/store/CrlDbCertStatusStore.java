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
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.ocsp.api.OcspStoreException;
import org.xipki.util.Args;
import org.xipki.util.IoUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;

/**
 * OcspStore for CRLs. Note that the CRLs will be imported to XiPKI OCSP database.
 *
 * @author Lijun Liao
 * @since 2.2.0
 */

public class CrlDbCertStatusStore extends DbCertStatusStore {

  private class CrlUpdateService implements Runnable {

    @Override
    public void run() {
      try {
        updateStore(false);
      } catch (Throwable th) {
        LogUtil.error(LOG, th, "error while calling initializeStore() for store " + name);
      }
    }

  } // StoreUpdateService

  private static final Logger LOG = LoggerFactory.getLogger(CrlDbCertStatusStore.class);

  private final CrlUpdateService storeUpdateService = new CrlUpdateService();

  private final AtomicBoolean crlUpdateInProcess = new AtomicBoolean(false);

  private String dir;

  private int sqlBatchCommit;

  private boolean ignoreExpiredCrls;

  private boolean crlUpdated;

  /**
   * Initialize the store.
   *
   * @param sourceConf
   * the store source configuration. It contains following key-value pairs:
   * <ul>
   * <li>dir: required
   *   <p>
   *   Directory of the CRL resources.</li>
   * <li>sqlBatchCommit:
   *   <p>
   *   Number of SQL queries before next commit, default to be 1000.</li>
   * <li>ignoreExpiredCrls:
   *   <p>
   *   Whether expired CRLs are ignored, default to true.</li>
   * </ul>
   * @param datasource DataSource.
   */
  public void init(Map<String, ? extends Object> sourceConf, DataSourceWrapper datasource)
      throws OcspStoreException {
    Args.notNull(sourceConf, "sourceConf");

    this.dir = IoUtil.expandFilepath(getStrValue(sourceConf, "dir", true));
    String value = getStrValue(sourceConf, "sqlBatchCommit", false);
    this.sqlBatchCommit = StringUtil.isBlank(value) ? 1000 : Integer.parseInt(value);

    value = getStrValue(sourceConf, "ignoreExpiredCrls", false);
    this.ignoreExpiredCrls = StringUtil.isBlank(value) ? true : Boolean.parseBoolean(value);

    super.datasource = datasource;
    updateStore(true);
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
      return objVal.toString();
    }
  }

  @Override
  protected List<Runnable> getScheduledServices() {
    return Arrays.asList(storeUpdateService);
  }

  @Override
  protected boolean isInitialized() {
    return crlUpdated && super.isInitialized();
  }

  private synchronized void updateStore(boolean firstTime) {
    if (crlUpdateInProcess.get()) {
      return;
    }

    crlUpdateInProcess.set(true);
    try {
      File[] subDirs = new File(dir).listFiles();
      boolean updateMe = false;
      if (subDirs != null) {
        for (File subDir : subDirs) {
          if (!subDir.isDirectory()) {
            continue;
          }

          String dirName = subDir.getName();
          if (dirName.startsWith("crl-")) {
            if (new File(subDir, "UPDATEME").exists()) {
              updateMe = true;
              break;
            }
          }
        }
      }

      if (!updateMe) {
        LOG.info("CertStore {} not changed", name);
        return;
      }

      ImportCrl importCrl = new ImportCrl(datasource, dir, sqlBatchCommit, ignoreExpiredCrls);

      if (importCrl.importCrlToOcspDb()) {
        LOG.info("updated CertStore {} successfully", name);
      } else {
        LOG.error("updating CertStore {} failed", name);
      }

      if (!firstTime) {
        super.updateIssuerStore(true);
      }
    } catch (Throwable th) {
      LogUtil.error(LOG, th, "error while executing updateStore()");
    } finally {
      crlUpdated = true;
      crlUpdateInProcess.set(false);
    }
  } // method initializeStore

}
