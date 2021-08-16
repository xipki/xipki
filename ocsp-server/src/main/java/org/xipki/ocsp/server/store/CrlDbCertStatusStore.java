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

package org.xipki.ocsp.server.store;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.ocsp.api.OcspStoreException;
import org.xipki.util.IoUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;

import java.io.File;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.xipki.util.Args.notNull;

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

  } // class CrlUpdateService

  private static final Logger LOG = LoggerFactory.getLogger(CrlDbCertStatusStore.class);

  private final CrlUpdateService storeUpdateService = new CrlUpdateService();

  private final Object lock = new Object();

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
  public void init(Map<String, ?> sourceConf, DataSourceWrapper datasource)
      throws OcspStoreException {
    notNull(sourceConf, "sourceConf");

    // check the dir
    this.dir = IoUtil.expandFilepath(getStrValue(sourceConf, "dir", true), true);
    File dirObj = new File(this.dir);
    if (!dirObj.exists()) {
      throw new OcspStoreException("the dir " + this.dir + " does not exist");
    }

    if (!dirObj.isDirectory()) {
      throw new OcspStoreException(this.dir + " is not a directory");
    }

    File[] subDirs = new File(dir).listFiles();
    boolean foundCrlDir = false;
    if (subDirs != null) {
      for (File subDir : subDirs) {
        if (!subDir.isDirectory()) {
          continue;
        }

        String dirName = subDir.getName();
        if (dirName.startsWith("crl-")) {
          foundCrlDir = true;
          break;
        }
      }
    }

    if (!foundCrlDir) {
      LOG.warn("Found no sub-directory starting with 'crl-' in " + dir);
    }

    String value = getStrValue(sourceConf, "sqlBatchCommit", false);
    this.sqlBatchCommit = StringUtil.isBlank(value) ? 1000 : Integer.parseInt(value);

    value = getStrValue(sourceConf, "ignoreExpiredCrls", false);
    this.ignoreExpiredCrls = StringUtil.isBlank(value) || Boolean.parseBoolean(value);

    super.datasource = datasource;
    updateStore(true);
    super.init(sourceConf, datasource);
  } // method init

  private static String getStrValue(Map<String, ?> sourceConf,
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
  } // method getStrValue

  @Override
  protected boolean isIgnoreExpiredCrls() {
    return ignoreExpiredCrls;
  }

  @Override
  protected List<Runnable> getScheduledServices() {
    return Collections.singletonList(storeUpdateService);
  }

  @Override
  protected boolean isInitialized() {
    return crlUpdated && super.isInitialized();
  }

  private void updateStore(boolean firstTime) {
    if (crlUpdateInProcess.get()) {
      return;
    }

    synchronized (lock) {
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
    } // end lock
  } // method updateStore

}
