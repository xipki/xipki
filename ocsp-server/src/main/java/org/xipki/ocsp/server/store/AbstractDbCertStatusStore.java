// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.store;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ocsp.api.OcspStore;
import org.xipki.ocsp.server.IssuerFilter;
import org.xipki.util.datasource.DataAccessException;
import org.xipki.util.datasource.DataSourceWrapper;
import org.xipki.pkix.util.misc.LogUtil;
import org.xipki.pkix.util.misc.RandomUtil;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Common part of the certificate status stores whose data are in a database.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class AbstractDbCertStatusStore extends OcspStore {

  private static final Logger LOG = LoggerFactory.getLogger(AbstractDbCertStatusStore.class);

  protected final Object lock = new Object();

  protected final AtomicBoolean storeUpdateInProcess = new AtomicBoolean(false);

  protected DataSourceWrapper datasource;

  protected String sqlCs;

  protected String sqlCsWithCertHash;

  protected IssuerFilter issuerFilter;

  protected boolean initialized;

  private ScheduledThreadPoolExecutor scheduledThreadPoolExecutor;

  /**
   * Updates the issuers from the database.
   */
  protected abstract void updateIssuerStore();

  /**
   * Returns the services to be executed periodically.
   * @return the services, by default only the update of the issuers.
   */
  protected List<Runnable> scheduledServices() {
    return Collections.singletonList(this::updateIssuerStore);
  }

  /**
   * (Re-)starts the scheduled services, if the update interval is set.
   */
  protected void startScheduledServices() {
    if (this.scheduledThreadPoolExecutor != null) {
      this.scheduledThreadPoolExecutor.shutdownNow();
    }

    if (updateInterval != null) {
      List<Runnable> scheduledServices = scheduledServices();
      int size = scheduledServices == null ? 0 : scheduledServices.size();
      if (size > 0) {
        this.scheduledThreadPoolExecutor = new ScheduledThreadPoolExecutor(size);
        long intervalSeconds = updateInterval.approxMinutes() * 60;
        for (Runnable service : scheduledServices) {
          this.scheduledThreadPoolExecutor.scheduleAtFixedRate(service,
              intervalSeconds + RandomUtil.nextInt(60), intervalSeconds, TimeUnit.SECONDS);
        }
      }
    }
  }

  /**
   * Borrow PreparedStatement.
   * @return the next idle preparedStatement, {@code null} will be returned if
   *         no PreparedStatement can be created within 5 seconds.
   */
  protected PreparedStatement preparedStatement(String sqlQuery) throws DataAccessException {
    return datasource.prepareStatement(sqlQuery);
  }

  protected void releaseDbResources(PreparedStatement ps, ResultSet rs) {
    datasource.releaseResources(ps, rs);
  }

  /**
   * Returns whether the store is initialized and the given SQL query can be executed.
   * @param testSql the SQL query to test the database.
   * @return whether the store is healthy.
   */
  protected boolean isHealthy(String testSql) {
    if (!isInitialized()) {
      return false;
    }

    try {
      PreparedStatement ps = preparedStatement(testSql);
      ResultSet rs = null;
      try {
        rs = ps.executeQuery();
        return true;
      } finally {
        releaseDbResources(ps, rs);
      }
    } catch (Exception ex) {
      LogUtil.error(LOG, ex);
      return false;
    }
  }

  @Override
  public void close() {
    if (scheduledThreadPoolExecutor != null) {
      scheduledThreadPoolExecutor.shutdown();
      scheduledThreadPoolExecutor = null;
    }

    if (datasource != null) {
      datasource.close();
    }
  }

  protected boolean isInitialized() {
    return initialized;
  }

}
