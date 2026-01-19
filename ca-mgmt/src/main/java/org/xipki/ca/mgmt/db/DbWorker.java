// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.db;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.mgmt.db.port.DbPorter;
import org.xipki.util.conf.ConfigurableProperties;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.datasource.DataSourceFactory;
import org.xipki.util.datasource.DataSourceWrapper;
import org.xipki.util.io.IoUtil;

import java.io.IOException;
import java.nio.file.Paths;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Worker for database export / import.
 *
 * @author Lijun Liao (xipki)
 * @since 5.3.15
 */

public abstract class DbWorker implements Runnable {

  private static final Logger LOG = LoggerFactory.getLogger(DbWorker.class);

  protected final AtomicBoolean stopMe = new AtomicBoolean(false);

  protected final DataSourceWrapper datasource;

  private Exception exception;

  public DbWorker(DataSourceFactory datasourceFactory, String dbConfFile)
          throws InvalidConfException, IOException {
    ConfigurableProperties props = DbPorter.getDbConfProperties(
        Paths.get(IoUtil.expandFilepath(dbConfFile)));

    this.datasource = datasourceFactory.createDataSource(
        "ds-" + dbConfFile, props);
  }

  public final Exception exception() {
    return exception;
  }

  public void setStopMe(boolean stopMe) {
    this.stopMe.set(stopMe);
  }

  protected abstract void close0();

  @Override
  public void run() {
    try {
      run0();
    } catch (Exception ex) {
      LOG.error("exception thrown", ex);
      exception = ex;
    } finally {
      datasource.close();
      close0();
    }
  } // method run

  protected abstract void run0() throws Exception;

}
