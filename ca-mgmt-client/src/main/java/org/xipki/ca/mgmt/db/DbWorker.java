// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.db;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.mgmt.db.port.DbPorter;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;
import org.xipki.util.ConfigurableProperties;
import org.xipki.util.IoUtil;

import java.io.IOException;
import java.nio.file.Files;
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

  public DbWorker(DataSourceFactory datasourceFactory, PasswordResolver passwordResolver, String dbConfFile)
          throws PasswordResolverException, IOException {
    ConfigurableProperties props =
        DbPorter.getDbConfProperties(Files.newInputStream(Paths.get(IoUtil.expandFilepath(dbConfFile))));
    this.datasource = datasourceFactory.createDataSource("ds-" + dbConfFile, props, passwordResolver);
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
