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

package org.xipki.ca.mgmt.db;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.mgmt.db.port.DbPorter;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;
import org.xipki.util.IoUtil;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Worker for database export / import.
 *
 * @author Lijun Liao
 * @since 5.3.15
 */

public abstract class DbWorker implements Runnable {

  private static final Logger LOG = LoggerFactory.getLogger(DbWorker.class);

  protected final AtomicBoolean stopMe = new AtomicBoolean(false);

  protected final DataSourceWrapper datasource;

  private Exception exception;

  public DbWorker(DataSourceFactory datasourceFactory, PasswordResolver passwordResolver, String dbConfFile)
          throws PasswordResolverException, IOException {
    Properties props = DbPorter.getDbConfProperties(Files.newInputStream(Paths.get(IoUtil.expandFilepath(dbConfFile))));
    this.datasource = datasourceFactory.createDataSource("ds-" + dbConfFile, props, passwordResolver);
  }

  public final Exception exception() {
    return exception;
  }

  public void setStopMe(boolean stopMe) {
    this.stopMe.set(stopMe);
  }

  @Override
  public void run() {
    try {
      run0();
    } catch (Exception ex) {
      LOG.error("exception thrown", ex);
      exception = ex;
    }
  } // method run

  protected abstract void run0() throws Exception;

}
