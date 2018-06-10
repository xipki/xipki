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

package org.xipki.ca.dbtool.port.ocsp;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.dbtool.port.DbPortWorker;
import org.xipki.ca.dbtool.port.DbPorter;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;
import org.xipki.util.IoUtil;
import org.xipki.util.ParamUtil;
import org.xipki.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class OcspDbImportWorker extends DbPortWorker {

  private static final Logger LOG = LoggerFactory.getLogger(OcspDbImportWorker.class);

  private final DataSourceWrapper datasource;

  private final boolean resume;

  private final String srcFolder;

  private final int batchEntriesPerCommit;

  public OcspDbImportWorker(DataSourceFactory datasourceFactory, PasswordResolver passwordResolver,
      String dbConfFile, boolean resume, String srcFolder, int batchEntriesPerCommit)
          throws PasswordResolverException, IOException {
    ParamUtil.requireNonNull("datasourceFactory", datasourceFactory);
    ParamUtil.requireNonNull("dbConfFile", dbConfFile);

    Properties props = DbPorter.getDbConfProperties(
        new FileInputStream(IoUtil.expandFilepath(dbConfFile)));
    this.datasource = datasourceFactory.createDataSource("ds-" + dbConfFile, props,
        passwordResolver);
    this.resume = resume;
    this.srcFolder = IoUtil.expandFilepath(srcFolder);
    this.batchEntriesPerCommit = batchEntriesPerCommit;
  }

  @Override
  protected void run0() throws Exception {
    long start = System.currentTimeMillis();
    // CertStore
    try {
      OcspCertstoreDbImporter certStoreImporter = new OcspCertstoreDbImporter(datasource,
          srcFolder, batchEntriesPerCommit, resume, stopMe);
      certStoreImporter.importToDb();
      certStoreImporter.shutdown();
    } finally {
      try {
        datasource.close();
      } catch (Throwable th) {
        LOG.error("datasource.close()", th);
      }
      long end = System.currentTimeMillis();
      System.out.println("finished in " + StringUtil.formatTime((end - start) / 1000, false));
    }
  }

}
