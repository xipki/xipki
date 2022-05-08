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

package org.xipki.ca.mgmt.db.diffdb;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.mgmt.db.port.DbPortWorker;
import org.xipki.ca.mgmt.db.port.DbPorter;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;
import org.xipki.util.Args;
import org.xipki.util.IoUtil;
import org.xipki.util.StringUtil;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Properties;
import java.util.Set;

/**
 * Worker for DigestDiff.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class DigestDiffWorker extends DbPortWorker {

  private static final Logger LOG = LoggerFactory.getLogger(DigestDiffWorker.class);

  private final boolean revokedOnly;

  private final Set<byte[]> includeCaCerts;

  private final DataSourceWrapper targetDatasource;

  private final String reportDir;

  private final int numCertsPerSelect;

  private final int numThreads;

  public DigestDiffWorker(DataSourceFactory datasourceFactory, PasswordResolver passwordResolver,
      boolean revokedOnly, String refDbConfFile, String targetDbConfFile, String reportDirName,
      int numCertsPerSelect, int numThreads, Set<byte[]> includeCaCerts)
      throws PasswordResolverException, IOException {
    super(datasourceFactory, passwordResolver, refDbConfFile);
    this.reportDir = reportDirName;
    this.numThreads = Args.positive(numThreads, "numThreads");
    this.numCertsPerSelect = numCertsPerSelect;
    this.includeCaCerts = includeCaCerts;
    this.revokedOnly = revokedOnly;

    File file = new File(reportDirName);
    if (!file.exists()) {
      file.mkdirs();
    } else {
      if (!file.isDirectory()) {
        throw new IOException(reportDirName + " is not a folder");
      }

      if (!file.canWrite()) {
        throw new IOException(reportDirName + " is not writable");
      }
    }

    String[] children = file.list();
    if (children != null && children.length > 0) {
      throw new IOException(reportDirName + " is not empty");
    }

    Properties props = DbPorter.getDbConfProperties(
        Files.newInputStream(Paths.get(IoUtil.expandFilepath(targetDbConfFile))));
    this.targetDatasource = datasourceFactory.createDataSource(
        "ds-" + targetDbConfFile, props, passwordResolver);
  } // constructor

  @Override
  protected void run0()
      throws Exception {
    long start = System.currentTimeMillis();

    try {
      DigestDiff diff = new DigestDiff(datasource, targetDatasource, reportDir, revokedOnly,
          stopMe, numCertsPerSelect, numThreads);
      diff.setIncludeCaCerts(includeCaCerts);
      diff.diff();
    } finally {
      try {
        datasource.close();
      } catch (Throwable th) {
        LOG.error("refDatasource.close()", th);
      }

      try {
        targetDatasource.close();
      } catch (Throwable th) {
        LOG.error("datasource.close()", th);
      }
      long end = System.currentTimeMillis();
      System.out.println("finished in " + StringUtil.formatTime((end - start) / 1000, false));
    }
  } // method run0

}
