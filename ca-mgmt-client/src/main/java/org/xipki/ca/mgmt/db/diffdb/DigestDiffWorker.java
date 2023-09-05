// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.db.diffdb;

import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.mgmt.db.DbWorker;
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
import java.time.Clock;
import java.util.Set;

/**
 * Worker for DigestDiff.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class DigestDiffWorker extends DbWorker {

  private static final Logger LOG = LoggerFactory.getLogger(DigestDiffWorker.class);

  private final boolean revokedOnly;

  private final Set<byte[]> includeCaCerts;

  private final DataSourceWrapper targetDatasource;

  private final String reportDir;

  private final int numCertsPerSelect;

  private final int numThreads;

  public DigestDiffWorker(
      DataSourceFactory datasourceFactory, PasswordResolver passwordResolver,
      boolean revokedOnly, String refDbConfFile, String targetDbConfFile, String reportDirName,
      int numCertsPerSelect, int numThreads, Set<byte[]> includeCaCerts)
          throws PasswordResolverException, IOException, ConfigurationException {
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

    PropertiesConfiguration props = DbPorter.getDbConfProperties(
        Files.newInputStream(Paths.get(IoUtil.expandFilepath(targetDbConfFile))));
    this.targetDatasource = datasourceFactory.createDataSource("ds-" + targetDbConfFile, props, passwordResolver);
  } // constructor

  @Override
  protected void close0() {
    targetDatasource.close();
  }

  @Override
  protected void run0() throws Exception {
    long start = Clock.systemUTC().millis();

    DigestDiff diff = new DigestDiff(datasource, targetDatasource, reportDir, revokedOnly,
        stopMe, numCertsPerSelect, numThreads);
    diff.setIncludeCaCerts(includeCaCerts);
    diff.diff();
    long end = Clock.systemUTC().millis();
    System.out.println("finished in " + StringUtil.formatTime((end - start) / 1000, false));
  } // method run0

}
