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

package org.xipki.ca.mgmt.db.port;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Worker for database export / import.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class DbPortWorker implements Runnable {

  private static final Logger LOG = LoggerFactory.getLogger(DbPortWorker.class);

  protected final AtomicBoolean stopMe = new AtomicBoolean(false);

  protected final DataSourceWrapper datasource;

  private Exception exception;

  public DbPortWorker(DataSourceFactory datasourceFactory, PasswordResolver passwordResolver,
      String dbConfFile)
          throws PasswordResolverException, IOException {
    Properties props = DbPorter.getDbConfProperties(
        Files.newInputStream(Paths.get(IoUtil.expandFilepath(dbConfFile))));
    this.datasource = datasourceFactory.createDataSource("ds-" + dbConfFile, props,
        passwordResolver);
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

  protected abstract void run0()
      throws Exception;

  public static class ImportCaDb extends DbPortWorker {

    private final boolean resume;

    private final String srcFolder;

    private final int batchEntriesPerCommit;

    public ImportCaDb(DataSourceFactory datasourceFactory, PasswordResolver passwordResolver,
        String dbConfFile, boolean resume, String srcFolder, int batchEntriesPerCommit)
        throws PasswordResolverException, IOException {
      super(datasourceFactory, passwordResolver, dbConfFile);
      this.resume = resume;
      this.srcFolder = IoUtil.expandFilepath(srcFolder);
      this.batchEntriesPerCommit = batchEntriesPerCommit;
    }

    @Override
    protected void run0()
        throws Exception {
      File processLogFile = new File(srcFolder, DbPorter.IMPORT_PROCESS_LOG_FILENAME);
      if (resume) {
        if (!processLogFile.exists()) {
          throw new Exception("could not process with '--resume' option");
        }
      } else {
        if (processLogFile.exists()) {
          throw new Exception("please either specify '--resume' option or delete the file "
              + processLogFile.getPath() + " first");
        }
      }

      long start = System.currentTimeMillis();
      try {
        if (!resume) {
          // CAConfiguration
          CaconfDbImporter caConfImporter = new CaconfDbImporter(datasource, srcFolder, stopMe);
          caConfImporter.importToDb();
          caConfImporter.close();
        }

        // CertStore
        CaCertstoreDbImporter certStoreImporter = new CaCertstoreDbImporter(datasource,
            srcFolder, batchEntriesPerCommit, resume, stopMe);
        certStoreImporter.importToDb();
        certStoreImporter.close();
      } finally {
        try {
          datasource.close();
        } catch (Throwable th) {
          LOG.error("datasource.close()", th);
        }
        long end = System.currentTimeMillis();
        System.out.println("Finished in " + StringUtil.formatTime((end - start) / 1000, false));
      }
    } // method run0

  } // class ImportCaDb

  public static class ExportCaDb extends DbPortWorker {

    private final String destFolder;

    private final boolean resume;

    private final int numCertsInBundle;

    private final int numCertsPerSelect;

    public ExportCaDb(DataSourceFactory datasourceFactory, PasswordResolver passwordResolver,
        String dbConfFile, String destFolder, boolean resume, int numCertsInBundle,
        int numCertsPerSelect)
            throws PasswordResolverException, IOException {
      super(datasourceFactory, passwordResolver, dbConfFile);
      this.destFolder = IoUtil.expandFilepath(destFolder);
      this.resume = resume;
      this.numCertsInBundle = numCertsInBundle;
      this.numCertsPerSelect = numCertsPerSelect;
      checkDestFolder();
    }

    private void checkDestFolder()
        throws IOException {
      File file = new File(destFolder);
      if (!file.exists()) {
        file.mkdirs();
      } else {
        if (!file.isDirectory()) {
          throw new IOException(destFolder + " is not a folder");
        }

        if (!file.canWrite()) {
          throw new IOException(destFolder + " is not writable");
        }
      }

      File processLogFile = new File(destFolder, DbPorter.EXPORT_PROCESS_LOG_FILENAME);
      if (resume) {
        if (!processLogFile.exists()) {
          throw new IOException("could not process with '--resume' option");
        }
      } else {
        String[] children = file.list();
        if (children != null && children.length > 0) {
          throw new IOException(destFolder + " is not empty");
        }
      }
    } // method checkDestFolder

    @Override
    protected void run0()
        throws Exception {
      long start = System.currentTimeMillis();
      try {
        if (!resume) {
          // CAConfiguration
          CaconfDbExporter caConfExporter = new CaconfDbExporter(datasource, destFolder, stopMe);
          caConfExporter.export();
          caConfExporter.close();
        }

        // CertStore
        CaCertstoreDbExporter certStoreExporter = new CaCertstoreDbExporter(datasource, destFolder,
            numCertsInBundle, numCertsPerSelect, resume, stopMe);
        certStoreExporter.export();
        certStoreExporter.close();
      } finally {
        try {
          datasource.close();
        } catch (Throwable th) {
          LOG.error("datasource.close()", th);
        }
        long end = System.currentTimeMillis();
        System.out.println("Finished in " + StringUtil.formatTime((end - start) / 1000, false));
      }
    } // method run0

  } // class ExportCaDb

  public static class ExportOcspDb extends DbPortWorker {

    private final String destFolder;

    private final boolean resume;

    private final int numCertsInBundle;

    private final int numCertsPerSelect;

    public ExportOcspDb(DataSourceFactory datasourceFactory, PasswordResolver passwordResolver,
        String dbConfFile, String destFolder, boolean resume, int numCertsInBundle,
        int numCertsPerSelect)
            throws PasswordResolverException, IOException {
      super(datasourceFactory, passwordResolver, dbConfFile);

      this.destFolder = Args.notBlank(destFolder, destFolder);

      File file = new File(destFolder);
      if (!file.exists()) {
        file.mkdirs();
      } else {
        if (!file.isDirectory()) {
          throw new IOException(destFolder + " is not a folder");
        }

        if (!file.canWrite()) {
          throw new IOException(destFolder + " is not writable");
        }
      }

      if (!resume) {
        String[] children = file.list();
        if (children != null && children.length > 0) {
          throw new IOException(destFolder + " is not empty");
        }
      }
      this.resume = resume;
      this.numCertsInBundle = numCertsInBundle;
      this.numCertsPerSelect = numCertsPerSelect;
    } // constructor

    @Override
    protected void run0()
        throws Exception {
      long start = System.currentTimeMillis();
      try {
        // CertStore
        OcspCertstoreDbExporter certStoreExporter = new OcspCertstoreDbExporter(datasource,
            destFolder, numCertsInBundle, numCertsPerSelect, resume, stopMe);
        certStoreExporter.export();
        certStoreExporter.close();
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

  } // class ExportOcspDb

  public static class ImportOcspDb extends DbPortWorker {

    private final boolean resume;

    private final String srcFolder;

    private final int batchEntriesPerCommit;

    public ImportOcspDb(DataSourceFactory datasourceFactory,
        PasswordResolver passwordResolver, String dbConfFile, boolean resume, String srcFolder,
        int batchEntriesPerCommit)
            throws PasswordResolverException, IOException {
      super(datasourceFactory, passwordResolver, dbConfFile);
      this.resume = resume;
      this.srcFolder = IoUtil.expandFilepath(srcFolder);
      this.batchEntriesPerCommit = batchEntriesPerCommit;
    }

    @Override
    protected void run0()
        throws Exception {
      long start = System.currentTimeMillis();
      // CertStore
      try {
        OcspCertstoreDbImporter certStoreImporter = new OcspCertstoreDbImporter(datasource,
            srcFolder, batchEntriesPerCommit, resume, stopMe);
        certStoreImporter.importToDb();
        certStoreImporter.close();
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

  } // class ImportOcspDb

  public static class ImportOcspFromCaDb extends DbPortWorker {

    private final String publisherName;

    private final boolean resume;

    private final String srcFolder;

    private final int batchEntriesPerCommit;

    public ImportOcspFromCaDb(DataSourceFactory datasourceFactory,
        PasswordResolver passwordResolver, String dbConfFile, String publisherName,
        boolean resume, String srcFolder, int batchEntriesPerCommit, boolean evaluateOnly)
        throws PasswordResolverException, IOException {
      super(datasourceFactory, passwordResolver, dbConfFile);
      this.publisherName = publisherName;
      this.resume = resume;
      this.srcFolder = IoUtil.expandFilepath(srcFolder);
      this.batchEntriesPerCommit = batchEntriesPerCommit;
    }

    @Override
    protected void run0()
        throws Exception {
      long start = System.currentTimeMillis();
      // CertStore
      try {
        OcspCertStoreFromCaDbImporter certStoreImporter = new OcspCertStoreFromCaDbImporter(
            datasource, srcFolder, publisherName, batchEntriesPerCommit, resume, stopMe);
        certStoreImporter.importToDb();
        certStoreImporter.close();
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

  } // class ImportOcspFromCaDb

}
