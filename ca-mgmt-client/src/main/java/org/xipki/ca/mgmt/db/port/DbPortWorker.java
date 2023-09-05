// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.db.port;

import net.lingala.zip4j.ZipFile;
import net.lingala.zip4j.model.ExcludeFileFilter;
import net.lingala.zip4j.model.FileHeader;
import net.lingala.zip4j.model.ZipParameters;
import net.lingala.zip4j.model.enums.AesKeyStrength;
import net.lingala.zip4j.model.enums.EncryptionMethod;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.mgmt.db.DbWorker;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;
import org.xipki.util.Args;
import org.xipki.util.FileUtils;
import org.xipki.util.IoUtil;
import org.xipki.util.StringUtil;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Clock;
import java.util.LinkedList;
import java.util.List;

/**
 * Worker for database export / import.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public abstract class DbPortWorker extends DbWorker {

  private static final Logger LOG = LoggerFactory.getLogger(DbPortWorker.class);

  protected char[] password;

  public DbPortWorker(DataSourceFactory datasourceFactory, PasswordResolver passwordResolver,
                      String dbConfFile, char[] password)
          throws PasswordResolverException, IOException, ConfigurationException {
    super(datasourceFactory, passwordResolver, dbConfFile);
    this.password = password;
  }

  private static ZipParameters getZipParameters() {
    ExcludeFileFilter excludeFileFilter = file -> file.isDirectory() && file.getName().equals("encrypted");

    ZipParameters zipParameters = new ZipParameters();
    zipParameters.setEncryptFiles(true);
    zipParameters.setIncludeRootFolder(false);
    zipParameters.setEncryptionMethod(EncryptionMethod.AES);
    zipParameters.setAesKeyStrength(AesKeyStrength.KEY_STRENGTH_256);
    zipParameters.setExcludeFileFilter(excludeFileFilter);
    return zipParameters;
  }

  protected void encrypt(File dir) throws IOException {
    File zipDir = new File(dir, "encrypted");
    // delete all contents
    if (zipDir.exists()) {
      FileUtils.deleteDirectory(zipDir);
    }
    zipDir.mkdirs();

    try (ZipFile zipFile = new ZipFile(new File(zipDir, "main.zip"), password)) {
      // split length: 64M Byte
      zipFile.createSplitZipFileFromFolder(dir, getZipParameters(), true, 64L * 1024 * 1024);
    }

    deleteDecryptedFiles(dir.getPath());
  }

  protected void decrypt(String dir) throws IOException {
    File mainFile = new File(dir, "encrypted/main.zip");
    try (ZipFile zipFile = new ZipFile(mainFile, password)) {
      boolean alreadyUnzipped = false;
      for (FileHeader fh : zipFile.getFileHeaders()) {
        if (fh.isDirectory()) {
          continue;
        }

        alreadyUnzipped = new File(dir, fh.getFileName()).exists();
        break;
      }

      if (!alreadyUnzipped) {
        zipFile.extractAll(dir);
      }
    }
  }

  protected void deleteDecryptedFiles(String dir) throws IOException {
    File[] files = new File(dir).listFiles();
    if (files == null) {
      return;
    }

    File mainFile = new File(dir, "encrypted");
    if (!mainFile.exists()) {
      return;
    }

    for (File f : files) {
      // delete all files and sub-dirs except 'encrypted'.
      if (f.getName().equals("encrypted")) {
        continue;
      }

      List<File> failedList = new LinkedList<>();
      BasicFileAttributes basicFileAttributes = Files.readAttributes(f.toPath(), BasicFileAttributes.class);
      if (basicFileAttributes.isRegularFile()) {
        if (!IoUtil.deleteFile(f)) {
          failedList.add(f);
        }
      } else if (basicFileAttributes.isDirectory()) {
        if (!IoUtil.deleteDir(f)) {
          failedList.add(f);
        }
      }

      if (!failedList.isEmpty()) {
        LOG.error("error deleting files & folders: {}", failedList);
      }
    }
  }

  public static class ImportCaDb extends DbPortWorker {

    private final boolean resume;

    private final String srcFolder;

    private final int batchEntriesPerCommit;

    private DataSourceWrapper caDataSource;

    public ImportCaDb(DataSourceFactory datasourceFactory, PasswordResolver passwordResolver,
                      String caConfDbFile, String caDbFile,
                      boolean resume, String srcFolder, int batchEntriesPerCommit, char[] password)
            throws PasswordResolverException, IOException, ConfigurationException {
      super(datasourceFactory, passwordResolver, (caConfDbFile == null ? caDbFile : caConfDbFile), password);
      this.resume = resume;
      this.srcFolder = IoUtil.expandFilepath(srcFolder);
      this.batchEntriesPerCommit = batchEntriesPerCommit;

      PropertiesConfiguration props = DbPorter.getDbConfProperties(Files.newInputStream(
                            Paths.get(IoUtil.expandFilepath(caDbFile))));
      this.caDataSource = datasourceFactory.createDataSource("ds-" + caDbFile,
                            props, passwordResolver);
    }

    @Override
    protected void close0() {
      caDataSource.close();
    }

    @Override
    protected void run0() throws Exception {
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

      long start = Clock.systemUTC().millis();
      try {
        if (password != null) {
          decrypt(srcFolder);
        }

        CaconfDbImporter caConfImporter = new CaconfDbImporter(datasource, srcFolder, stopMe);
        if (!resume) {
          // CAConfiguration
          caConfImporter.importToDb();
          caConfImporter.close();
        }

        CaCertstore.Caconf caconf = caConfImporter.getCaConf();

        // CertStore
        CaCertstoreDbImporter certStoreImporter = new CaCertstoreDbImporter(caDataSource,
                srcFolder, batchEntriesPerCommit, resume, stopMe, caconf);
        certStoreImporter.importToDb();
        certStoreImporter.close();
      } finally {
        try {
          datasource.close();
        } catch (Throwable th) {
          LOG.error("datasource.close()", th);
        }

        try {
          caDataSource.close();
        } catch (Throwable th) {
          LOG.error("certStoreDataSource.close()", th);
        }
        deleteDecryptedFiles(srcFolder);
        printFinishedIn(start);
      }
    } // method run0

  } // class ImportCaDb

  public static class ExportCaDb extends DbPortWorker {

    private final String destFolder;

    private final boolean resume;

    private final int numCertsInBundle;

    private final int numCertsPerSelect;

    private final DataSourceWrapper caDataSource;

    public ExportCaDb(
        DataSourceFactory datasourceFactory, PasswordResolver passwordResolver, String caConfDbFile, String caDbFile,
        String destFolder, boolean resume, int numCertsInBundle, int numCertsPerSelect, char[] password)
            throws PasswordResolverException, IOException, ConfigurationException {
      super(datasourceFactory, passwordResolver, caConfDbFile != null ? caConfDbFile : caDbFile, password);
      this.destFolder = IoUtil.expandFilepath(destFolder);
      this.resume = resume;
      this.numCertsInBundle = numCertsInBundle;
      this.numCertsPerSelect = numCertsPerSelect;
      checkDestFolder();

      PropertiesConfiguration props = DbPorter.getDbConfProperties(Files.newInputStream(
          Paths.get(IoUtil.expandFilepath(caDbFile))));
      this.caDataSource = datasourceFactory.createDataSource("ds-" + caDbFile,
          props, passwordResolver);
    }

    @Override
    protected void close0() {
      caDataSource.close();
    }

    private void checkDestFolder() throws IOException {
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
    protected void run0() throws Exception {
      long start = Clock.systemUTC().millis();
      try {
        if (!resume) {
          // CAConfiguration
          CaconfDbExporter caConfExporter = new CaconfDbExporter(datasource, destFolder, stopMe);
          caConfExporter.export();
          caConfExporter.close();
        }

        // CertStore
        CaCertstoreDbExporter certStoreExporter = new CaCertstoreDbExporter(caDataSource, destFolder,
            numCertsInBundle, numCertsPerSelect, resume, stopMe);
        certStoreExporter.export();
        certStoreExporter.close();

        if (password != null) {
          encrypt(new File(destFolder));
        }
      } finally {
        try {
          datasource.close();
        } catch (Throwable th) {
          LOG.error("datasource.close()", th);
        }
        printFinishedIn(start);
      }
    } // method run0

  } // class ExportCaDb

  public static class ExportOcspDb extends DbPortWorker {

    private final String destFolder;

    private final boolean resume;

    private final int numCertsInBundle;

    private final int numCertsPerSelect;

    public ExportOcspDb(
        DataSourceFactory datasourceFactory, PasswordResolver passwordResolver, String dbConfFile,
        String destFolder, boolean resume, int numCertsInBundle, int numCertsPerSelect, char[] password)
            throws PasswordResolverException, IOException, ConfigurationException {
      super(datasourceFactory, passwordResolver, dbConfFile, password);

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
    protected void close0() {
    }

    @Override
    protected void run0() throws Exception {
      long start = Clock.systemUTC().millis();
      try {
        // CertStore
        OcspCertstoreDbExporter certStoreExporter = new OcspCertstoreDbExporter(datasource,
            destFolder, numCertsInBundle, numCertsPerSelect, resume, stopMe);
        certStoreExporter.export();
        certStoreExporter.close();

        if (password != null) {
          encrypt(new File(destFolder));
        }
      } finally {
        try {
          datasource.close();
        } catch (Throwable th) {
          LOG.error("datasource.close()", th);
        }
        printFinishedIn(start);
      }
    }

  } // class ExportOcspDb

  public static class ImportOcspDb extends DbPortWorker {

    private final boolean resume;

    private final String srcFolder;

    private final int batchEntriesPerCommit;

    public ImportOcspDb(
        DataSourceFactory datasourceFactory, PasswordResolver passwordResolver, String dbConfFile,
        boolean resume, String srcFolder, int batchEntriesPerCommit, char[] password)
            throws PasswordResolverException, IOException, ConfigurationException {
      super(datasourceFactory, passwordResolver, dbConfFile, password);
      this.resume = resume;
      this.srcFolder = IoUtil.expandFilepath(srcFolder);
      this.batchEntriesPerCommit = batchEntriesPerCommit;
    }

    @Override
    protected void close0() {
    }

    @Override
    protected void run0() throws Exception {
      long start = Clock.systemUTC().millis();
      if (password != null) {
        decrypt(srcFolder);
      }

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
        deleteDecryptedFiles(srcFolder);
        printFinishedIn(start);
      }
    }

  } // class ImportOcspDb

  public static class ImportOcspFromCaDb extends DbPortWorker {

    private final String publisherName;

    private final boolean resume;

    private final String srcFolder;

    private final int batchEntriesPerCommit;

    public ImportOcspFromCaDb(
        DataSourceFactory datasourceFactory, PasswordResolver passwordResolver, String dbConfFile,
        String publisherName, boolean resume, String srcFolder, int batchEntriesPerCommit, char[] password)
            throws PasswordResolverException, IOException, ConfigurationException {
      super(datasourceFactory, passwordResolver, dbConfFile, password);
      this.publisherName = publisherName;
      this.resume = resume;
      this.srcFolder = IoUtil.expandFilepath(srcFolder);
      this.batchEntriesPerCommit = batchEntriesPerCommit;
    }

    @Override
    protected void close0() {
    }

    @Override
    protected void run0() throws Exception {
      long start = Clock.systemUTC().millis();
      if (password != null) {
        decrypt(srcFolder);
      }

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

        deleteDecryptedFiles(srcFolder);
        printFinishedIn(start);
      }
    }

  } // class ImportOcspFromCaDb

  private static void printFinishedIn(long startMs) {
    long duration = (Clock.systemUTC().millis() - startMs) / 1000;
    System.out.println("Finished in " + StringUtil.formatTime(duration, false));
  }

}
