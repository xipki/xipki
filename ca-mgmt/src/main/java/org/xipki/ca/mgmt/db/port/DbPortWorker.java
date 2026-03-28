// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.db.port;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.mgmt.db.DbWorker;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.cbor.ByteArrayCborDecoder;
import org.xipki.util.codec.cbor.ByteArrayCborEncoder;
import org.xipki.util.codec.cbor.CborDecoder;
import org.xipki.util.conf.ConfigurableProperties;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.datasource.DataSourceFactory;
import org.xipki.util.datasource.DataSourceWrapper;
import org.xipki.util.io.IoUtil;
import org.xipki.util.misc.StringUtil;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.time.Clock;
import java.util.Arrays;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * DB Port Worker.
 *
 * @author Lijun Liao (xipki)
 */

public abstract class DbPortWorker extends DbWorker {

  private static final Logger LOG = LoggerFactory.getLogger(DbPortWorker.class);

  private static final int algSuite_pbkdf2_cbc256_hmacsha256 = 1;

  private static final SecureRandom rnd = new SecureRandom();

  protected char[] password;

  public DbPortWorker(DataSourceFactory datasourceFactory, String dbConfFile, char[] password)
      throws InvalidConfException, IOException {
    super(datasourceFactory, dbConfFile);
    this.password = Args.notNull(password, "password");
  }

  protected void encrypt(File dir) throws IOException, GeneralSecurityException, CodecException {
    File zipFile = buildZipFile(dir);
    zipFolder(dir.toPath(), zipFile.toPath());

    int macValueLen = 32;

    byte[] salt = new byte[20];
    rnd.nextBytes(salt);
    byte[] aesNonce = new byte[16];
    rnd.nextBytes(aesNonce);

    final int algSuite = algSuite_pbkdf2_cbc256_hmacsha256;
    byte[] metaData;
    try (ByteArrayCborEncoder cborEncoder = new ByteArrayCborEncoder()) {
      cborEncoder.writeArrayStart(5);
      cborEncoder.writeInt(1); // syntax version
      cborEncoder.writeInt(algSuite);
      cborEncoder.writeByteString(salt);
      cborEncoder.writeByteString(aesNonce);
      // reserved for the MAC value
      cborEncoder.writeByteString(new byte[macValueLen]);
      metaData = cborEncoder.toByteArray();

      if (metaData.length > 0xFFFF) {
        throw new IOException("metaData too long");
      }
    }

    CipherSuite cipherSuite = initCipherSuite(true, algSuite, password, salt, aesNonce);

    File encZipFile = new File(zipFile.getPath() + ".enc");
    byte[] macValue;

    try (InputStream is = new FileInputStream(zipFile);
        OutputStream encOs = new FileOutputStream(encZipFile)) {
      int metaDataLen = metaData.length;
      encOs.write((byte) (metaDataLen >> 8));
      encOs.write((byte) metaDataLen);
      encOs.write(metaData);

      byte[] inBuf = new byte[4096];
      int readLen;
      while ((readLen = is.read(inBuf)) != -1) {
        if (readLen == 0) {
          continue;
        }

        byte[] encBuf = cipherSuite.cipher.update(inBuf, 0, readLen);
        if (encBuf != null && encBuf.length > 0) {
          cipherSuite.mac.update(encBuf);
          encOs.write(encBuf);
        }
      }

      byte[] encBuf = cipherSuite.cipher.doFinal();
      if (encBuf != null && encBuf.length > 0) {
        cipherSuite.mac.update(encBuf);
        encOs.write(encBuf);
      }

      macValue = cipherSuite.mac.doFinal();
    }

    // overwrite the macValue
    int offset = 2 + metaData.length - macValueLen;
    try (RandomAccessFile file = new RandomAccessFile(encZipFile, "rw")) {
      // Move the file pointer to the specific position
      file.seek(offset);

      // Write the new data (this overwrites existing bytes)
      file.write(macValue);
    }

    IoUtil.deleteDir(dir);
    IoUtil.deleteFile(zipFile);
  }

  protected void decrypt(String dirName)
      throws IOException, CodecException, GeneralSecurityException {
    File dir = new File(dirName);
    File zipFile = buildZipFile(dir);
    File encZipFile = new File(zipFile.getPath() + ".enc");
    if (!encZipFile.exists()) {
      throw new IOException("found no encrypted ZIP file " + zipFile.getPath());
    }

    CipherSuite cipherSuite;
    int cipherTextOffset;

    try (InputStream encIs = new FileInputStream(encZipFile)) {
      // read the length of meta-data
      byte[] metaDataLenBytes = IoUtil.readExactBytes(encIs, 2);
      int metaDataLen = ((metaDataLenBytes[0] & 0xFF) << 8) + (metaDataLenBytes[1] & 0xFF);
      byte[] metaData = IoUtil.readExactBytes(encIs, metaDataLen);
      cipherTextOffset = 2 + metaDataLen;

      int algSuite;
      byte[] kdfSalt;
      byte[] symNonce;
      byte[] macValue;

      try (CborDecoder cborDecoder = new ByteArrayCborDecoder(metaData)) {
        int arrayLen = cborDecoder.readArrayLength();
        int version = cborDecoder.readInt();
        if (version != 1) {
          throw new CodecException("invalid version " + version);
        }

        if (arrayLen != 5) {
          throw new CodecException("invalid Cbor array length " + arrayLen);
        }

        algSuite = cborDecoder.readInt();
        kdfSalt  = cborDecoder.readByteString();
        symNonce = cborDecoder.readByteString();
        macValue = cborDecoder.readByteString();

        if (algSuite != algSuite_pbkdf2_cbc256_hmacsha256) {
          throw new CodecException("invalid algorithm suite " + algSuite);
        }
      }

      if (macValue.length != 32) {
        throw new SignatureException("MAC value invalid");
      }

      cipherSuite = initCipherSuite(false, algSuite, password, kdfSalt, symNonce);

      // first check the mac
      byte[] inBuf = new byte[4096];
      int readLen;
      while ((readLen = encIs.read(inBuf)) != -1) {
        if (readLen == 0) {
          continue;
        }

        cipherSuite.mac.update(inBuf, 0, readLen);
      }

      byte[] computedMacValue = cipherSuite.mac.doFinal();
      if (!Arrays.equals(macValue, computedMacValue)) {
        throw new SignatureException("MAC value is not valid");
      }
    }

    // now do the decrypt
    try (InputStream encIs = new FileInputStream(encZipFile);
        OutputStream zipOs = new FileOutputStream(zipFile)) {
      IoUtil.readExactBytes(encIs, cipherTextOffset); // skip mata data
      byte[] inBuf = new byte[4096];
      int readLen;
      while ((readLen = encIs.read(inBuf)) != -1) {
        if (readLen == 0) {
          continue;
        }

        byte[] encBuf = cipherSuite.cipher.update(inBuf, 0, readLen);
        if (encBuf != null && encBuf.length > 0) {
          zipOs.write(encBuf);
        }
      }

      byte[] encBuf = cipherSuite.cipher.doFinal();
      if (encBuf != null && encBuf.length > 0) {
        zipOs.write(encBuf);
      }
    }

    unzip(zipFile.toPath(), dir.toPath());
    IoUtil.deleteFile(zipFile);
  }

  private static CipherSuite initCipherSuite(
      boolean encrypt, int algSuite, char[] password, byte[] salt, byte[] aesNonce)
      throws GeneralSecurityException {
    if (algSuite != algSuite_pbkdf2_cbc256_hmacsha256) {
      throw new NoSuchAlgorithmException("unsupported algSuite " + algSuite);
    }

    String kdfAlg = "PBKDF2WithHmacSHA256";
    int iteration = 1_000_000;

    SecretKeyFactory factory = SecretKeyFactory.getInstance(kdfAlg, KeyUtil.providerName(kdfAlg));

    PBEKeySpec spec = new PBEKeySpec(password, salt, iteration, 256 + 256);
    byte[] compositeKey = factory.generateSecret(spec).getEncoded();
    SecretKey aesKey = new SecretKeySpec(Arrays.copyOfRange(compositeKey, 0, 32), "AES");
    SecretKey macKey = new SecretKeySpec(Arrays.copyOfRange(compositeKey, 32, 64), "HMAC");

    // We do NOT use AEAD algorithm e.g. GCM and CCM due to the fact that
    // in the decrypt process, some provides will buffer all data till the last
    // block and then begin the decryption

    String macAlg = "HMAC-SHA256"; // 32-bit key
    // first check the mac
    Mac mac = Mac.getInstance(macAlg, KeyUtil.providerName(macAlg));
    mac.init(macKey);

    String symEncAlg = "AES/CBC/PKCS5Padding"; // 256-bit key
    Cipher cipher = Cipher.getInstance(symEncAlg, KeyUtil.providerName(symEncAlg));
    cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
        aesKey, new IvParameterSpec(aesNonce));

    return new CipherSuite(cipher, mac);
  }

  private static File buildZipFile(File dir) {
    if (dir.getParentFile() == null) {
      return new File(dir.getName() + ".zip");
    } else {
      return new File(dir.getParentFile(), dir.getName() + ".zip");
    }
  }

  private static void zipFolder(Path sourceFolderPath, Path zipPath) throws IOException {
    try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(zipPath))) {
      Files.walkFileTree(sourceFolderPath, new SimpleFileVisitor<>() {
        @Override
        public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
          // Create a relative path for the zip entry name
          String entryName = sourceFolderPath.relativize(file).toString();

          // Standardize slashes for ZIP format (use forward slashes)
          entryName = entryName.replace("\\", "/");

          zos.putNextEntry(new ZipEntry(entryName));
          Files.copy(file, zos);
          zos.closeEntry();
          return FileVisitResult.CONTINUE;
        }

        @Override
        public FileVisitResult visitFileFailed(Path file, IOException exc) {
          System.err.println("Could not read file: " + file);
          return FileVisitResult.TERMINATE;
        }
      });
    }
  }

  private static void unzip(Path zipFile, Path targetDir) throws IOException {
    // 1. Create target directory if it doesn't exist
    if (Files.notExists(targetDir)) {
      Files.createDirectories(targetDir);
    }

    try (ZipInputStream zis = new ZipInputStream(Files.newInputStream(zipFile))) {
      ZipEntry entry;
      while ((entry = zis.getNextEntry()) != null) {
        // 2. Resolve the path and protect against "Zip Slip" attacks
        Path newPath = targetDir.resolve(entry.getName()).normalize();
        if (!newPath.startsWith(targetDir)) {
          throw new IOException("Entry is outside of the target dir: " + entry.getName());
        }

        if (entry.isDirectory()) {
          Files.createDirectories(newPath);
        } else {
          // 3. Ensure parent directories exist
          // (some zips don't have explicit dir entries)
          if (newPath.getParent() != null && Files.notExists(newPath.getParent())) {
            Files.createDirectories(newPath.getParent());
          }

          // 4. Write the file content
          Files.copy(zis, newPath, StandardCopyOption.REPLACE_EXISTING);
        }
        zis.closeEntry();
      }
    }
  }

  private static class CipherSuite {

    private final Cipher cipher;

    private final Mac mac;

    public CipherSuite(Cipher cipher, Mac mac) {
      this.cipher = cipher;
      this.mac = mac;
    }

  }

  /**
   * Import CA DB.
   *
   * @author Lijun Liao (xipki)
   */
  public static class ImportCaDb extends DbPortWorker {

    private final boolean resume;

    private final String srcFolder;

    private final int batchEntriesPerCommit;

    private final DataSourceWrapper caDataSource;

    public ImportCaDb(DataSourceFactory datasourceFactory, String caConfDbFile, String caDbFile,
                      boolean resume, String srcFolder, int batchEntriesPerCommit, char[] password)
        throws InvalidConfException, IOException {
      super(datasourceFactory, caConfDbFile, password);
      this.resume = resume;
      this.srcFolder = IoUtil.expandFilepath(srcFolder);
      this.batchEntriesPerCommit = batchEntriesPerCommit;

      ConfigurableProperties props = DbPorter.getDbConfProperties(
                            Paths.get(IoUtil.expandFilepath(caDbFile)));
      this.caDataSource = datasourceFactory.createDataSource("ds-" + caDbFile, props);
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
          throw new Exception("please either specify '--resume' option or delete the file " +
              processLogFile.getPath() + " first");
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

        // CertStore
        CaCertstoreDbImporter certStoreImporter = new CaCertstoreDbImporter(
            caDataSource, srcFolder, batchEntriesPerCommit, resume, stopMe);
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
        IoUtil.deleteDir(new File(srcFolder));
        printFinishedIn(start);
      }
    } // method run0

  } // class ImportCaDb

  /**
   * Import CA Cert Store DB.
   *
   * @author Lijun Liao (xipki)
   */
  public static class ImportCaCertStoreDb extends DbPortWorker {

    private final boolean resume;

    private final String srcFolder;

    private final int batchEntriesPerCommit;

    public ImportCaCertStoreDb(
        DataSourceFactory datasourceFactory, String caCerStoreDbFile,
        boolean resume, String srcFolder, int batchEntriesPerCommit, char[] password)
        throws InvalidConfException, IOException {
      super(datasourceFactory, caCerStoreDbFile, password);
      this.resume = resume;
      this.srcFolder = IoUtil.expandFilepath(srcFolder);
      this.batchEntriesPerCommit = batchEntriesPerCommit;
    }

    @Override
    protected void close0() {
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
          throw new Exception("please either specify '--resume' option or delete the " +
              "file " + processLogFile.getPath() + " first");
        }
      }

      long start = Clock.systemUTC().millis();
      try {
        if (password != null) {
          decrypt(srcFolder);
        }

        // CertStore
        CaCertstoreDbImporter certStoreImporter = new CaCertstoreDbImporter(
            datasource, srcFolder, batchEntriesPerCommit, resume, stopMe);
        certStoreImporter.importToDb();
        certStoreImporter.close();
      } finally {
        try {
          datasource.close();
        } catch (Throwable th) {
          LOG.error("datasource.close()", th);
        }

        IoUtil.deleteDir(new File(srcFolder));
        printFinishedIn(start);
      }
    } // method run0

  } // class ImportCaCertStoreDb

  /**
   * Export CA DB.
   *
   * @author Lijun Liao (xipki)
   */
  public static class ExportCaDb extends ExportCaCertStoreDb {

    private final DataSourceWrapper caConfSource;

    public ExportCaDb(
        DataSourceFactory datasourceFactory, String caConfDbFile,
        String caDbFile, String destFolder, boolean resume,
        int numCertsInBundle, int numCertsPerSelect, char[] password)
        throws InvalidConfException, IOException {
      super(datasourceFactory, caDbFile, destFolder,
          resume, numCertsInBundle, numCertsPerSelect, password);
      checkDestFolder();

      if (caConfDbFile != null) {
        ConfigurableProperties props = DbPorter.getDbConfProperties(
            Paths.get(IoUtil.expandFilepath(caConfDbFile)));
        this.caConfSource = datasourceFactory.createDataSource("ds-" + caConfDbFile, props);
      } else {
        this.caConfSource = super.datasource;
      }
    }

    @Override
    protected void close0() {
      if (caConfSource != super.datasource) {
        caConfSource.close();
      }
    }

    @Override
    protected void run0() throws Exception {
      long start = Clock.systemUTC().millis();
      try {
        if (!resume) {
          // CAConfiguration
          CaconfDbExporter caConfExporter = new CaconfDbExporter(caConfSource, destFolder, stopMe);
          caConfExporter.export();
          caConfExporter.close();
        }

        // CertStore
        CaCertstoreDbExporter certStoreExporter = new CaCertstoreDbExporter(
            datasource, destFolder, numCertsInBundle, numCertsPerSelect, resume, stopMe);
        certStoreExporter.export();
        certStoreExporter.close();

        if (password != null) {
          encrypt(new File(destFolder));
        }
      } finally {
        try {
          caConfSource.close();
        } catch (Throwable th) {
          LOG.error("caConfSource.close()", th);
        }

        try {
          datasource.close();
        } catch (Throwable th) {
          LOG.error("datasource.close()", th);
        }
        printFinishedIn(start);
      }
    } // method run0

  } // class ExportCaDb

  /**
   * Export CA Cert Store DB.
   *
   * @author Lijun Liao (xipki)
   */
  public static class ExportCaCertStoreDb extends DbPortWorker {

    protected final String destFolder;

    protected final boolean resume;

    protected final int numCertsInBundle;

    protected final int numCertsPerSelect;

    public ExportCaCertStoreDb(
        DataSourceFactory datasourceFactory, String caDbFile, String destFolder,
        boolean resume, int numCertsInBundle, int numCertsPerSelect, char[] password)
        throws InvalidConfException, IOException {
      super(datasourceFactory, caDbFile, password);
      this.destFolder = IoUtil.expandFilepath(destFolder);
      this.resume = resume;
      this.numCertsInBundle = numCertsInBundle;
      this.numCertsPerSelect = numCertsPerSelect;
      checkDestFolder();
    }

    @Override
    protected void close0() {
    }

    protected void checkDestFolder() throws IOException {
      File file = new File(destFolder);
      if (!file.exists()) {
        IoUtil.mkdirs(file);
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
        // CertStore
        CaCertstoreDbExporter certStoreExporter = new CaCertstoreDbExporter(
            datasource, destFolder, numCertsInBundle, numCertsPerSelect, resume, stopMe);
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

  } // class ExportCaCertStoreDb

  /**
   * Export OCSP DB.
   *
   * @author Lijun Liao (xipki)
   */
  public static class ExportOcspDb extends DbPortWorker {

    private final String destFolder;

    private final boolean resume;

    private final int numCertsInBundle;

    private final int numCertsPerSelect;

    public ExportOcspDb(
        DataSourceFactory datasourceFactory, String dbConfFile, String destFolder,
        boolean resume, int numCertsInBundle, int numCertsPerSelect, char[] password)
        throws InvalidConfException, IOException {
      super(datasourceFactory, dbConfFile, password);

      this.destFolder = Args.notBlank(destFolder, destFolder);

      File file = new File(destFolder);
      if (!file.exists()) {
        IoUtil.mkdirs(file);
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
        OcspCertstoreDbExporter certStoreExporter = new OcspCertstoreDbExporter(
            datasource, destFolder, numCertsInBundle, numCertsPerSelect, resume, stopMe);
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

  /**
   * Import OCSP DB.
   *
   * @author Lijun Liao (xipki)
   */
  public static class ImportOcspDb extends DbPortWorker {

    private final boolean resume;

    private final String srcFolder;

    private final int batchEntriesPerCommit;

    public ImportOcspDb(
        DataSourceFactory datasourceFactory, String dbConfFile, boolean resume,
        String srcFolder, int batchEntriesPerCommit, char[] password)
        throws InvalidConfException, IOException {
      super(datasourceFactory, dbConfFile, password);
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
        OcspCertstoreDbImporter certStoreImporter = new OcspCertstoreDbImporter(
            datasource, srcFolder, batchEntriesPerCommit, resume, stopMe);
        certStoreImporter.importToDb();
        certStoreImporter.close();
      } finally {
        try {
          datasource.close();
        } catch (Throwable th) {
          LOG.error("datasource.close()", th);
        }
        IoUtil.deleteDir(new File(srcFolder));
        printFinishedIn(start);
      }
    }

  } // class ImportOcspDb

  /**
   * Import OCSP From CA DB.
   *
   * @author Lijun Liao (xipki)
   */
  public static class ImportOcspFromCaDb extends DbPortWorker {

    private final String publisherName;

    private final boolean resume;

    private final String srcFolder;

    private final int batchEntriesPerCommit;

    public ImportOcspFromCaDb(
        DataSourceFactory datasourceFactory, String dbConfFile, String publisherName,
        boolean resume, String srcFolder, int batchEntriesPerCommit, char[] password)
        throws InvalidConfException, IOException {
      super(datasourceFactory, dbConfFile, password);
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

        IoUtil.deleteDir(new File(srcFolder));
        printFinishedIn(start);
      }
    }

  } // class ImportOcspFromCaDb

  private static void printFinishedIn(long startMs) {
    long duration = (Clock.systemUTC().millis() - startMs) / 1000;
    System.out.println("Finished in " + StringUtil.formatTime(duration, false));
  }

}
