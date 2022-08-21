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
import org.xipki.ca.mgmt.db.DbSchemaInfo;
import org.xipki.ca.mgmt.db.DbToolBase;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.util.*;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Database porter.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class DbPorter extends DbToolBase {

  public enum OcspDbEntryType {
    CERT("certs", "CERT", 1);

    private final String dirName;

    private final String tableName;

    private final float sqlBatchFactor;

    OcspDbEntryType(String dirName, String tableName, float sqlBatchFactor) {
      this.dirName = dirName;
      this.tableName = tableName;
      this.sqlBatchFactor = sqlBatchFactor;
    }

    public String getDirName() {
      return dirName;
    }

    public String getTableName() {
      return tableName;
    }

    public float getSqlBatchFactor() {
      return sqlBatchFactor;
    }

  } // class OcspDbEntryType

  public enum CaDbEntryType {
    CERT("certs", "CERT", 1),
    CRL("crls", "CRL", 0.1f),
    REQUEST("requests", "REQUEST", 0.1f),
    REQCERT("reqcerts", "REQCERT", 50);

    private final String dirName;

    private final String tableName;

    private final float sqlBatchFactor;

    CaDbEntryType(String dirName, String tableName, float sqlBatchFactor) {
      this.dirName = dirName;
      this.tableName = tableName;
      this.sqlBatchFactor = sqlBatchFactor;
    }

    public String getDirName() {
      return dirName;
    }

    public String getTableName() {
      return tableName;
    }

    public float getSqlBatchFactor() {
      return sqlBatchFactor;
    }

  } // class CaDbEntryType

  public static class DbPortFileNameIterator implements Iterator<String>, Closeable {

    private static final Logger LOG = LoggerFactory.getLogger(DbPortFileNameIterator.class);

    private final BufferedReader reader;

    private String nextFilename;

    public DbPortFileNameIterator(String filename)
        throws IOException {
      Args.notNull(filename, "filename");

      this.reader = Files.newBufferedReader(Paths.get(filename));
      this.nextFilename = readNextFilenameLine();
    }

    @Override
    public boolean hasNext() {
      return nextFilename != null;
    }

    @Override
    public String next() {
      String str = nextFilename;
      nextFilename = null;
      try {
        nextFilename = readNextFilenameLine();
      } catch (IOException ex) {
        throw new IllegalStateException("could not read next file name");
      }
      return str;
    }

    @Override
    public void remove() {
      throw new UnsupportedOperationException("remove is not supported");
    }

    @Override
    public void close() {
      try {
        reader.close();
      } catch (Throwable th) {
        LogUtil.error(LOG, th,"could not close reader");
      }
    }

    private String readNextFilenameLine()
        throws IOException {
      String line;
      while ((line = reader.readLine()) != null) {
        line = line.trim();
        if (StringUtil.isBlank(line) || line.startsWith("#") || !line.endsWith(".zip")) {
          continue;
        }
        return line;
      }

      return null;
    }

  } // class DbPortFileNameIterator

  public static final String FILENAME_CA_CONFIGURATION = "ca-configuration.json";

  public static final String FILENAME_CA_CERTSTORE = "ca-certstore.json";

  public static final String FILENAME_OCSP_CERTSTORE = "ocsp-certstore.json";

  public static final String EXPORT_PROCESS_LOG_FILENAME = "export.process";

  public static final String IMPORT_PROCESS_LOG_FILENAME = "import.process";

  public static final String IMPORT_TO_OCSP_PROCESS_LOG_FILENAME = "import-to-ocsp.process";

  /**
   * For XiPKI Version 5.3.x
   */
  public static final int VERSION_V1 = 1;

  /**
   * For XiPKI Version 5.4.x
   */
  public static final int VERSION_V2 = 2;

  protected final int dbSchemaVersion;

  protected final int maxX500nameLen;

  protected final DbSchemaInfo dbSchemaInfo;

  public DbPorter(DataSourceWrapper datasource, String baseDir, AtomicBoolean stopMe)
      throws DataAccessException {
    super(datasource, baseDir, stopMe);

    this.dbSchemaInfo = new DbSchemaInfo(datasource);
    this.dbSchemaVersion = Integer.parseInt(dbSchemaInfo.getVariableValue("VERSION"));
    this.maxX500nameLen = Integer.parseInt(dbSchemaInfo.getVariableValue("X500NAME_MAXLEN"));
  }

  protected FileOrValue buildFileOrValue(String content, String fileName)
      throws IOException {
    if (content == null) {
      return null;
    }

    Args.notNull(fileName, "fileName");

    FileOrValue ret = new FileOrValue();
    if (content.length() < 256) {
      ret.setValue(content);
      return ret;
    }

    File file = new File(baseDir, fileName);
    IoUtil.mkdirsParent(file.toPath());
    IoUtil.save(file, StringUtil.toUtf8Bytes(content));

    ret.setFile(fileName);
    return ret;
  } // method buildFileOrValue

  protected FileOrBinary buildFileOrBase64Binary(String base64Content, String fileName)
      throws IOException {
    if (base64Content == null) {
      return null;
    }
    return buildFileOrBinary(Base64.decode(base64Content), fileName);
  } // method buildFileOrBase64Binary

  protected FileOrBinary buildFileOrBinary(byte[] content, String fileName)
      throws IOException {
    if (content == null) {
      return null;
    }

    Args.notNull(fileName, "fileName");

    FileOrBinary ret = new FileOrBinary();
    if (content.length < 256) {
      ret.setBinary(content);
      return ret;
    }

    File file = new File(baseDir, fileName);
    IoUtil.mkdirsParent(file.toPath());
    IoUtil.save(file, content);

    ret.setFile(fileName);
    return ret;
  } // method buildFileOrBinary

  protected byte[] readContent(FileOrBinary fileOrBinary)
      throws IOException {
    if (fileOrBinary == null) {
      return null;
    }

    if (fileOrBinary.getBinary() != null) {
      return fileOrBinary.getBinary();
    }

    File file = new File(baseDir, fileOrBinary.getFile());
    return IoUtil.read(file);
  } // method readContent

  protected String readContent(FileOrValue fileOrValue)
      throws IOException {
    if (fileOrValue == null) {
      return null;
    }

    if (fileOrValue.getValue() != null) {
      return fileOrValue.getValue();
    }

    File file = new File(baseDir, fileOrValue.getFile());
    return StringUtil.toUtf8String(IoUtil.read(file));
  } // method readContent

  public static void echoToFile(String content, File file)
      throws IOException {
    Files.write(Args.notNull(file, "file").toPath(), StringUtil.toUtf8Bytes(Args.notNull(content, "content")));
  }

}
