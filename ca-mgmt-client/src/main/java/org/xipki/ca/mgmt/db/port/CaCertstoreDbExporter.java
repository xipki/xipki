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

import com.alibaba.fastjson.JSON;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.security.HashAlgo;
import org.xipki.security.util.X509Util;
import org.xipki.util.*;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.cert.CRLException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Database exporter of CA CertStore.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

class CaCertstoreDbExporter extends DbPorter {

  private static final Logger LOG = LoggerFactory.getLogger(CaCertstoreDbExporter.class);

  private final int numCertsInBundle;

  private final int numCertsPerSelect;

  private final boolean resume;

  CaCertstoreDbExporter(DataSourceWrapper datasource, String baseDir, int numCertsInBundle,
      int numCertsPerSelect, boolean resume, AtomicBoolean stopMe)
          throws DataAccessException {
    super(datasource, baseDir, stopMe);

    this.numCertsInBundle = Args.positive(numCertsInBundle, "numCertsInBundle");
    this.numCertsPerSelect = Args.positive(numCertsPerSelect, "numCertsPerSelect");
    this.resume = resume;
  } // constructor

  public void export()
      throws Exception {
    CaCertstore certstore;
    if (resume) {
      try (InputStream is = Files.newInputStream(Paths.get(baseDir, FILENAME_CA_CERTSTORE))) {
        certstore = JSON.parseObject(is, CaCertstore.class);
      }
      certstore.validate();

      if (certstore.getVersion() > VERSION) {
        throw new Exception("could not continue with CertStore greater than "
            + VERSION + ": " + certstore.getVersion());
      }
    } else {
      certstore = new CaCertstore();
      certstore.setVersion(VERSION);
    }

    Exception exception = null;
    System.out.println("exporting CA certstore from database");
    try {
      if (!resume) {
        exportPublishQueue(certstore);
      }

      File processLogFile = new File(baseDir, DbPorter.EXPORT_PROCESS_LOG_FILENAME);

      Long idProcessedInLastProcess = null;
      CaDbEntryType typeProcessedInLastProcess = null;
      if (processLogFile.exists()) {
        byte[] content = IoUtil.read(processLogFile);
        if (content != null && content.length > 0) {
          String str = StringUtil.toUtf8String(content);
          int idx = str.indexOf(':');
          String typeName = str.substring(0, idx).trim();
          typeProcessedInLastProcess = CaDbEntryType.valueOf(typeName);
          idProcessedInLastProcess = Long.parseLong(str.substring(idx + 1).trim());
        }
      }

      if (CaDbEntryType.CRL == typeProcessedInLastProcess || typeProcessedInLastProcess == null) {
        exception = exportEntries(CaDbEntryType.CRL, certstore, processLogFile,
            idProcessedInLastProcess);
        typeProcessedInLastProcess = null;
        idProcessedInLastProcess = null;
      }

      CaDbEntryType[] types = {CaDbEntryType.CERT, CaDbEntryType.REQUEST, CaDbEntryType.REQCERT};

      for (CaDbEntryType type : types) {
        if (exception == null
            && (type == typeProcessedInLastProcess || typeProcessedInLastProcess == null)) {
          exception = exportEntries(type, certstore, processLogFile, idProcessedInLastProcess);
          typeProcessedInLastProcess = null;
          idProcessedInLastProcess = null;
        }
      }

      certstore.validate();
      try (OutputStream os = Files.newOutputStream(Paths.get(baseDir, FILENAME_CA_CERTSTORE))) {
        JSON.writeJSONString(os, StandardCharsets.UTF_8, certstore);
      }
    } catch (Exception ex) {
      System.err.println("could not export CA certstore from database");
      exception = ex;
    }

    if (exception == null) {
      System.out.println(" exported CA certstore from database");
    } else {
      throw exception;
    }
  } // method export

  private Exception exportEntries(CaDbEntryType type, CaCertstore certstore,
      File processLogFile, Long idProcessedInLastProcess) {
    String tablesText = "table " + type.getTableName();

    File dir = new File(baseDir, type.getDirName());
    dir.mkdirs();

    OutputStream entriesFileOs = null;
    try {
      entriesFileOs = Files.newOutputStream(Paths.get(baseDir, type.getDirName() + ".mf"),
          StandardOpenOption.CREATE, StandardOpenOption.APPEND);
      exportEntries(type, certstore, processLogFile, entriesFileOs, idProcessedInLastProcess);
      return null;
    } catch (Exception ex) {
      // delete the temporary files
      deleteTmpFiles(baseDir, "tmp-");

      System.err.println("\nexporting " + tablesText + " has been cancelled due to error,\n"
          + "please continue with the option '--resume'");
      LOG.error("Exception", ex);
      return ex;
    } finally {
      IoUtil.closeQuietly(entriesFileOs);
    }
  } // method exportEntries

  private void exportEntries(CaDbEntryType type, CaCertstore certstore, File processLogFile,
      OutputStream filenameListOs, Long idProcessedInLastProcess)
          throws Exception {
    int numEntriesPerSelect = Math.max(1, Math.round(type.getSqlBatchFactor() * numCertsPerSelect));
    int numEntriesPerZip = Math.max(1, Math.round(type.getSqlBatchFactor() * numCertsInBundle));
    File entriesDir = new File(baseDir, type.getDirName());
    String tableName = type.getTableName();

    int numProcessedBefore;
    String coreSql;

    switch (type) {
      case CERT:
        numProcessedBefore = certstore.getCountCerts();
        coreSql = "ID,SN,CA_ID,PID,RID,RTYPE,TID,UID,EE,LUPDATE,REV,RR,RT,RIT,FP_RS,"
            + "REQ_SUBJECT,CRL_SCOPE,CERT FROM CERT WHERE ID>=?";
        break;
      case CRL:
        numProcessedBefore = certstore.getCountCrls();
        coreSql = "ID,CA_ID,CRL_SCOPE,CRL FROM CRL WHERE ID>=?";
        break;
      case REQUEST:
        numProcessedBefore = certstore.getCountRequests();
        coreSql = "ID,LUPDATE,DATA FROM REQUEST WHERE ID>=?";
        break;
      case REQCERT:
        numProcessedBefore = certstore.getCountReqCerts();
        coreSql = "ID,RID,CID FROM REQCERT WHERE ID>=?";
        break;
      default:
        throw new IllegalStateException("unknown CaDbEntryType " + type);
    }

    long minId = (idProcessedInLastProcess != null) ? idProcessedInLastProcess + 1
        : min(tableName, "ID");

    String tablesText = "table " + type.getTableName();
    System.out.println("exporting " + tablesText + " from ID " + minId);

    final long maxId = max(tableName, "ID");
    long total = count(tableName) - numProcessedBefore;
    if (total < 1) {
      total = 1; // to avoid exception
    }

    String sql = datasource.buildSelectFirstSql(numEntriesPerSelect, "ID ASC", coreSql);

    Object entriesInCurrentFile = createContainer(type);
    PreparedStatement ps = prepareStatement(sql);

    int numEntriesInCurrentFile = 0;

    int sum = 0;
    File currentEntriesZipFile = new File(baseDir,
        "tmp-" + type.getDirName() + "-" + System.currentTimeMillis() + ".zip");
    ZipOutputStream currentEntriesZip = getZipOutputStream(currentEntriesZipFile);

    long minIdOfCurrentFile = -1;
    long maxIdOfCurrentFile = -1;

    ProcessLog processLog = new ProcessLog(total);
    processLog.printHeader();

    try {
      Long id = null;
      boolean interrupted = false;
      long lastMaxId = minId - 1;

      while (true) {
        if (stopMe.get()) {
          interrupted = true;
          break;
        }

        ps.setLong(1, lastMaxId + 1);

        ResultSet rs = ps.executeQuery();

        // no entries anymore
        if (!rs.next()) {
          break;
        }

        do {
          id = rs.getLong("ID");
          if (lastMaxId < id) {
            lastMaxId = id;
          }

          if (minIdOfCurrentFile == -1) {
            minIdOfCurrentFile = id;
          } else if (minIdOfCurrentFile > id) {
            minIdOfCurrentFile = id;
          }

          if (maxIdOfCurrentFile == -1) {
            maxIdOfCurrentFile = id;
          } else if (maxIdOfCurrentFile < id) {
            maxIdOfCurrentFile = id;
          }

          if (CaDbEntryType.CERT == type) {
            byte[] certBytes = Base64.decodeFast(rs.getString("CERT"));

            String sha1 = HashAlgo.SHA1.hexHash(certBytes);
            String certFileName = sha1 + ".der";
            ZipEntry certZipEntry = new ZipEntry(certFileName);
            currentEntriesZip.putNextEntry(certZipEntry);
            try {
              currentEntriesZip.write(certBytes);
            } finally {
              currentEntriesZip.closeEntry();
            }

            CaCertstore.Cert cert = new CaCertstore.Cert();
            cert.setId(id);
            cert.setCaId(rs.getInt("CA_ID"));
            cert.setEe(rs.getBoolean("EE"));
            cert.setFile(certFileName);

            long fpReqSubject = rs.getLong("FP_RS");
            if (fpReqSubject != 0) {
              cert.setFpRs(fpReqSubject);
              cert.setRs(rs.getString("REQ_SUBJECT"));
            }

            cert.setPid(rs.getInt("PID"));
            cert.setReqType(rs.getInt("RTYPE"));
            cert.setRid(rs.getInt("RID"));
            cert.setSn(rs.getString("SN"));

            String str = rs.getString("TID");
            if (StringUtil.isNotBlank(str)) {
              cert.setTid(str);
            }

            int userId = rs.getInt("UID");
            if (userId != 0) {
              cert.setUid(userId);
            }
            cert.setUpdate(rs.getLong("LUPDATE"));

            int revoked = rs.getInt("REV");
            cert.setRev(revoked);

            if (revoked == 1) {
              cert.setRr(rs.getInt("RR"));
              cert.setRt(rs.getLong("RT"));
              long revInvTime = rs.getLong("RIT");
              if (revInvTime != 0) {
                cert.setRit(revInvTime);
              }
            }

            cert.setCrlScope(rs.getInt("CRL_SCOPE"));

            cert.validate();
            ((CaCertstore.Certs) entriesInCurrentFile).add(cert);
          } else if (CaDbEntryType.CRL == type) {
            byte[] crlBytes = Base64.decodeFast(rs.getString("CRL"));

            X509CRLHolder x509Crl;
            try {
              x509Crl = X509Util.parseCrl(crlBytes);
            } catch (CRLException ex) {
              LogUtil.error(LOG, ex, "could not parse CRL with id " + id);
              throw ex;
            } catch (Exception ex) {
              LogUtil.error(LOG, ex, "could not parse CRL with id " + id);
              throw new CRLException(ex.getMessage(), ex);
            }

            byte[] extnValue = X509Util.getCoreExtValue(x509Crl.getExtensions(),
                                  Extension.cRLNumber);
            if (extnValue == null) {
              LOG.warn("CRL without CRL number, ignore it");
              continue;
            }
            String sha1 = HashAlgo.SHA1.hexHash(crlBytes);

            final String crlFilename = sha1 + ".crl";
            ZipEntry certZipEntry = new ZipEntry(crlFilename);
            currentEntriesZip.putNextEntry(certZipEntry);
            try {
              currentEntriesZip.write(crlBytes);
            } finally {
              currentEntriesZip.closeEntry();
            }

            CaCertstore.Crl crl = new CaCertstore.Crl();
            crl.setId(id);

            crl.setCaId(rs.getInt("CA_ID"));

            BigInteger crlNumber = ASN1Integer.getInstance(extnValue).getPositiveValue();
            crl.setCrlNo(crlNumber.toString());
            crl.setCrlScope(rs.getInt("CRL_SCOPE"));
            crl.setFile(crlFilename);

            crl.validate();
            ((CaCertstore.Crls) entriesInCurrentFile).add(crl);
          } else if (CaDbEntryType.REQUEST == type) {
            byte[] dataBytes = Base64.decodeFast(rs.getString("DATA"));
            String sha1 = HashAlgo.SHA1.hexHash(dataBytes);
            final String dataFilename = sha1 + ".req";
            ZipEntry certZipEntry = new ZipEntry(dataFilename);
            currentEntriesZip.putNextEntry(certZipEntry);
            try {
              currentEntriesZip.write(dataBytes);
            } finally {
              currentEntriesZip.closeEntry();
            }

            CaCertstore.Request entry = new CaCertstore.Request();
            entry.setId(id);
            entry.setUpdate(rs.getLong("LUPDATE"));
            entry.setFile(dataFilename);

            entry.validate();
            ((CaCertstore.Requests) entriesInCurrentFile).add(entry);
          } else if (CaDbEntryType.REQCERT == type) {
            CaCertstore.ReqCert entry = new CaCertstore.ReqCert();
            entry.setId(id);
            entry.setCid(rs.getLong("CID"));
            entry.setRid(rs.getLong("RID"));

            entry.validate();
            ((CaCertstore.ReqCerts) entriesInCurrentFile).add(entry);
          } else {
            throw new IllegalStateException("unknown CaDbEntryType " + type);
          }

          numEntriesInCurrentFile++;
          sum++;

          if (numEntriesInCurrentFile == numEntriesPerZip) {
            String currentEntriesFilename = buildFilename(type.getDirName() + "_", ".zip",
                minIdOfCurrentFile, maxIdOfCurrentFile, maxId);
            finalizeZip(currentEntriesZip, "overview.json", entriesInCurrentFile);
            currentEntriesZipFile.renameTo(new File(entriesDir, currentEntriesFilename));

            writeLine(filenameListOs, currentEntriesFilename);
            setCount(type, certstore, numProcessedBefore + sum);
            echoToFile(tableName + ":" + id, processLogFile);

            processLog.addNumProcessed(numEntriesInCurrentFile);
            processLog.printStatus();

            // reset
            entriesInCurrentFile = createContainer(type);
            numEntriesInCurrentFile = 0;
            minIdOfCurrentFile = -1;
            maxIdOfCurrentFile = -1;
            currentEntriesZipFile = new File(baseDir, "tmp-" + type.getDirName() + "-"
                + System.currentTimeMillis() + ".zip");
            currentEntriesZip = getZipOutputStream(currentEntriesZipFile);
          }
        } while (rs.next());

        rs.close();
      } // end for

      if (interrupted) {
        currentEntriesZip.close();
        throw new InterruptedException("interrupted by the user");
      }

      if (numEntriesInCurrentFile > 0) {
        finalizeZip(currentEntriesZip, "overview.json", entriesInCurrentFile);

        String currentEntriesFilename = buildFilename(type.getDirName() + "_", ".zip",
            minIdOfCurrentFile, maxIdOfCurrentFile, maxId);
        currentEntriesZipFile.renameTo(new File(entriesDir, currentEntriesFilename));

        writeLine(filenameListOs, currentEntriesFilename);
        setCount(type, certstore, numProcessedBefore + sum);
        if (id != null) {
          echoToFile(Long.toString(id), processLogFile);
        }

        processLog.addNumProcessed(numEntriesInCurrentFile);
      } else {
        currentEntriesZip.close();
        currentEntriesZipFile.delete();
      }

    } catch (SQLException ex) {
      throw translate(null, ex);
    } finally {
      releaseResources(ps, null);
    } // end try

    processLog.printTrailer();
    // all successful, delete the processLogFile
    processLogFile.delete();
    System.out.println(" exported " + sum + " entries from " + tablesText);
  } // method exportEntries

  private void exportPublishQueue(CaCertstore certstore)
      throws DataAccessException, InvalidConfException {
    System.out.println("exporting table PUBLISHQUEUE");

    String sql = "SELECT CID,PID,CA_ID FROM PUBLISHQUEUE WHERE CID>=? AND CID<? ORDER BY CID ASC";
    final int minId = (int) min("PUBLISHQUEUE", "CID");
    final int maxId = (int) max("PUBLISHQUEUE", "CID");

    List<CaCertstore.ToPublish> queue = new LinkedList<>();
    certstore.setPublishQueue(queue);
    if (maxId == 0) {
      System.out.println(" exported table PUBLISHQUEUE");
      return;
    }

    PreparedStatement ps = prepareStatement(sql);
    ResultSet rs = null;

    final int n = 500;

    try {
      for (int i = minId; i <= maxId; i += n) {
        ps.setInt(1, i);
        ps.setInt(2, i + n);

        rs = ps.executeQuery();

        while (rs.next()) {
          CaCertstore.ToPublish toPub = new CaCertstore.ToPublish();
          toPub.setPubId(rs.getInt("PID"));
          toPub.setCertId(rs.getInt("CID"));
          toPub.setCaId(rs.getInt("CA_ID"));

          toPub.validate();
          queue.add(toPub);
        }
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(ps, rs);
    }
    System.out.println(" exported table PUBLISHQUEUE");
  } // method exportPublishQueue

  private void finalizeZip(ZipOutputStream zipOutStream, String filename, Object container)
      throws IOException {
    ZipEntry certZipEntry = new ZipEntry(filename);
    zipOutStream.putNextEntry(certZipEntry);
    try {
      JSON.writeJSONString(zipOutStream, StandardCharsets.UTF_8, container);
    } finally {
      zipOutStream.closeEntry();
    }

    zipOutStream.close();
  } // method finalizeZip

  private static Object createContainer(CaDbEntryType type) {
    switch (type) {
      case CERT:
        return new CaCertstore.Certs();
      case CRL:
        return new CaCertstore.Crls();
      case REQUEST:
        return new CaCertstore.Requests();
      case REQCERT:
        return new CaCertstore.ReqCerts();
      default:
        throw new IllegalStateException("unknown CaDbEntryType " + type);
    }
  } // method createContainer

  private static void setCount(CaDbEntryType type, CaCertstore certstore, int num) {
    switch (type) {
      case CERT:
        certstore.setCountCerts(num);
        break;
      case CRL:
        certstore.setCountCrls(num);
        break;
      case REQUEST:
        certstore.setCountRequests(num);
        break;
      case REQCERT:
        certstore.setCountReqCerts(num);
        break;
      default:
        throw new IllegalStateException("unknown CaDbEntryType " + type);
    }
  } // method setCount
}
