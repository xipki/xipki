// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.db.port;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.mgmt.CaJson;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.security.HashAlgo;
import org.xipki.security.util.X509Util;
import org.xipki.util.*;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.cert.CRLException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Database exporter of CA CertStore.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

class CaCertstoreDbExporter extends DbPorter {

  private static final Logger LOG = LoggerFactory.getLogger(CaCertstoreDbExporter.class);

  private final int numCertsInBundle;

  private final int numCertsPerSelect;

  private final boolean resume;

  CaCertstoreDbExporter(
      DataSourceWrapper datasource, String baseDir, int numCertsInBundle,
      int numCertsPerSelect, boolean resume, AtomicBoolean stopMe)
      throws DataAccessException {
    super(datasource, baseDir, stopMe);

    this.numCertsInBundle = Args.positive(numCertsInBundle, "numCertsInBundle");
    this.numCertsPerSelect = Args.positive(numCertsPerSelect, "numCertsPerSelect");
    this.resume = resume;
  } // constructor

  public void export() throws Exception {
    CaCertstore certstore;
    Path path = Paths.get(baseDir, FILENAME_CA_CERTSTORE);
    if (resume) {
      certstore = CaJson.parseObject(path, CaCertstore.class);
      certstore.validate();

      if (certstore.getVersion() > VERSION_V2) {
        throw new Exception("could not continue with CertStore greater than "
            + VERSION_V2 + ": " + certstore.getVersion());
      }
    } else {
      certstore = new CaCertstore();
      certstore.setVersion(VERSION_V2);
    }

    Exception exception = null;
    System.out.println("exporting CA certstore from database");

    if (dbSchemaVersion >= 8) {
      for (String tblName : new String[]{"PROFILE", "REQUESTOR", "CA"}) {
        String sql = "SELECT ID,NAME";
        if ("CA".equalsIgnoreCase(tblName)) {
          sql += ",CERT";
        }
        sql += " FROM " + tblName;

        System.out.print("    exporting table " + tblName + " ... ");

        PreparedStatement stmt = null;
        ResultSet rs = null;
        boolean succ = false;
        try {
          stmt = prepareStatement(sql);
          rs = stmt.executeQuery();

          List<CaCertstore.IdName> entries = new LinkedList<>();
          while (rs.next()) {
            String name = rs.getString("NAME");

            CaCertstore.IdName entry = "CA".equalsIgnoreCase(tblName)
                ? new CaCertstore.Ca() : new CaCertstore.IdName();
            entry.setId(rs.getInt("ID"));
            entry.setName(name);

            if ("CA".equalsIgnoreCase(tblName)) {
              ((CaCertstore.Ca) entry).setCert(Base64.decode(rs.getString("CERT")));
            }
            entry.validate();
            entries.add(entry);
          }

          if ("REQUESTOR".equalsIgnoreCase(tblName)) {
            certstore.setRequestors(entries);
          } else if (("PROFILE").equalsIgnoreCase(tblName)) {
            certstore.setProfiles(entries);
          } else {
            List<CaCertstore.Ca> caEntries = new ArrayList<>(entries.size());
            for (CaCertstore.IdName entry : entries) {
              caEntries.add((CaCertstore.Ca) entry);
            }
            certstore.setCas(caEntries);
          }
          succ = true;
        } catch (SQLException ex) {
          throw translate(sql, ex);
        } finally {
          releaseResources(stmt, rs);
          System.out.println(succ ? "SUCCESSFUL" : "FAILED");
        }
      }
    }

    try {
      File processLogFile = new File(baseDir, DbPorter.EXPORT_PROCESS_LOG_FILENAME);

      Long idProcessedInLastProcess = null;
      CaDbEntryType typeProcessedInLastProcess = null;
      if (processLogFile.exists()) {
        byte[] content = IoUtil.read(processLogFile);
        if (content.length > 0) {
          String str = StringUtil.toUtf8String(content);
          int idx = str.indexOf(':');
          String typeName = str.substring(0, idx).trim();
          typeProcessedInLastProcess = CaDbEntryType.valueOf(typeName);
          idProcessedInLastProcess = Long.parseLong(str.substring(idx + 1).trim());
        }
      }

      if (CaDbEntryType.CRL == typeProcessedInLastProcess || typeProcessedInLastProcess == null) {
        exception = exportEntries(CaDbEntryType.CRL, certstore, processLogFile, idProcessedInLastProcess);
        typeProcessedInLastProcess = null;
        idProcessedInLastProcess = null;
      }

      CaDbEntryType[] types = {CaDbEntryType.CERT};

      for (CaDbEntryType type : types) {
        if (exception == null && (type == typeProcessedInLastProcess || typeProcessedInLastProcess == null)) {
          exception = exportEntries(type, certstore, processLogFile, idProcessedInLastProcess);
          typeProcessedInLastProcess = null;
          idProcessedInLastProcess = null;
        }
      }

      certstore.validate();
      try (OutputStream os = Files.newOutputStream(path)) {
        CaJson.writeJSON(certstore, os);
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

  private Exception exportEntries(
      CaDbEntryType type, CaCertstore certstore, File processLogFile, Long idProcessedInLastProcess) {
    String tablesText = "table " + type.getTableName();

    File dir = new File(baseDir, type.getDirName());
    try {
      IoUtil.mkdirs(dir);
    } catch (IOException ex) {
      LOG.error("IO Exception", ex);
      return ex;
    }

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

  private void exportEntries(
      CaDbEntryType type, CaCertstore certstore, File processLogFile,
      OutputStream filenameListOs, Long idProcessedInLastProcess)
      throws Exception {
    int numEntriesPerSelect = Math.max(1, Math.round(type.getSqlBatchFactor() * numCertsPerSelect));
    int numEntriesPerZip = Math.max(1, Math.round(type.getSqlBatchFactor() * numCertsInBundle));
    File entriesDir = new File(baseDir, type.getDirName());
    String tableName = type.getTableName();

    int numProcessedBefore;
    String coreSql;

    if (type == CaDbEntryType.CERT) {
      numProcessedBefore = certstore.getCountCerts();
      String columns = "ID,SN,CA_ID,PID,RID,TID,EE,LUPDATE,REV,RR,RT,RIT,FP_RS,REQ_SUBJECT,CRL_SCOPE,CERT";
      if (dbSchemaVersion >= 7) {
        columns += ",PRIVATE_KEY";
      }
      coreSql = columns + " FROM CERT WHERE ID>=?";
    } else if (type == CaDbEntryType.CRL) {
      numProcessedBefore = certstore.getCountCrls();
      coreSql = "ID,CA_ID,CRL_SCOPE,CRL FROM CRL WHERE ID>=?";
    } else {
      throw new IllegalStateException("unknown CaDbEntryType " + type);
    }

    long minId = (idProcessedInLastProcess != null) ? idProcessedInLastProcess + 1 : min(tableName, "ID");

    String tablesText = "table " + type.getTableName();
    System.out.println("exporting " + tablesText + " from ID " + minId);

    final long maxId = max(tableName, "ID");
    long total = Math.max(1, count(tableName) - numProcessedBefore); // 1: to avoid exception
    String sql = datasource.buildSelectFirstSql(numEntriesPerSelect, "ID ASC", coreSql);

    Object entriesInCurrentFile = createContainer(type);
    PreparedStatement ps = prepareStatement(sql);

    int numEntriesInCurrentFile = 0;

    int sum = 0;
    File currentEntriesZipFile = new File(baseDir,
        "tmp-" + type.getDirName() + "-" + Clock.systemUTC().millis() + ".zip");
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
            String privateKey = null;
            if (dbSchemaVersion >= 7) {
              privateKey = rs.getString("PRIVATE_KEY");
            }

            String sha1 = HashAlgo.SHA1.hexHash(certBytes);

            String certFileName = sha1 + ".der";
            currentEntriesZip.putNextEntry(new ZipEntry(certFileName));
            try {
              currentEntriesZip.write(certBytes);
            } finally {
              currentEntriesZip.closeEntry();
            }

            String privateKeyFileName = sha1 + "-key.bin";
            if (privateKey != null) {
              currentEntriesZip.putNextEntry(new ZipEntry(privateKeyFileName));
              try {
                currentEntriesZip.write(privateKey.getBytes(StandardCharsets.UTF_8));
              } finally {
                currentEntriesZip.closeEntry();
              }
            }

            CaCertstore.Cert cert = new CaCertstore.Cert();
            cert.setId(id);
            cert.setCaId(rs.getInt("CA_ID"));
            cert.setEe(rs.getBoolean("EE"));
            cert.setFile(certFileName);
            if (privateKey != null) {
              cert.setPrivateKeyFile(privateKeyFileName);
            }

            long fpReqSubject = rs.getLong("FP_RS");
            if (fpReqSubject != 0) {
              cert.setFpRs(fpReqSubject);
              cert.setRs(rs.getString("REQ_SUBJECT"));
            }

            cert.setPid(rs.getInt("PID"));
            cert.setRid(rs.getInt("RID"));
            cert.setSn(rs.getString("SN"));

            String str = rs.getString("TID");
            if (StringUtil.isNotBlank(str)) {
              cert.setTid(str);
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
            } catch (Exception ex) {
              LogUtil.error(LOG, ex, "could not parse CRL with id " + id);
              throw (ex instanceof CRLException) ? (CRLException) ex : new CRLException(ex.getMessage(), ex);
            }

            byte[] extnValue = X509Util.getCoreExtValue(x509Crl.getExtensions(), Extension.cRLNumber);
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
          } else {
            throw new IllegalStateException("unknown CaDbEntryType " + type);
          }

          numEntriesInCurrentFile++;
          sum++;

          if (numEntriesInCurrentFile == numEntriesPerZip) {
            String currentEntriesFilename = buildFilename(type.getDirName() + "_", ".zip",
                minIdOfCurrentFile, maxIdOfCurrentFile, maxId);
            finalizeZip(currentEntriesZip, "overview.json", entriesInCurrentFile);
            IoUtil.renameTo(currentEntriesZipFile, new File(entriesDir, currentEntriesFilename));

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
                + Clock.systemUTC().millis() + ".zip");
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
        IoUtil.renameTo(currentEntriesZipFile, new File(entriesDir, currentEntriesFilename));

        writeLine(filenameListOs, currentEntriesFilename);
        setCount(type, certstore, numProcessedBefore + sum);
        echoToFile(Long.toString(id), processLogFile);

        processLog.addNumProcessed(numEntriesInCurrentFile);
      } else {
        currentEntriesZip.close();
        IoUtil.deleteFile0(currentEntriesZipFile);
      }
    } catch (SQLException ex) {
      throw translate(null, ex);
    } finally {
      releaseResources(ps, null);
    } // end try

    processLog.printTrailer();
    // all successful, delete the processLogFile
    IoUtil.deleteFile0(processLogFile);
    System.out.println(" exported " + sum + " entries from " + tablesText);
  } // method exportEntries

  private void finalizeZip(ZipOutputStream zipOutStream, String filename, Object container)
      throws IOException {
    ZipEntry certZipEntry = new ZipEntry(filename);
    zipOutStream.putNextEntry(certZipEntry);
    try {
      CaJson.writeJSON(container, zipOutStream);
    } finally {
      zipOutStream.closeEntry();
    }

    zipOutStream.close();
  } // method finalizeZip

  private static Object createContainer(CaDbEntryType type) {
    if (type == CaDbEntryType.CERT) {
      return new CaCertstore.Certs();
    } else if (type == CaDbEntryType.CRL) {
      return new CaCertstore.Crls();
    } else {
      throw new IllegalStateException("unknown CaDbEntryType " + type);
    }
  } // method createContainer

  private static void setCount(CaDbEntryType type, CaCertstore certstore, int num) {
    if (type == CaDbEntryType.CERT) {
      certstore.setCountCerts(num);
    } else if (type == CaDbEntryType.CRL) {
      certstore.setCountCrls(num);
    } else {
      throw new IllegalStateException("unknown CaDbEntryType " + type);
    }
  } // method setCount
}
