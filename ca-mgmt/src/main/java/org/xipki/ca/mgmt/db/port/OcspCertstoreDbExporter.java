// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.db.port;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.util.benchmark.ProcessLog;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonBuilder;
import org.xipki.util.codec.json.JsonParser;
import org.xipki.util.datasource.DataAccessException;
import org.xipki.util.datasource.DataSourceWrapper;
import org.xipki.util.io.IoUtil;
import org.xipki.util.misc.StringUtil;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Database exporter of OCSP CertStore.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

class OcspCertstoreDbExporter extends DbPorter {

  public static final String PROCESS_LOG_FILENAME = "export.process";

  private static final Logger LOG =
      LoggerFactory.getLogger(OcspCertstoreDbExporter.class);

  private final int numCertsInBundle;

  private final int numCertsPerSelect;

  private final boolean resume;

  OcspCertstoreDbExporter(DataSourceWrapper datasource, String baseDir,
                          int numCertsInBundle, int numCertsPerSelect,
                          boolean resume, AtomicBoolean stopMe)
      throws Exception {
    super(datasource, baseDir, stopMe);

    this.numCertsInBundle = Args.positive(numCertsInBundle, "numCertsInBundle");
    this.numCertsPerSelect = Args.positive(numCertsPerSelect,
        "numCertsPerSelect");

    if (resume) {
      File processLogFile = new File(baseDir, PROCESS_LOG_FILENAME);
      if (!processLogFile.exists()) {
        throw new Exception("could not process with '--resume' option");
      }
    }
    this.resume = resume;
  } // constructor

  public void export() throws Exception {
    OcspCertstore certstore;
    Path path = Paths.get(baseDir, FILENAME_OCSP_CERTSTORE);
    if (resume) {
      certstore = OcspCertstore.parse(JsonParser.parseMap(path, false));
      if (certstore.getVersion() > VERSION_V2) {
        throw new Exception("could not continue with Certstore greater than " +
            VERSION_V2 + ": " + certstore.getVersion());
      }
    } else {
      certstore = new OcspCertstore(VERSION_V2);
    }
    System.out.println("exporting OCSP certstore from database");

    if (!resume) {
      exportHashAlgo(certstore);
      exportIssuer(certstore);
      exportCrlInfo(certstore);
    }

    File processLogFile = new File(baseDir, PROCESS_LOG_FILENAME);
    Exception exception = exportCert(certstore, processLogFile);

    try (OutputStream os = Files.newOutputStream(path)) {
      os.write(StringUtil.toUtf8Bytes(
          JsonBuilder.toJson(certstore.toCodec())));
    }

    if (exception == null) {
      System.out.println(" exported OCSP certstore from database");
    } else {
      throw exception;
    }
  } // method export

  private void exportHashAlgo(OcspCertstore certstore)
      throws DataAccessException {
    String certHashAlgoStr = Optional.ofNullable(
        dbSchemaInfo.getVariableValue("CERTHASH_ALGO"))
        .orElseThrow(() -> new DataAccessException(
            "CERTHASH_ALGO is not defined in table DBSCHEMA"));
    certstore.setCerthashAlgo(certHashAlgoStr);
  } // method exportHashAlgo

  private void exportIssuer(OcspCertstore certstore)
      throws DataAccessException, IOException {
    System.out.print("    exporting table ISSUER ... ");
    boolean succ = false;
    List<OcspCertstore.Issuer> issuers = certstore.getIssuers();
    final String sql = "SELECT ID,CERT,REV_INFO,CRL_ID FROM ISSUER";

    PreparedStatement stmt = null;
    ResultSet rs = null;
    try {
      stmt = prepareStatement(sql);
      rs = stmt.executeQuery();

      while (rs.next()) {
        int id = rs.getInt("ID");

        String certFileName = "issuer-conf/cert-issuer-" + id;
        IoUtil.save(new File(baseDir, certFileName),
            StringUtil.toUtf8Bytes(rs.getString("CERT")));
        String revInfo = rs.getString("REV_INFO");

        int i = rs.getInt("CRL_ID");
        Integer crlId = (i == 0) ? null : i;
        OcspCertstore.Issuer issuer = new OcspCertstore.Issuer(
            id, certFileName, revInfo, crlId);

        issuers.add(issuer);
      }
      succ = true;
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
      System.out.println(succ ? "SUCCESSFUL" : "FAILED");
    }
  } // method exportIssuer

  private void exportCrlInfo(OcspCertstore certstore)
      throws DataAccessException {
    System.out.print("    exporting table CRL_INFO ... ");
    boolean succ = false;
    List<OcspCertstore.CrlInfo> crlInfos = certstore.getCrlInfos();
    final String sql = "SELECT ID,NAME,INFO FROM CRL_INFO";

    PreparedStatement stmt = null;
    ResultSet rs = null;
    try {
      stmt = prepareStatement(sql);
      rs = stmt.executeQuery();

      while (rs.next()) {
        int id = rs.getInt("ID");
        String name = rs.getString("NAME");
        String info = rs.getString("INFO");
        OcspCertstore.CrlInfo crlInfo = new OcspCertstore.CrlInfo(
            id, name, info);

        crlInfos.add(crlInfo);
      }
      succ = true;
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
      System.out.println(succ ? "SUCCESSFUL" : "FAILED");
    }
  } // method exportCrlInfo

  private Exception exportCert(OcspCertstore certstore, File processLogFile) {
    try {
      IoUtil.mkdirs(new File(baseDir, OcspDbEntryType.CERT.getDirName()));
    } catch (IOException ex) {
      LOG.error("IO Exception", ex);
      return ex;
    }

    OutputStream certsFileOs = null;

    try {
      certsFileOs = Files.newOutputStream(
          Paths.get(baseDir, OcspDbEntryType.CERT.getDirName() + ".mf"),
          StandardOpenOption.CREATE, StandardOpenOption.APPEND);
      exportCert0(certstore, processLogFile, certsFileOs);
      return null;
    } catch (Exception ex) {
      // delete the temporary files
      deleteTmpFiles(baseDir, "tmp-certs-");
      System.err.println("\nexporting table CERT has been cancelled due " +
          "to error,\nplease continue with the option '--resume'");
      LOG.error("Exception", ex);
      return ex;
    } finally {
      IoUtil.closeQuietly(certsFileOs);
    }
  } // method exportCert

  private void exportCert0(OcspCertstore certstore, File processLogFile,
                           OutputStream certsFileOs)
      throws Exception {
    File certsDir = new File(baseDir, OcspDbEntryType.CERT.getDirName());
    Long minId = null;
    if (processLogFile.exists()) {
      byte[] content = IoUtil.read(processLogFile);
      if (content.length > 0) {
        minId = 1 + Long.parseLong(StringUtil.toUtf8String(content).trim());
      }
    }

    if (minId == null) {
      minId = min("CERT", "ID");
    }

    System.out.println("exporting table CERT from ID " + minId);

    final String coreSql = "ID,SN,IID,LUPDATE,REV,RR,RT,RIT,NAFTER,NBEFORE," +
        "HASH,SUBJECT,CRL_ID FROM CERT WHERE ID>=?";
    final String certSql = datasource.buildSelectFirstSql(numCertsPerSelect,
        "ID ASC", coreSql);

    final long maxId = max("CERT", "ID");

    int numProcessedBefore = certstore.getCountCerts();
    final long total = count("CERT") - numProcessedBefore;
    ProcessLog processLog = new ProcessLog(total);

    PreparedStatement certPs = prepareStatement(certSql);

    int sum = 0;
    int numCertInCurrentFile = 0;

    OcspCertstore.Certs certsInCurrentFile = new OcspCertstore.Certs();

    File currentCertsZipFile = new File(baseDir,
        "tmp-certs-" + Clock.systemUTC().millis() + ".zip");
    ZipOutputStream currentCertsZip = getZipOutputStream(currentCertsZipFile);

    long minCertIdOfCurrentFile = -1;
    long maxCertIdOfCurrentFile = -1;

    processLog.printHeader();

    String sql = null;
    Long id = null; // TODO: id -> long

    try {
      boolean interrupted = false;

      long lastMaxId = minId - 1;

      while (true) {
        if (stopMe.get()) {
          interrupted = true;
          break;
        }

        sql = certSql;
        certPs.setLong(1, lastMaxId + 1);

        ResultSet rs = certPs.executeQuery();

        if (!rs.next()) {
          break;
        }

        do {
          id = rs.getLong("ID");
          if (lastMaxId < id) {
            lastMaxId = id;
          }

          if (minCertIdOfCurrentFile == -1) {
            minCertIdOfCurrentFile = id;
          } else if (minCertIdOfCurrentFile > id) {
            minCertIdOfCurrentFile = id;
          }

          if (maxCertIdOfCurrentFile == -1) {
            maxCertIdOfCurrentFile = id;
          } else if (maxCertIdOfCurrentFile < id) {
            maxCertIdOfCurrentFile = id;
          }

          int iid = rs.getInt("IID");
          String sn = rs.getString("SN");
          long lUpdate = rs.getLong("LUPDATE");

          boolean revoked = rs.getBoolean("REV");

          String hash = rs.getString("HASH");
          String subject = rs.getString("SUBJECT");

          long nafter = rs.getLong("NAFTER");
          long nbefore = rs.getLong("NBEFORE");

          int i = rs.getInt("CRL_ID");
          Integer crlId = (i == 0) ? null : i;

          OcspCertstore.Cert cert = new OcspCertstore.Cert(id, hash, iid,
              lUpdate, nbefore, nafter, sn, subject, crlId);

          if (revoked) {
            int reason = rs.getInt("RR");
            long revTime = rs.getLong("RT");
            long l = rs.getLong("RIT");
            Long rit = (l == 0) ? null : l;
            cert.setRevocation(reason, revTime, rit);
          }

          certsInCurrentFile.add(cert);
          numCertInCurrentFile++;
          sum++;

          if (numCertInCurrentFile == numCertsInBundle) {
            finalizeZip(currentCertsZip, certsInCurrentFile);

            String currentCertsFilename = buildFilename("certs_", ".zip",
                minCertIdOfCurrentFile, maxCertIdOfCurrentFile, maxId);
            IoUtil.renameTo(currentCertsZipFile,
                new File(certsDir, currentCertsFilename));

            writeLine(certsFileOs, currentCertsFilename);
            certstore.setCountCerts(numProcessedBefore + sum);
            echoToFile(Long.toString(id), processLogFile);

            processLog.addNumProcessed(numCertInCurrentFile);
            processLog.printStatus();

            // reset
            certsInCurrentFile = new OcspCertstore.Certs();
            numCertInCurrentFile = 0;
            minCertIdOfCurrentFile = -1;
            maxCertIdOfCurrentFile = -1;
            currentCertsZipFile = new File(baseDir,
                "tmp-certs-" + Clock.systemUTC().millis() + ".zip");
            currentCertsZip = getZipOutputStream(currentCertsZipFile);
          } // end if
        } while (rs.next());

        rs.close();
      } // end for

      if (interrupted) {
        throw new InterruptedException("interrupted by the user");
      }

      if (numCertInCurrentFile > 0) {
        finalizeZip(currentCertsZip, certsInCurrentFile);

        String currentCertsFilename = buildFilename("certs_", ".zip",
            minCertIdOfCurrentFile, maxCertIdOfCurrentFile, maxId);
        IoUtil.renameTo(currentCertsZipFile,
            new File(certsDir, currentCertsFilename));

        writeLine(certsFileOs, currentCertsFilename);
        certstore.setCountCerts(numProcessedBefore + sum);
        echoToFile(Long.toString(id), processLogFile);

        processLog.addNumProcessed(numCertInCurrentFile);
      } else {
        currentCertsZip.close();
        IoUtil.deleteFile0(currentCertsZipFile);
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(certPs, null);
    }

    processLog.printTrailer();
    // all successful, delete the processLogFile
    IoUtil.deleteFile0(processLogFile);

    System.out.println(" exported " + processLog.numProcessed() +
        " certificates from tables CERT");
  } // method exportCert0

  private void finalizeZip(ZipOutputStream zipOutStream,
                           OcspCertstore.Certs certs)
      throws IOException, CodecException {
    ZipEntry certZipEntry = new ZipEntry("certs.json");
    zipOutStream.putNextEntry(certZipEntry);
    try {
      zipOutStream.write(StringUtil.toUtf8Bytes(
          JsonBuilder.toJson(certs.toCodec())));
    } finally {
      zipOutStream.closeEntry();
    }

    zipOutStream.close();
  } // method finalizeZip

}
