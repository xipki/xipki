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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.util.Args;
import org.xipki.util.IoUtil;
import org.xipki.util.ProcessLog;
import org.xipki.util.StringUtil;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Database exporter of OCSP CertStore.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

class OcspCertstoreDbExporter extends DbPorter {

  public static final String PROCESS_LOG_FILENAME = "export.process";

  private static final Logger LOG = LoggerFactory.getLogger(OcspCertstoreDbExporter.class);

  private final int numCertsInBundle;

  private final int numCertsPerSelect;

  private final boolean resume;

  OcspCertstoreDbExporter(DataSourceWrapper datasource, String baseDir, int numCertsInBundle,
      int numCertsPerSelect, boolean resume, AtomicBoolean stopMe)
          throws Exception {
    super(datasource, baseDir, stopMe);

    this.numCertsInBundle = Args.positive(numCertsInBundle, "numCertsInBundle");
    this.numCertsPerSelect = Args.positive(numCertsPerSelect, "numCertsPerSelect");

    if (resume) {
      File processLogFile = new File(baseDir, PROCESS_LOG_FILENAME);
      if (!processLogFile.exists()) {
        throw new Exception("could not process with '--resume' option");
      }
    }
    this.resume = resume;
  } // constructor

  public void export()
      throws Exception {
    OcspCertstore certstore;
    if (resume) {
      try (InputStream is = Files.newInputStream(Paths.get(baseDir, FILENAME_OCSP_CERTSTORE))) {
        certstore = JSON.parseObject(is, OcspCertstore.class);
      }
      certstore.validate();

      if (certstore.getVersion() > VERSION) {
        throw new Exception("could not continue with Certstore greater than " + VERSION
            + ": " + certstore.getVersion());
      }
    } else {
      certstore = new OcspCertstore();
      certstore.setVersion(VERSION);
    }
    System.out.println("exporting OCSP certstore from database");

    if (!resume) {
      exportHashAlgo(certstore);
      exportIssuer(certstore);
      exportCrlInfo(certstore);
    }

    File processLogFile = new File(baseDir, PROCESS_LOG_FILENAME);
    Exception exception = exportCert(certstore, processLogFile);

    try (OutputStream os = Files.newOutputStream(Paths.get(baseDir, FILENAME_OCSP_CERTSTORE))) {
      JSON.writeJSONString(os, certstore);
    }

    if (exception == null) {
      System.out.println(" exported OCSP certstore from database");
    } else {
      throw exception;
    }
  } // method export

  private void exportHashAlgo(OcspCertstore certstore)
      throws DataAccessException {
    String certHashAlgoStr = dbSchemaInfo.getVariableValue("CERTHASH_ALGO");
    if (certHashAlgoStr == null) {
      throw new DataAccessException("CERTHASH_ALGO is not defined in table DBSCHEMA");
    }

    certstore.setCerthashAlgo(certHashAlgoStr);
  } // method exportHashAlgo

  private void exportIssuer(OcspCertstore certstore)
      throws DataAccessException, IOException {
    System.out.println("exporting table ISSUER");
    List<OcspCertstore.Issuer> issuers = new LinkedList<>();
    certstore.setIssuers(issuers);
    final String sql = "SELECT ID,CERT,REV_INFO,CRL_ID FROM ISSUER";

    Statement stmt = null;
    ResultSet rs = null;

    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        int id = rs.getInt("ID");

        OcspCertstore.Issuer issuer = new OcspCertstore.Issuer();
        issuer.setId(id);

        String certFileName = "issuer-conf/cert-issuer-" + id;
        IoUtil.save(new File(baseDir, certFileName), StringUtil.toUtf8Bytes(rs.getString("CERT")));
        issuer.setCertFile(certFileName);
        issuer.setRevInfo(rs.getString("REV_INFO"));

        int crlId = rs.getInt("CRL_ID");
        if (crlId != 0) {
          issuer.setCrlId(crlId);
        }

        issuers.add(issuer);
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
    }

    System.out.println(" exported table ISSUER");
  } // method exportIssuer

  private void exportCrlInfo(OcspCertstore certstore)
      throws DataAccessException {
    System.out.println("exporting table CRL_INFO");
    List<OcspCertstore.CrlInfo> crlInfos = new LinkedList<>();
    certstore.setCrlInfos(crlInfos);
    final String sql = "SELECT ID,NAME,INFO FROM CRL_INFO";

    Statement stmt = null;
    ResultSet rs = null;

    try {
      stmt = createStatement();
      rs = stmt.executeQuery(sql);

      while (rs.next()) {
        OcspCertstore.CrlInfo crlInfo = new OcspCertstore.CrlInfo();
        crlInfo.setId(rs.getInt("ID"));
        crlInfo.setName(rs.getString("NAME"));
        crlInfo.setInfo(rs.getString("INFO"));

        crlInfos.add(crlInfo);
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs);
    }

    System.out.println(" exported table CRL_INFO");
  } // method exportCrlInfo

  private Exception exportCert(OcspCertstore certstore, File processLogFile) {
    new File(baseDir, OcspDbEntryType.CERT.getDirName()).mkdirs();

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
      System.err.println("\nexporting table CERT has been cancelled due to error,\n"
          + "please continue with the option '--resume'");
      LOG.error("Exception", ex);
      return ex;
    } finally {
      IoUtil.closeQuietly(certsFileOs);
    }
  } // method exportCert

  private void exportCert0(OcspCertstore certstore, File processLogFile, OutputStream certsFileOs)
      throws Exception {
    File certsDir = new File(baseDir, OcspDbEntryType.CERT.getDirName());
    Long minId = null;
    if (processLogFile.exists()) {
      byte[] content = IoUtil.read(processLogFile);
      if (content != null && content.length > 0) {
        minId = Long.parseLong(StringUtil.toUtf8String(content).trim());
        minId++;
      }
    }

    if (minId == null) {
      minId = min("CERT", "ID");
    }

    System.out.println("exporting table CERT from ID " + minId);

    final String coreSql = "ID,SN,IID,LUPDATE,REV,RR,RT,RIT,NAFTER,NBEFORE,HASH,SUBJECT,CRL_ID "
        + "FROM CERT WHERE ID>=?";
    final String certSql = datasource.buildSelectFirstSql(numCertsPerSelect, "ID ASC", coreSql);

    final long maxId = max("CERT", "ID");

    int numProcessedBefore = certstore.getCountCerts();
    final long total = count("CERT") - numProcessedBefore;
    ProcessLog processLog = new ProcessLog(total);

    PreparedStatement certPs = prepareStatement(certSql);

    int sum = 0;
    int numCertInCurrentFile = 0;

    OcspCertstore.Certs certsInCurrentFile = new OcspCertstore.Certs();

    File currentCertsZipFile = new File(baseDir,
        "tmp-certs-" + System.currentTimeMillis() + ".zip");
    ZipOutputStream currentCertsZip = getZipOutputStream(currentCertsZipFile);

    long minCertIdOfCurrentFile = -1;
    long maxCertIdOfCurrentFile = -1;

    processLog.printHeader();

    String sql = null;
    Long id = null;

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

          OcspCertstore.Cert cert = new OcspCertstore.Cert();

          cert.setId(id);

          cert.setIid(rs.getInt("IID"));
          cert.setSn(rs.getString("SN"));
          cert.setUpdate(rs.getLong("LUPDATE"));

          boolean revoked = rs.getBoolean("REV");
          cert.setRev(revoked);

          if (revoked) {
            cert.setRr(rs.getInt("RR"));
            cert.setRt(rs.getLong("RT"));
            long rit = rs.getLong("RIT");
            if (rit != 0) {
              cert.setRit(rit);
            }
          }

          String hash = rs.getString("HASH");
          if (hash != null) {
            cert.setHash(hash);
          }

          String subject = rs.getString("SUBJECT");
          if (subject != null) {
            cert.setSubject(subject);
          }

          long nafter = rs.getLong("NAFTER");
          if (nafter != 0) {
            cert.setNafter(nafter);
          }

          long nbefore = rs.getLong("NBEFORE");
          if (nbefore != 0) {
            cert.setNbefore(nbefore);
          }

          int crlId = rs.getInt("CRL_ID");
          if (crlId != 0) {
            cert.setCrlId(crlId);
          }

          certsInCurrentFile.add(cert);
          numCertInCurrentFile++;
          sum++;

          if (numCertInCurrentFile == numCertsInBundle) {
            finalizeZip(currentCertsZip, certsInCurrentFile);

            String currentCertsFilename = buildFilename("certs_", ".zip",
                minCertIdOfCurrentFile, maxCertIdOfCurrentFile, maxId);
            currentCertsZipFile.renameTo(new File(certsDir, currentCertsFilename));

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
                "tmp-certs-" + System.currentTimeMillis() + ".zip");
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
        currentCertsZipFile.renameTo(new File(certsDir, currentCertsFilename));

        writeLine(certsFileOs, currentCertsFilename);
        certstore.setCountCerts(numProcessedBefore + sum);
        echoToFile(Long.toString(id), processLogFile);

        processLog.addNumProcessed(numCertInCurrentFile);
      } else {
        currentCertsZip.close();
        currentCertsZipFile.delete();
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(certPs, null);
    }

    processLog.printTrailer();
    // all successful, delete the processLogFile
    processLogFile.delete();

    System.out.println(" exported " + processLog.numProcessed() + " certificates from tables CERT");
  } // method exportCert0

  private void finalizeZip(ZipOutputStream zipOutStream, OcspCertstore.Certs certs)
      throws IOException {
    ZipEntry certZipEntry = new ZipEntry("certs.json");
    zipOutStream.putNextEntry(certZipEntry);
    try {
      JSON.writeJSONString(zipOutStream, StandardCharsets.UTF_8, certs);
    } finally {
      zipOutStream.closeEntry();
    }

    zipOutStream.close();
  } // method finalizeZip

}
