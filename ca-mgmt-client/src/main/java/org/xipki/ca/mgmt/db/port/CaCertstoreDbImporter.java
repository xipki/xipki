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
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CRLHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.security.HashAlgo;
import org.xipki.security.util.X509Util;
import org.xipki.util.*;

import java.io.File;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Types;
import java.util.List;
import java.util.StringTokenizer;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import static org.xipki.util.SqlUtil.buildInsertSql;

/**
 * Database importer of CA CertStore.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

class CaCertstoreDbImporter extends DbPorter {

  private static final Logger LOG = LoggerFactory.getLogger(CaCertstoreDbImporter.class);

  private static final String SQL_ADD_CERT = buildInsertSql("CERT",
      "ID,LUPDATE,SN,SUBJECT,FP_S,FP_RS,NBEFORE,NAFTER,REV,RR,RT,RIT,"
      + "PID,CA_ID,RID,EE,TID,SHA1,REQ_SUBJECT,CRL_SCOPE,CERT,PRIVATE_KEY");

  private static final String SQL_ADD_CRL = buildInsertSql("CRL",
      "ID,CA_ID,CRL_NO,THISUPDATE,NEXTUPDATE,DELTACRL,BASECRL_NO,CRL_SCOPE,SHA1,CRL");

  private static final String SQL_ADD_REQUEST = buildInsertSql("REQUEST",
      "ID,LUPDATE,DATA");

  private static final String SQL_ADD_REQCERT = buildInsertSql("REQCERT",
      "ID,RID,CID");

  private final int numCertsPerCommit;

  CaCertstoreDbImporter(DataSourceWrapper datasource, String srcDir, int numCertsPerCommit,
      boolean resume, AtomicBoolean stopMe)
          throws Exception {
    super(datasource, srcDir, stopMe);

    this.numCertsPerCommit = Args.positive(numCertsPerCommit, "numCertsPerCommit");

    File processLogFile = new File(baseDir, DbPorter.IMPORT_PROCESS_LOG_FILENAME);
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
  } // constructor

  public void importToDb()
      throws Exception {
    CaCertstore certstore;
    try (InputStream is = Files.newInputStream(Paths.get(baseDir, FILENAME_CA_CERTSTORE))) {
      certstore = JSON.parseObject(is, CaCertstore.class);
    }
    certstore.validate();

    if (certstore.getVersion() > VERSION_V2) {
      throw new Exception("could not import Certstore greater than " + VERSION_V2 + ": "
          + certstore.getVersion());
    }

    File processLogFile = new File(baseDir, DbPorter.IMPORT_PROCESS_LOG_FILENAME);
    System.out.println("importing CA certstore to database");
    try {
      CaDbEntryType typeProcessedInLastProcess = null;
      Integer numProcessedInLastProcess = null;
      Long idProcessedInLastProcess = null;
      if (processLogFile.exists()) {
        byte[] content = IoUtil.read(processLogFile);
        if (content != null && content.length > 5) {
          String str = StringUtil.toUtf8String(content);
          StringTokenizer st = new StringTokenizer(str, ":");
          String type = st.nextToken();
          typeProcessedInLastProcess = CaDbEntryType.valueOf(type);
          numProcessedInLastProcess = Integer.parseInt(st.nextToken());
          idProcessedInLastProcess = Long.parseLong(st.nextToken());
        }
      }

      boolean entriesFinished = false;
      // finished for the given type
      if (typeProcessedInLastProcess != null && idProcessedInLastProcess == -1) {
        numProcessedInLastProcess = 0;
        idProcessedInLastProcess = 0L;

        switch (typeProcessedInLastProcess) {
          case CRL:
            typeProcessedInLastProcess = CaDbEntryType.CERT;
            break;
          case CERT:
            typeProcessedInLastProcess = CaDbEntryType.REQUEST;
            break;
          case REQUEST:
            typeProcessedInLastProcess = CaDbEntryType.REQCERT;
            break;
          case REQCERT:
            entriesFinished = true;
            break;
          default:
            throw new IllegalStateException("unsupported CaDbEntryType " + typeProcessedInLastProcess);
        }
      }

      if (!entriesFinished) {
        Exception exception = null;
        if (CaDbEntryType.CRL == typeProcessedInLastProcess || typeProcessedInLastProcess == null) {
          exception = importEntries(CaDbEntryType.CRL, certstore, processLogFile,
              numProcessedInLastProcess, idProcessedInLastProcess);
          typeProcessedInLastProcess = null;
          numProcessedInLastProcess = null;
          idProcessedInLastProcess = null;
        }

        CaDbEntryType[] types = {CaDbEntryType.CERT, CaDbEntryType.REQUEST, CaDbEntryType.REQCERT};

        for (CaDbEntryType type : types) {
          if (exception == null && (type == typeProcessedInLastProcess || typeProcessedInLastProcess == null)) {
            exception = importEntries(type, certstore, processLogFile,
                numProcessedInLastProcess, idProcessedInLastProcess);
          }
        }

        if (exception != null) {
          throw exception;
        }
      }

      importPublishQueue(certstore.getPublishQueue());

      processLogFile.delete();
    } catch (Exception ex) {
      System.err.println("could not import CA certstore to database");
      throw ex;
    }
    System.out.println(" imported CA certstore to database");
  } // method importToDb

  private void importPublishQueue(List<CaCertstore.ToPublish> publishQueue)
      throws DataAccessException {
    final String sql = buildInsertSql("PUBLISHQUEUE", "CID,PID,CA_ID");
    System.out.println("importing table PUBLISHQUEUE");
    PreparedStatement ps = prepareStatement(sql);

    try {
      for (CaCertstore.ToPublish tbp : publishQueue) {
        try {
          ps.setLong(1, tbp.getCertId());
          ps.setInt(2, tbp.getPubId());
          ps.setInt(3, tbp.getCaId());
          ps.execute();
        } catch (SQLException ex) {
          System.err.println("could not import PUBLISHQUEUE with CID="
              + tbp.getCertId() + " and PID=" + tbp.getPubId() + ", message: " + ex.getMessage());
          throw translate(sql, ex);
        }
      }
    } finally {
      releaseResources(ps, null);
    }

    System.out.println(" imported table PUBLISHQUEUE");
  } // method importPublishQueue

  private Exception importEntries(CaDbEntryType type, CaCertstore certstore,
      File processLogFile, Integer numProcessedInLastProcess, Long idProcessedInLastProcess) {
    String tablesText = "table " + type.getTableName();

    try {
      int numProcessedBefore = 0;
      long minId = 1;
      if (idProcessedInLastProcess != null) {
        minId = idProcessedInLastProcess + 1;
        numProcessedBefore = numProcessedInLastProcess;
      }

      deleteFromTableWithLargerId(type.getTableName(), "ID", minId - 1, LOG);

      final long total;
      String sql;

      switch (type) {
        case CERT:
          total = certstore.getCountCerts();
          sql = SQL_ADD_CERT;
          break;
        case CRL:
          total = certstore.getCountCrls();
          sql = SQL_ADD_CRL;
          break;
        case REQUEST:
          total = certstore.getCountRequests();
          sql = SQL_ADD_REQUEST;
          break;
        case REQCERT:
          total = certstore.getCountReqCerts();
          sql = SQL_ADD_REQCERT;
          break;
        default:
          throw new IllegalStateException("unsupported DbEntryType " + type);
      }

      final long remainingTotal = total - numProcessedBefore;
      final ProcessLog processLog = new ProcessLog(remainingTotal);

      System.out.println("importing entries to " + tablesText + " from ID " + minId);
      processLog.printHeader();

      PreparedStatement stmt = null;
      try (DbPortFileNameIterator entriesFileIterator = new DbPortFileNameIterator(
              baseDir + File.separator + type.getDirName() + ".mf")) {

        stmt = prepareStatement(sql);

        while (entriesFileIterator.hasNext()) {
          String entriesFile = baseDir + File.separator + type.getDirName()
              + File.separator + entriesFileIterator.next();

          // extract the toId from the filename
          int fromIdx = entriesFile.indexOf('-');
          int toIdx = entriesFile.indexOf(".zip");
          if (fromIdx != -1 && toIdx != -1) {
            try {
              long toId = Integer.parseInt(entriesFile.substring(fromIdx + 1, toIdx));
              if (toId < minId) {
                // try next file
                continue;
              }
            } catch (Exception ex) {
              LOG.warn("invalid file name '{}', but will still be processed", entriesFile);
            }
          } else {
            LOG.warn("invalid file name '{}', but will still be processed", entriesFile);
          }

          try {
            long lastId;
            switch (type) {
              case CERT:
                lastId = importCerts(entriesFile, minId, processLogFile, processLog, numProcessedBefore, stmt, sql);
                break;
              case CRL:
                lastId = importCrls(entriesFile, minId, processLogFile, processLog, numProcessedBefore, stmt, sql);
                break;
              case REQUEST:
                lastId = importRequests(entriesFile, minId, processLogFile, processLog, numProcessedBefore, stmt, sql);
                break;
              case REQCERT:
                lastId = importReqCerts(entriesFile, minId, processLogFile, processLog, numProcessedBefore, stmt, sql);
                break;
              default:
                throw new IllegalStateException("unknown CaDbEntryType " + type);
            }

            minId = lastId + 1;
          } catch (Exception ex) {
            System.err.println("\ncould not import entries from file " + entriesFile
                + ".\nplease continue with the option '--resume'");
            LOG.error("Exception", ex);
            return ex;
          }
        } // end for
      } finally {
        releaseResources(stmt, null);
      }

      processLog.printTrailer();
      echoToFile(type + ":" + (numProcessedBefore + processLog.numProcessed()) + ":-1", processLogFile);

      System.out.println(" imported " + processLog.numProcessed() + " entries");
      return null;
    } catch (Exception ex) {
      System.err.println("\nimporting " + tablesText + " has been cancelled due to error,\n"
          + "please continue with the option '--resume'");
      LOG.error("Exception", ex);
      return ex;
    }
  } // method importEntries

  private long importCerts
      (String entriesZipFile, long minId, File processLogFile, ProcessLog processLog, int numProcessedInLastProcess,
      PreparedStatement stmt, String sql)
      throws Exception {
    final CaDbEntryType type = CaDbEntryType.CERT;
    final int numEntriesPerCommit = Math.max(1, Math.round(type.getSqlBatchFactor() * numCertsPerCommit));

    ZipFile zipFile = new ZipFile(new File(entriesZipFile));
    ZipEntry entriesEntry = zipFile.getEntry("overview.json");

    CaCertstore.Certs certs;
    try {
      certs = JSON.parseObject(zipFile.getInputStream(entriesEntry), CaCertstore.Certs.class);
    } catch (Exception ex) {
      try {
        zipFile.close();
      } catch (Exception e2) {
        LOG.error("could not close ZIP file {}: {}", entriesZipFile, e2.getMessage());
        LOG.debug("could not close ZIP file " + entriesZipFile, e2);
      }
      throw ex;
    }
    certs.validate();

    disableAutoCommit();

    try {
      int numEntriesInBatch = 0;
      long lastSuccessfulEntryId = 0;

      List<CaCertstore.Cert> list = certs.getCerts();
      final int n = list.size();

      for (int i = 0; i < n; i++) {
        CaCertstore.Cert cert = list.get(i);

        if (stopMe.get()) {
          throw new InterruptedException("interrupted by the user");
        }

        long id = cert.getId();
        if (id < minId) {
          continue;
        }

        numEntriesInBatch++;

        String filename = cert.getFile();
        // rawcert
        ZipEntry certZipEnty = zipFile.getEntry(filename);
        byte[] encodedCert = IoUtil.read(zipFile.getInputStream(certZipEnty));

        TBSCertificate tbsCert;
        try {
          Certificate cc = Certificate.getInstance(encodedCert);
          tbsCert = cc.getTBSCertificate();
        } catch (RuntimeException ex) {
          LOG.error("could not parse certificate in file {}", filename);
          LOG.debug("could not parse certificate in file " + filename, ex);
          throw new CertificateException(ex.getMessage(), ex);
        }

        String b64Sha1FpCert = HashAlgo.SHA1.base64Hash(encodedCert);

        // cert's subject
        String subjectText = X509Util.cutX500Name(tbsCert.getSubject(), maxX500nameLen);

        // private key
        String privateKey = null;
        if (cert.getPrivateKeyFile() != null) {
          ZipEntry keyZipEnty = zipFile.getEntry(cert.getPrivateKeyFile());
          if (keyZipEnty != null) {
            privateKey = new String(IoUtil.read(zipFile.getInputStream(keyZipEnty)));
          }
        }

        try {
          int idx = 1;

          stmt.setLong(idx++, id);
          stmt.setLong(idx++, cert.getUpdate());
          stmt.setString(idx++, tbsCert.getSerialNumber().getPositiveValue().toString(16));

          stmt.setString(idx++, subjectText);
          long fpSubject = X509Util.fpCanonicalizedName(tbsCert.getSubject());
          stmt.setLong(idx++, fpSubject);

          if (cert.getFpRs() != null) {
            stmt.setLong(idx++, cert.getFpRs());
          } else {
            stmt.setNull(idx++, Types.BIGINT);
          }

          stmt.setLong(idx++, tbsCert.getStartDate().getDate().getTime() / 1000);
          stmt.setLong(idx++, tbsCert.getEndDate().getDate().getTime() / 1000);
          setInt(stmt, idx++, cert.getRev());
          setInt(stmt, idx++, cert.getRr());
          setLong(stmt, idx++, cert.getRt());
          setLong(stmt, idx++, cert.getRit());
          setInt(stmt, idx++, cert.getPid());
          setInt(stmt, idx++, cert.getCaId());

          setInt(stmt, idx++, cert.getRid());
          Extension extension = tbsCert.getExtensions().getExtension(Extension.basicConstraints);
          boolean ee = true;
          if (extension != null) {
            ASN1Encodable asn1 = extension.getParsedValue();
            ee = !BasicConstraints.getInstance(asn1).isCA();
          }

          stmt.setInt(idx++, ee ? 1 : 0);
          String tidS = null;
          if (cert.getTid() != null) {
            tidS = cert.getTid();
          }
          stmt.setString(idx++, tidS);
          stmt.setString(idx++, b64Sha1FpCert);
          stmt.setString(idx++, cert.getRs());
          stmt.setInt(idx++, cert.getCrlScope());
          stmt.setString(idx++, Base64.encodeToString(encodedCert));
          stmt.setString(idx, privateKey);
          stmt.addBatch();
        } catch (SQLException ex) {
          throw translate(sql, ex);
        }

        boolean isLastBlock = i == n - 1;
        if (numEntriesInBatch > 0
            && (numEntriesInBatch % numEntriesPerCommit == 0 || isLastBlock)) {
          try {
            stmt.executeBatch();
            commit("(commit import to CA)");
          } catch (Throwable th) {
            rollback();
            deleteFromTableWithLargerId(type.getTableName(), "ID", id, LOG);
            if (th instanceof SQLException) {
              throw translate(sql, (SQLException) th);
            } else if (th instanceof Exception) {
              throw (Exception) th;
            } else {
              throw new Exception(th);
            }
          }

          lastSuccessfulEntryId = id;
          processLog.addNumProcessed(numEntriesInBatch);
          numEntriesInBatch = 0;
          echoToFile(type + ":" + (numProcessedInLastProcess + processLog.numProcessed())
              + ":" + lastSuccessfulEntryId, processLogFile);
          processLog.printStatus();
        }

      } // end while

      return lastSuccessfulEntryId;
    } finally {
      recoverAutoCommit();
      zipFile.close();
    }
  } // method importCerts

  private long importCrls(
      String entriesZipFile, long minId, File processLogFile, ProcessLog processLog, int numProcessedInLastProcess,
      PreparedStatement stmt, String sql)
      throws Exception {
    final CaDbEntryType type = CaDbEntryType.CRL;
    final int numEntriesPerCommit = Math.max(1, Math.round(type.getSqlBatchFactor() * numCertsPerCommit));

    ZipFile zipFile = new ZipFile(new File(entriesZipFile));
    ZipEntry entriesEntry = zipFile.getEntry("overview.json");

    CaCertstore.Crls crls;
    try {
      crls = JSON.parseObject(zipFile.getInputStream(entriesEntry), CaCertstore.Crls.class);
    } catch (Exception ex) {
      try {
        zipFile.close();
      } catch (Exception e2) {
        LOG.error("could not close ZIP file {}: {}", entriesZipFile, e2.getMessage());
        LOG.debug("could not close ZIP file " + entriesZipFile, e2);
      }
      throw ex;
    }
    crls.validate();

    disableAutoCommit();

    try {
      int numEntriesInBatch = 0;
      long lastSuccessfulEntryId = 0;

      List<CaCertstore.Crl> list = crls.getCrls();
      final int n = list.size();

      for (int i = 0; i < n; i++) {
        CaCertstore.Crl crl = list.get(i);

        long id = crl.getId();
        if (id < minId) {
          continue;
        }

        numEntriesInBatch++;

        String filename = crl.getFile();

        // CRL
        ZipEntry zipEnty = zipFile.getEntry(filename);

        // rawcert
        byte[] encodedCrl = IoUtil.read(zipFile.getInputStream(zipEnty));
        String b64Sha1 = HashAlgo.SHA1.base64Hash(encodedCrl);

        X509CRLHolder x509crl;
        try {
          x509crl = X509Util.parseCrl(encodedCrl);
        } catch (Exception ex) {
          LOG.error("could not parse CRL in file {}", filename);
          LOG.debug("could not parse CRL in file " + filename, ex);
          if (ex instanceof CRLException) {
            throw ex;
          } else {
            throw new CRLException(ex.getMessage(), ex);
          }
        }

        try {
          Extensions extns = x509crl.getExtensions();
          byte[] extnValue = X509Util.getCoreExtValue(extns, Extension.cRLNumber);
          if (extnValue == null) {
            LOG.warn("CRL without CRL number, ignore it");
            continue;
          }
          BigInteger crlNumber = ASN1Integer.getInstance(extnValue).getPositiveValue();

          BigInteger baseCrlNumber = null;
          extnValue = X509Util.getCoreExtValue(extns, Extension.deltaCRLIndicator);
          if (extnValue != null) {
            baseCrlNumber = ASN1Integer.getInstance(extnValue).getPositiveValue();
          }

          int idx = 1;
          stmt.setLong(idx++, crl.getId());
          stmt.setInt(idx++, crl.getCaId());
          stmt.setLong(idx++, crlNumber.longValue());
          stmt.setLong(idx++, x509crl.getThisUpdate().getTime() / 1000);
          if (x509crl.getNextUpdate() != null) {
            stmt.setLong(idx++, x509crl.getNextUpdate().getTime() / 1000);
          } else {
            stmt.setNull(idx++, Types.INTEGER);
          }

          if (baseCrlNumber == null) {
            setBoolean(stmt, idx++, false);
            stmt.setNull(idx++, Types.BIGINT);
          } else {
            setBoolean(stmt, idx++, true);
            stmt.setLong(idx++, baseCrlNumber.longValue());
          }

          stmt.setInt(idx++, crl.getCrlScope());
          stmt.setString(idx++, b64Sha1);
          stmt.setString(idx, Base64.encodeToString(encodedCrl));

          stmt.addBatch();
        } catch (SQLException ex) {
          System.err.println("could not import CRL with ID=" + crl.getId() + ", message: " + ex.getMessage());
          throw ex;
        }

        boolean isLastBlock = i == n - 1;
        if (numEntriesInBatch > 0
            && (numEntriesInBatch % numEntriesPerCommit == 0 || isLastBlock)) {
          try {
            stmt.executeBatch();
            commit("(commit import to CA)");
          } catch (Throwable th) {
            rollback();
            deleteFromTableWithLargerId(type.getTableName(), "ID", id, LOG);
            if (th instanceof SQLException) {
              throw translate(sql, (SQLException) th);
            } else if (th instanceof Exception) {
              throw (Exception) th;
            } else {
              throw new Exception(th);
            }
          }

          lastSuccessfulEntryId = id;
          processLog.addNumProcessed(numEntriesInBatch);
          numEntriesInBatch = 0;
          echoToFile(type + ":" + (numProcessedInLastProcess + processLog.numProcessed()) + ":"
              + lastSuccessfulEntryId, processLogFile);
          processLog.printStatus();
        }

      } // end while

      return lastSuccessfulEntryId;
    } finally {
      recoverAutoCommit();
      zipFile.close();
    }
  } // method importCrls

  private long importRequests(
      String entriesZipFile, long minId, File processLogFile, ProcessLog processLog, int numProcessedInLastProcess,
      PreparedStatement stmt, String sql)
      throws Exception {
    final CaDbEntryType type = CaDbEntryType.REQUEST;
    final int numEntriesPerCommit = Math.max(1, Math.round(type.getSqlBatchFactor() * numCertsPerCommit));

    ZipFile zipFile = new ZipFile(new File(entriesZipFile));
    ZipEntry entriesEntry = zipFile.getEntry("overview.json");

    CaCertstore.Requests requests;
    try {
      requests = JSON.parseObject(zipFile.getInputStream(entriesEntry), CaCertstore.Requests.class);
    } catch (Exception ex) {
      try {
        zipFile.close();
      } catch (Exception e2) {
        LOG.error("could not close ZIP file {}: {}", entriesZipFile, e2.getMessage());
        LOG.debug("could not close ZIP file " + entriesZipFile, e2);
      }
      throw ex;
    }
    requests.validate();

    disableAutoCommit();

    try {
      int numEntriesInBatch = 0;
      long lastSuccessfulEntryId = 0;

      List<CaCertstore.Request> list = requests.getRequests();
      final int n = list.size();

      for (int i = 0; i < n; i++) {
        CaCertstore.Request request = list.get(i);

        if (stopMe.get()) {
          throw new InterruptedException("interrupted by the user");
        }

        long id = request.getId();
        if (id < minId) {
          continue;
        }

        numEntriesInBatch++;

        String filename = request.getFile();

        ZipEntry zipEnty = zipFile.getEntry(filename);
        byte[] encodedRequest = IoUtil.read(zipFile.getInputStream(zipEnty));

        try {
          int idx = 1;
          stmt.setLong(idx++, request.getId());
          stmt.setLong(idx++, request.getUpdate());
          stmt.setString(idx, Base64.encodeToString(encodedRequest));
          stmt.addBatch();
        } catch (SQLException ex) {
          System.err.println("could not import REQUEST with ID=" + request.getId() + ", message: " + ex.getMessage());
          throw ex;
        }

        boolean isLastBlock = i == n - 1;
        if (numEntriesInBatch > 0
            && (numEntriesInBatch % numEntriesPerCommit == 0 || isLastBlock)) {
          try {
            stmt.executeBatch();
            commit("(commit import to CA)");
          } catch (Throwable th) {
            rollback();
            deleteFromTableWithLargerId(type.getTableName(), "ID", id, LOG);
            if (th instanceof SQLException) {
              throw translate(sql, (SQLException) th);
            } else if (th instanceof Exception) {
              throw (Exception) th;
            } else {
              throw new Exception(th);
            }
          }

          lastSuccessfulEntryId = id;
          processLog.addNumProcessed(numEntriesInBatch);
          numEntriesInBatch = 0;
          echoToFile(type + ":" + (numProcessedInLastProcess + processLog.numProcessed()) + ":"
              + lastSuccessfulEntryId, processLogFile);
          processLog.printStatus();
        }

      } // end while

      return lastSuccessfulEntryId;
    } finally {
      recoverAutoCommit();
      zipFile.close();
    }
  } // method importRequests

  private long importReqCerts(
      String entriesZipFile, long minId, File processLogFile, ProcessLog processLog, int numProcessedInLastProcess,
      PreparedStatement stmt, String sql)
      throws Exception {
    final CaDbEntryType type = CaDbEntryType.REQCERT;
    final int numEntriesPerCommit = Math.max(1, Math.round(type.getSqlBatchFactor() * numCertsPerCommit));

    ZipFile zipFile = new ZipFile(new File(entriesZipFile));
    ZipEntry entriesEntry = zipFile.getEntry("overview.json");

    CaCertstore.ReqCerts reqCerts;
    try {
      reqCerts = JSON.parseObject(zipFile.getInputStream(entriesEntry), CaCertstore.ReqCerts.class);
    } catch (Exception ex) {
      try {
        zipFile.close();
      } catch (Exception e2) {
        LOG.error("could not close ZIP file {}: {}", entriesZipFile, e2.getMessage());
        LOG.debug("could not close ZIP file " + entriesZipFile, e2);
      }
      throw ex;
    }
    reqCerts.validate();

    disableAutoCommit();

    try {
      int numEntriesInBatch = 0;
      long lastSuccessfulEntryId = 0;

      List<CaCertstore.ReqCert> list = reqCerts.getReqCerts();
      final int n = list.size();

      for (int i = 0; i < n; i++) {
        CaCertstore.ReqCert reqCert = list.get(i);
        if (stopMe.get()) {
          throw new InterruptedException("interrupted by the user");
        }

        long id = reqCert.getId();
        if (id < minId) {
          continue;
        }

        numEntriesInBatch++;

        try {
          int idx = 1;
          stmt.setLong(idx++, reqCert.getId());
          stmt.setLong(idx++, reqCert.getRid());
          stmt.setLong(idx, reqCert.getCid());
          stmt.addBatch();
        } catch (SQLException ex) {
          System.err.println("could not import REQUEST with ID=" + reqCert.getId() + ", message: " + ex.getMessage());
          throw ex;
        }

        boolean isLastBlock = i == n - 1;
        if (numEntriesInBatch > 0
            && (numEntriesInBatch % numEntriesPerCommit == 0 || isLastBlock)) {
          try {
            stmt.executeBatch();
            commit("(commit import to CA)");
          } catch (Throwable th) {
            rollback();
            deleteFromTableWithLargerId(type.getTableName(), "ID", id, LOG);
            if (th instanceof SQLException) {
              throw translate(sql, (SQLException) th);
            } else if (th instanceof Exception) {
              throw (Exception) th;
            } else {
              throw new Exception(th);
            }
          }

          lastSuccessfulEntryId = id;
          processLog.addNumProcessed(numEntriesInBatch);
          numEntriesInBatch = 0;
          echoToFile(type + ":" + (numProcessedInLastProcess + processLog.numProcessed()) + ":"
              + lastSuccessfulEntryId, processLogFile);
          processLog.printStatus();
        }

      } // end while

      return lastSuccessfulEntryId;
    } finally {
      recoverAutoCommit();
      zipFile.close();
    }
  } // method importReqCerts

}
