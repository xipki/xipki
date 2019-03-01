/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

import java.io.File;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Types;
import java.util.List;
import java.util.StringTokenizer;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.security.FpIdCalculator;
import org.xipki.security.HashAlgo;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.Base64;
import org.xipki.util.IoUtil;
import org.xipki.util.ProcessLog;
import org.xipki.util.StringUtil;

import com.alibaba.fastjson.JSON;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

class CaCertstoreDbImporter extends DbPorter {

  private static final Logger LOG = LoggerFactory.getLogger(CaCertstoreDbImporter.class);

  private static final String SQL_ADD_CERT =
      "INSERT INTO CERT (ID,LUPDATE,SN,SUBJECT,FP_S,FP_RS,NBEFORE,NAFTER,REV,RR,RT,RIT,"
      + "PID,CA_ID,RID,UID,FP_K,EE,RTYPE,TID,SHA1,REQ_SUBJECT,CERT)"
      + " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

  private static final String SQL_ADD_CRL =
      "INSERT INTO CRL (ID,CA_ID,CRL_NO,THISUPDATE,NEXTUPDATE,DELTACRL,BASECRL_NO,CRL)"
      + " VALUES (?,?,?,?,?,?,?,?)";

  private static final String SQL_ADD_REQUEST =
      "INSERT INTO REQUEST (ID,LUPDATE,DATA) VALUES (?,?,?)";

  private static final String SQL_ADD_REQCERT = "INSERT INTO REQCERT (ID,RID,CID) VALUES (?,?,?)";

  private final boolean resume;

  private final int numCertsPerCommit;

  CaCertstoreDbImporter(DataSourceWrapper datasource, String srcDir, int numCertsPerCommit,
      boolean resume, AtomicBoolean stopMe) throws Exception {
    super(datasource, srcDir, stopMe);

    this.numCertsPerCommit = Args.positive(numCertsPerCommit, "numCertsPerCommit");
    this.resume = resume;

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
  }

  public void importToDb() throws Exception {
    CaCertstore certstore;
    try (InputStream is = Files.newInputStream(Paths.get(baseDir, FILENAME_CA_CERTSTORE))) {
      certstore = JSON.parseObject(is, CaCertstore.class);
    }
    certstore.validate();

    if (certstore.getVersion() > VERSION) {
      throw new Exception("could not import Certstore greater than " + VERSION + ": "
          + certstore.getVersion());
    }

    File processLogFile = new File(baseDir, DbPorter.IMPORT_PROCESS_LOG_FILENAME);
    System.out.println("importing CA certstore to database");
    try {
      if (!resume) {
        dropIndexes();
      }

      CaDbEntryType typeProcessedInLastProcess = null;
      Integer numProcessedInLastProcess = null;
      Long idProcessedInLastProcess = null;
      if (processLogFile.exists()) {
        byte[] content = IoUtil.read(processLogFile);
        if (content != null && content.length > 5) {
          String str = new String(content);
          StringTokenizer st = new StringTokenizer(str, ":");
          String type = st.nextToken();
          typeProcessedInLastProcess = CaDbEntryType.valueOf(type);
          numProcessedInLastProcess = Integer.parseInt(st.nextToken());
          idProcessedInLastProcess = Long.parseLong(st.nextToken());
        }
      }

      boolean entriesFinished = false;
      // finished for the given type
      if (typeProcessedInLastProcess != null && (idProcessedInLastProcess != null
          && idProcessedInLastProcess == -1)) {
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
            throw new IllegalStateException(
                "unsupported CaDbEntryType " + typeProcessedInLastProcess);
        }
      }

      if (!entriesFinished) {
        Exception exception = null;
        if (CaDbEntryType.CRL == typeProcessedInLastProcess
            || typeProcessedInLastProcess == null) {
          exception = importEntries(CaDbEntryType.CRL, certstore, processLogFile,
              numProcessedInLastProcess, idProcessedInLastProcess);
          typeProcessedInLastProcess = null;
          numProcessedInLastProcess = null;
          idProcessedInLastProcess = null;
        }

        CaDbEntryType[] types = {CaDbEntryType.CERT, CaDbEntryType.REQUEST, CaDbEntryType.REQCERT};

        for (CaDbEntryType type : types) {
          if (exception == null
              && (type == typeProcessedInLastProcess || typeProcessedInLastProcess == null)) {
            exception = importEntries(type, certstore, processLogFile,
                numProcessedInLastProcess, idProcessedInLastProcess);
          }
        }

        if (exception != null) {
          throw exception;
        }
      }

      importPublishQueue(certstore.getPublishQueue());
      importDeltaCrlCache(certstore.getDeltaCrlCache());

      recoverIndexes();
      processLogFile.delete();
    } catch (Exception ex) {
      System.err.println("could not import CA certstore to database");
      throw ex;
    }
    System.out.println(" imported CA certstore to database");
  } // method importToDb

  private void importPublishQueue(List<CaCertstore.ToPublish> publishQueue)
      throws DataAccessException {
    final String sql = "INSERT INTO PUBLISHQUEUE (CID,PID,CA_ID) VALUES (?,?,?)";
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

  private void importDeltaCrlCache(List<CaCertstore.DeltaCrlCacheEntry> deltaCrlCache)
      throws DataAccessException {
    final String sql = "INSERT INTO DELTACRL_CACHE (ID,SN,CA_ID) VALUES (?,?,?)";
    System.out.println("importing table DELTACRL_CACHE");
    PreparedStatement ps = prepareStatement(sql);

    try {
      long id = 1;
      for (CaCertstore.DeltaCrlCacheEntry entry : deltaCrlCache) {
        try {
          ps.setLong(1, id++);
          ps.setString(2, entry.getSerial());
          ps.setInt(3, entry.getCaId());
          ps.execute();
        } catch (SQLException ex) {
          System.err.println("could not import DELTACRL_CACHE with caId=" + entry.getCaId()
              + " and serial=" + entry.getSerial() + ", message: " + ex.getMessage());
          throw translate(sql, ex);
        }
      }
    } finally {
      releaseResources(ps, null);
    }

    System.out.println(" imported table DELTACRL_CACHE");
  } // method importDeltaCRLCache

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

      DbPortFileNameIterator entriesFileIterator = null;
      PreparedStatement stmt = null;

      try {
        entriesFileIterator = new DbPortFileNameIterator(
            baseDir + File.separator + type.getDirName() + ".mf");

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
                lastId = importCerts(entriesFile, minId, processLogFile,
                    processLog, numProcessedBefore, stmt, sql);
                break;
              case CRL:
                lastId = importCrls(entriesFile, minId, processLogFile,
                    processLog, numProcessedBefore, stmt, sql);
                break;
              case REQUEST:
                lastId = importRequests(entriesFile, minId, processLogFile,
                    processLog, numProcessedBefore, stmt, sql);
                break;
              case REQCERT:
                lastId = importReqCerts(entriesFile, minId, processLogFile,
                    processLog, numProcessedBefore, stmt, sql);
                break;
              default:
                throw new IllegalStateException("unknown CaDbEntryType " + type);
            }

            minId = lastId + 1;
          } catch (Exception ex) {
            System.err.println("\ncould not import entries from file "
                + entriesFile + ".\nplease continue with the option '--resume'");
            LOG.error("Exception", ex);
            return ex;
          }
        } // end for
      } finally {
        releaseResources(stmt, null);
        if (entriesFileIterator != null) {
          entriesFileIterator.close();
        }
      }

      processLog.printTrailer();
      echoToFile(type + ":" + (numProcessedBefore + processLog.numProcessed()) + ":-1",
          processLogFile);

      System.out.println(" imported " + processLog.numProcessed() + " entries");
      return null;
    } catch (Exception ex) {
      System.err.println("\nimporting " + tablesText + " has been cancelled due to error,\n"
          + "please continue with the option '--resume'");
      LOG.error("Exception", ex);
      return ex;
    }
  }

  private long importCerts(String entriesZipFile, long minId,
      File processLogFile, ProcessLog processLog, int numProcessedInLastProcess,
      PreparedStatement stmt, String sql) throws Exception {
    final CaDbEntryType type = CaDbEntryType.CERT;
    final int numEntriesPerCommit = Math.max(1,
        Math.round(type.getSqlBatchFactor() * numCertsPerCommit));

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
        // rawcert
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

        byte[] encodedKey = tbsCert.getSubjectPublicKeyInfo().getPublicKeyData().getBytes();

        String b64Sha1FpCert = HashAlgo.SHA1.base64Hash(encodedCert);

        // cert
        String subjectText = X509Util.cutX500Name(tbsCert.getSubject(), maxX500nameLen);

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
          setInt(stmt, idx++, cert.getUid());
          stmt.setLong(idx++, FpIdCalculator.hash(encodedKey));
          Extension extension = tbsCert.getExtensions().getExtension(Extension.basicConstraints);
          boolean ee = true;
          if (extension != null) {
            ASN1Encodable asn1 = extension.getParsedValue();
            ee = !BasicConstraints.getInstance(asn1).isCA();
          }

          stmt.setInt(idx++, ee ? 1 : 0);
          stmt.setInt(idx++, cert.getReqType());
          String tidS = null;
          if (cert.getTid() != null) {
            tidS = cert.getTid();
          }
          stmt.setString(idx++, tidS);
          stmt.setString(idx++, b64Sha1FpCert);
          stmt.setString(idx++, cert.getRs());
          stmt.setString(idx++, Base64.encodeToString(encodedCert));
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

  private long importCrls(String entriesZipFile, long minId,
      File processLogFile, ProcessLog processLog, int numProcessedInLastProcess,
      PreparedStatement stmt, String sql) throws Exception {
    final CaDbEntryType type = CaDbEntryType.CRL;
    final int numEntriesPerCommit = Math.max(1,
        Math.round(type.getSqlBatchFactor() * numCertsPerCommit));

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

        X509CRL x509crl = null;
        try {
          x509crl = X509Util.parseCrl(encodedCrl);
        } catch (Exception ex) {
          LOG.error("could not parse CRL in file {}", filename);
          LOG.debug("could not parse CRL in file " + filename, ex);
          if (ex instanceof CRLException) {
            throw (CRLException) ex;
          } else {
            throw new CRLException(ex.getMessage(), ex);
          }
        }

        try {
          byte[] octetString = x509crl.getExtensionValue(Extension.cRLNumber.getId());
          if (octetString == null) {
            LOG.warn("CRL without CRL number, ignore it");
            continue;
          }
          byte[] extnValue = DEROctetString.getInstance(octetString).getOctets();
          // CHECKSTYLE:SKIP
          BigInteger crlNumber = ASN1Integer.getInstance(extnValue).getPositiveValue();

          BigInteger baseCrlNumber = null;
          octetString = x509crl.getExtensionValue(Extension.deltaCRLIndicator.getId());
          if (octetString != null) {
            extnValue = DEROctetString.getInstance(octetString).getOctets();
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

          String str = Base64.encodeToString(encodedCrl);
          stmt.setString(idx++, str);

          stmt.addBatch();
        } catch (SQLException ex) {
          System.err.println("could not import CRL with ID=" + crl.getId()
              + ", message: " + ex.getMessage());
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

  private long importRequests(String entriesZipFile, long minId,
      File processLogFile, ProcessLog processLog, int numProcessedInLastProcess,
      PreparedStatement stmt, String sql) throws Exception {
    final CaDbEntryType type = CaDbEntryType.REQUEST;
    final int numEntriesPerCommit = Math.max(1,
        Math.round(type.getSqlBatchFactor() * numCertsPerCommit));

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
          stmt.setString(idx++, Base64.encodeToString(encodedRequest));
          stmt.addBatch();
        } catch (SQLException ex) {
          System.err.println("could not import REQUEST with ID=" + request.getId()
              + ", message: " + ex.getMessage());
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

  private long importReqCerts(String entriesZipFile, long minId,
      File processLogFile, ProcessLog processLog, int numProcessedInLastProcess,
      PreparedStatement stmt, String sql) throws Exception {
    final CaDbEntryType type = CaDbEntryType.REQCERT;
    final int numEntriesPerCommit = Math.max(1,
        Math.round(type.getSqlBatchFactor() * numCertsPerCommit));

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
          stmt.setLong(idx++, reqCert.getCid());
          stmt.addBatch();
        } catch (SQLException ex) {
          System.err.println("could not import REQUEST with ID=" + reqCert.getId()
              + ", message: " + ex.getMessage());
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

  private void dropIndexes() throws DataAccessException {
    long start = System.currentTimeMillis();

    datasource.dropIndex(null, "CERT", "IDX_CA_FPK");
    datasource.dropIndex(null, "CERT", "IDX_CA_FPS");
    datasource.dropIndex(null, "CERT", "IDX_CA_FPRS");

    datasource.dropForeignKeyConstraint(null, "FK_CERT_CA1", "CERT");
    datasource.dropForeignKeyConstraint(null, "FK_CERT_USER1", "CERT");

    datasource.dropUniqueConstrain(null, "CONST_CA_SN", "CERT");

    datasource.dropForeignKeyConstraint(null, "FK_PUBLISHQUEUE_CERT1", "PUBLISHQUEUE");

    datasource.dropForeignKeyConstraint(null, "FK_REQCERT_REQ1", "REQCERT");
    datasource.dropForeignKeyConstraint(null, "FK_REQCERT_CERT1", "REQCERT");

    datasource.dropPrimaryKey(null, "PK_CERT", "CERT");
    datasource.dropPrimaryKey(null, "PK_REQUEST", "REQUEST");
    datasource.dropPrimaryKey(null, "PK_REQCERT", "REQCERT");

    long duration = (System.currentTimeMillis() - start) / 1000;
    System.out.println(" dropped indexes in " + StringUtil.formatTime(duration, false));
  }

  private void recoverIndexes() throws DataAccessException {
    long start = System.currentTimeMillis();
    datasource.addPrimaryKey(null, "PK_CERT", "CERT", "ID");
    datasource.addPrimaryKey(null, "PK_REQUEST", "REQUEST", "ID");
    datasource.addPrimaryKey(null, "PK_REQCERT", "REQCERT", "ID");

    datasource.addForeignKeyConstraint(null, "FK_PUBLISHQUEUE_CERT1", "PUBLISHQUEUE",
        "CID", "CERT", "ID", "CASCADE", "NO ACTION");

    datasource.addForeignKeyConstraint(null, "FK_CERT_CA1", "CERT",
        "CA_ID", "CA", "ID", "CASCADE", "NO ACTION");

    datasource.addForeignKeyConstraint(null, "FK_CERT_USER1", "CERT",
        "UID", "TUSER", "ID", "CASCADE", "NO ACTION");

    datasource.addForeignKeyConstraint(null, "FK_REQCERT_REQ1", "REQCERT",
        "RID", "REQUEST", "ID", "CASCADE", "NO ACTION");

    datasource.addForeignKeyConstraint(null, "FK_REQCERT_CERT1", "REQCERT",
        "CID", "CERT", "ID", "CASCADE", "NO ACTION");

    datasource.addUniqueConstrain(null, "CONST_CA_SN", "CERT", "CA_ID", "SN");

    datasource.createIndex(null, "IDX_CA_FPK", "CERT", "CA_ID", "FP_K");
    datasource.createIndex(null, "IDX_CA_FPS", "CERT", "CA_ID", "FP_S");
    datasource.createIndex(null, "IDX_CA_FPRS", "CERT", "CA_ID", "FP_RS");

    long duration = (System.currentTimeMillis() - start) / 1000;
    System.out.println(" recovered indexes in " + StringUtil.formatTime(duration, false));
  }

}
